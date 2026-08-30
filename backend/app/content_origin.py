"""Content-origin matching — "where did this leaked prompt content come from?"

Palivane is one of the few systems capturing BOTH ends in one place: the at-rest scan
(Drive/SharePoint/Slack/Salesforce) sees where sensitive content lives, and the egress
capture sees what leaves for an AI tool. This module connects them.

Approach: probabilistic content overlap, NOT kernel syscall lineage (that needs a
heavyweight endpoint agent Palivane deliberately doesn't ship). Each scanned document is
reduced to a *sampled set of word-shingles*; a leaked prompt is reduced the same way, and
we measure CONTAINMENT — the fraction of the prompt's shingles present in a document. High
containment means the prompt was taken from (or heavily overlaps) that document, even if
it's a small excerpt of a large file.

Honest limits, stated where they'll be read: this only covers content Palivane has scanned
at rest, and shingle overlap is a similarity estimate — it catches copies, excerpts, and
light edits, not paraphrases or a fact retyped from memory. It answers "this paste matches
a document we know" with a confidence, not "prove this byte's ancestry."
"""

from __future__ import annotations

import hashlib
import re

# k consecutive normalized words per shingle. 5 balances excerpt sensitivity (shorter =
# more matches, more coincidences) against precision (longer = misses light edits).
_K = 5
# 1-in-N deterministic sample of shingles (keep hash where hash % _SAMPLE == 0). Bounds
# stored/compared set size while preserving containment in expectation — the prompt is
# sampled the SAME way, so overlap fractions stay comparable.
_SAMPLE = 4
# Storage guard: never persist more than this many sampled shingles per document (a very
# large file is truncated, flagged by a shorter set — matching still works on what's kept).
_MAX_SHINGLES = 6000
# A prompt must contribute at least this many sampled shingles for a match to mean
# anything — a one-line common phrase can't coincidentally "originate" from a doc.
_MIN_PROMPT_SHINGLES = 4
# Containment threshold: this fraction of the prompt's sampled shingles must appear in the
# document's set to call it an origin.
_MIN_CONTAINMENT = 0.5
# Cap documents compared per egress event — bounded work on the shared capture path.
_MAX_DOCS_SCANNED = 5000

_WORD_RE = re.compile(r"[a-z0-9]+")


def _shingle_hashes(text: str) -> set[int]:
    """Sampled set of 64-bit shingle hashes for `text`. Empty for content too short to
    form a shingle."""
    words = _WORD_RE.findall((text or "").lower())
    if len(words) < _K:
        return set()
    out: set[int] = set()
    for i in range(len(words) - _K + 1):
        shingle = " ".join(words[i:i + _K])
        h = int.from_bytes(hashlib.blake2b(shingle.encode(), digest_size=8).digest(), "big")
        if h % _SAMPLE == 0:
            out.add(h)
    return out


def fingerprint(text: str) -> list[str]:
    """The stored sketch for a document: sampled shingle hashes as strings (JSON-friendly,
    and SQLite JSON ints stay exact as text). Capped; empty when unfingerprintable."""
    hs = _shingle_hashes(text)
    if not hs:
        return []
    if len(hs) > _MAX_SHINGLES:
        hs = set(sorted(hs)[:_MAX_SHINGLES])   # deterministic truncation
    return [str(h) for h in hs]


def store_fingerprint(db, tenant_id: int, source: str, ref: str, title: str,
                      owner: str, content: str) -> None:
    """Upsert one document's sketch. Best-effort — a fingerprinting failure must never
    sink the scan it rides on."""
    try:
        from datetime import datetime, timezone

        from .models import ContentFingerprint
        sk = fingerprint(content)
        row = (db.query(ContentFingerprint)
               .filter(ContentFingerprint.tenant_id == tenant_id,
                       ContentFingerprint.source == source,
                       ContentFingerprint.ref == (ref or "")[:512])
               .one_or_none())
        if not sk:
            # Content became unfingerprintable (emptied/too short) — drop a stale sketch.
            if row is not None:
                db.delete(row)
            return
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if row is None:
            row = ContentFingerprint(tenant_id=tenant_id, source=source,
                                     ref=(ref or "")[:512])
            db.add(row)
        row.title = (title or "")[:512]
        row.owner = (owner or "")[:320]
        row.shingles = sk
        row.updated_at = now
    except Exception:
        pass


def match_origin(db, tenant_id: int, content: str) -> dict | None:
    """Best document the leaked `content` overlaps, or None. Returns
    {source, ref, title, owner, containment} for the highest-containment match above
    threshold. Read-only and bounded; safe on the capture path."""
    try:
        prompt = _shingle_hashes(content)
        if len(prompt) < _MIN_PROMPT_SHINGLES:
            return None
        from .models import ContentFingerprint
        rows = (db.query(ContentFingerprint)
                .filter(ContentFingerprint.tenant_id == tenant_id)
                .order_by(ContentFingerprint.updated_at.desc())
                .limit(_MAX_DOCS_SCANNED).all())
        best = None
        best_c = _MIN_CONTAINMENT
        for r in rows:
            doc = {int(x) for x in (r.shingles or [])}
            if not doc:
                continue
            containment = len(prompt & doc) / len(prompt)
            if containment > best_c:
                best_c = containment
                best = r
        if best is None:
            return None
        return {"source": best.source, "ref": best.ref, "title": best.title,
                "owner": best.owner, "containment": round(best_c, 2)}
    except Exception:
        return None
