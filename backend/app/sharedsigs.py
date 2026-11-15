"""Shared threat signatures: one org's confirmed poisoned tool reaches every org in minutes.

When an analyst triages a tool-poisoning finding (confirms it), and the org has opted in to
contribute, the digest of the poisoned tool description, and the MCP server's name when the
finding names one, go into a global table with no tenant identity attached: a hash, a short
masked sample, how many orgs reported it and when. Every tenant consumes the table whether
or not it contributes: the MCP guard checks each advertised tool description and server name
against the digests (cached in-process, refreshed every few minutes) and raises a signal that
says "reported by N organisations", which scores like a confirmed poisoning rather than a
pattern match. A contributor that later dismisses its finding as a false positive withdraws
its report; a signature with no reports left is retracted and stops matching.

Vendors blog about what they "caught in the wild". This is the feed that makes it a product,
and it is built from the reviews customers already do.
"""
from __future__ import annotations

import hashlib
import hmac
import threading
import time
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .models import Finding, SharedSignature, Tenant

KINDS = ("tool_description", "mcp_server")
_TTL = 300.0
_cache: tuple[float, dict[str, dict]] = (0.0, {})
_lock = threading.Lock()


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def digest_text(text: str) -> str:
    """The digest of a tool description: whitespace-collapsed, case-folded, NFKC via the
    guard's normalizer so an obfuscated copy hashes like the plain one."""
    from .detectors.normalize import normalize_for_match
    norm = " ".join(normalize_for_match(text or "").lower().split())
    return hashlib.sha256(norm.encode()).hexdigest()


def digest_name(name: str) -> str:
    return hashlib.sha256(("server:" + (name or "").strip().lower()).encode()).hexdigest()


def _reporter(tenant_id: int) -> str:
    """A tenant's handle in the reporters list: keyed, so the table never names an org."""
    from .security import _secret
    key = hmac.new(_secret(), b"palivane-shared-signatures", hashlib.sha256).digest()
    return hmac.new(key, str(tenant_id).encode(), hashlib.sha256).hexdigest()[:16]


def _sample(text: str) -> str:
    """A short excerpt that shows what the signature is about, with anything secret-shaped
    masked. Never the full description."""
    from .detectors.patterns import find_secret_matches
    s = " ".join((text or "").split())[:160]
    for _label, value in find_secret_matches(s):
        s = s.replace(value, "••••")
    return s


def known(db: Session | None = None) -> dict[str, dict]:
    """digest -> {kind, reports, sample, first_seen}, for every active signature. Cached."""
    global _cache
    now = time.monotonic()
    with _lock:
        if _cache[1] and now - _cache[0] < _TTL:
            return _cache[1]
    if db is None:
        return _cache[1]
    rows = db.query(SharedSignature).filter(SharedSignature.status == "active").all()
    out = {r.digest: {"kind": r.kind, "reports": r.reports or 0, "sample": r.sample or "",
                      "first_seen": r.first_seen.isoformat() if r.first_seen else None}
           for r in rows}
    with _lock:
        _cache = (now, out)
    return out


def invalidate() -> None:
    global _cache
    with _lock:
        _cache = (0.0, {})


def _poison_digests(finding: Finding) -> list[tuple[str, str, str]]:
    """[(kind, digest, sample)] a finding carries: the fold_key the guard set on each
    tool-poisoning signal is the description's digest, and the server name is in the subject
    metadata the signal detail names."""
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for s in finding.signals or []:
        if s.get("category") != "tool_poisoning":
            continue
        fk = s.get("fold") or s.get("fold_key") or ""
        if not fk.startswith("desc:"):
            continue
        desc, _, srv = fk[5:].partition("|srv:")
        if desc and desc not in seen:
            seen.add(desc); out.append(("tool_description", desc, s.get("evidence") or ""))
        if srv:
            d = digest_name(srv)
            if d not in seen:
                seen.add(d); out.append(("mcp_server", d, srv[:160]))
    return out


def contribute(db: Session, tenant: Tenant, finding: Finding) -> int:
    """The org confirmed this finding: add its report to each signature. Returns how many
    signatures were touched. No-op unless the org opted in."""
    if not tenant or not getattr(tenant, "share_signatures", False):
        return 0
    items = _poison_digests(finding)
    rep = _reporter(tenant.id)
    now = _now()
    touched = 0
    for kind, digest, sample in items:
        row = db.query(SharedSignature).filter(SharedSignature.digest == digest).one_or_none()
        if row is None:
            row = SharedSignature(kind=kind, digest=digest, sample=_sample(sample), reporters=[rep],
                                  reports=1, first_seen=now, last_seen=now, status="active")
            db.add(row)
        else:
            reps = list(row.reporters or [])
            if rep not in reps:
                reps.append(rep)
            row.reporters = reps
            row.reports = len(reps)
            row.last_seen = now
            row.status = "active"
        touched += 1
    if touched:
        db.commit()
        invalidate()
    return touched


def withdraw(db: Session, tenant: Tenant, finding: Finding) -> int:
    """The org says it was a false positive: take its report back. A signature nobody still
    reports is retracted."""
    if not tenant:
        return 0
    rep = _reporter(tenant.id)
    touched = 0
    for _kind, digest, _sample in _poison_digests(finding):
        row = db.query(SharedSignature).filter(SharedSignature.digest == digest).one_or_none()
        if row is None or rep not in (row.reporters or []):
            continue
        reps = [r for r in (row.reporters or []) if r != rep]
        row.reporters, row.reports = reps, len(reps)
        if not reps:
            row.status = "retracted"
        touched += 1
    if touched:
        db.commit()
        invalidate()
    return touched


def listing(db: Session, limit: int = 200) -> list[dict]:
    rows = (db.query(SharedSignature).order_by(SharedSignature.last_seen.desc()).limit(limit).all())
    return [{"id": r.id, "kind": r.kind, "digest": r.digest[:16], "sample": r.sample or "",
             "reports": r.reports or 0, "status": r.status,
             "first_seen": r.first_seen.isoformat() if r.first_seen else None,
             "last_seen": r.last_seen.isoformat() if r.last_seen else None} for r in rows]
