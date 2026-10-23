"""Where, in the text a client submitted, the values that blocked it are.

When a message is blocked only because it carries a secret or personal data, the person (or a
client that cannot ask them) can send it again with those values removed instead of retyping.
The verdict carries `redactions`: `{start, end, label}` for each value, as offsets into the
EXACT string the client submitted, so the client cuts the values out itself. The values never
come back from the server; a client that has the text does not need them, and a verdict is
logged, relayed and cached in places a credential must not reach.

Each span carries the offsets in two units: `start`/`end` in Unicode CODE POINTS (Python `str`
indexing, for the proxy and the hooks) and `start16`/`end16` in UTF-16 code units (JavaScript
string indexing, for the browser extension and editor clients). They differ by one for every
astral character (an emoji, some CJK) before the point. Every occurrence of a flagged value is
listed, not just the first.

Finding the values reuses the evidence masker's span finder (`excerpts._spans`) rather than a
third copy of the pattern tables. It runs on the raw text with homoglyphs folded one character
for one character, so an offset in the scanned copy is the same offset in the original. Views
that change length (NFKC folding of fullwidth digits, a decoded base64 blob, a key split by
spaces) are deliberately NOT mapped back: a value only those views reveal yields no span, and
the re-scan in main._redaction_plan then finds the block still standing, so the verdict says
`redactable: false` rather than offering a removal that would not clear it.

The marker a client puts where a value was is the same one stored findings and the coaching
copy use (app/redaction.py): `«redacted:<label>»`.
"""
from __future__ import annotations

import re
import unicodedata

from .detectors.normalize import _HOMOGLYPH_TABLE
from .detectors.shadow_ai import (CONTACT_LIST_TITLE, SSN_CONTEXT_RE, SSN_NODASH_RE,
                                  _valid_ssn9)

# Categories whose evidence is a value in the text that can be cut out.
REDACTABLE_CATEGORIES = frozenset({"secret_leak", "pii_exposure", "phi_exposure"})
# Categories that rule redaction out whenever they are present, whatever their weight: an
# action an agent is about to take, a tool or server that is not trusted, a scan that did not
# complete. Removing values from the text changes nothing about any of them.
_NEVER = frozenset({"dangerous_command", "unsafe_autonomy", "agent_authz", "tool_poisoning",
                    "mcp_untrusted_server", "mcp_integrity", "mcp_reputation",
                    "sensitive_resource_access", "session_correlation", "posture_gap",
                    "data_oversharing", "credential_at_rest", "dependency_risk",
                    "ci_workflow_risk"})
# Everything else that may sit beside a secret or PII (an unsanctioned destination,
# confidential prose, an injection or jailbreak phrase, hidden characters) is left to the
# re-scan in main._redaction_plan: if the text with the values removed would still BLOCK, the
# block rests on it and nothing is offered; if it would only warn, it is what that text alone
# would have scored had it been sent first, and removing the values is what this block needs.
# The detector whose data-loss signals come from matches this module can locate. A secret or
# PII signal from anything else (the LLM judge, a classifier) has no span to cut.
_SPAN_DETECTORS = frozenset({"shadow_ai"})

PLACEHOLDER = "«redacted:{label}»"

# Friendlier names for the masker's internal labels (what the person reads on the button).
_LABELS = {
    "AWS access key id": "AWS access key",
    "Private key block": "private key",
    "credential": "password or secret",
    "bearer token": "bearer token",
    "high-entropy": "possible secret",
    "card": "card number",
    "email": "email address",
    "phone": "phone number",
    "PHI": "health identifier",
}
_CONTACT_LABELS = frozenset({"email", "phone", "date of birth"})
_EVASION_SUFFIX = re.compile(r"\s*\(separator stripped.*\)$")
# Characters that belong to the one before them: a span must not end just before one, or the
# marker would be followed by an orphaned accent / joiner / emoji modifier.
_JOINERS = {chr(0x200D), chr(0xFE0E), chr(0xFE0F)}   # ZWJ, text and emoji presentation selectors


def placeholder(label: str) -> str:
    return PLACEHOLDER.format(label=label)


def _friendly(label: str) -> str:
    label = _EVASION_SUFFIX.sub("", label)
    return _LABELS.get(label, label)


def _clings(ch: str) -> bool:
    return ch in _JOINERS or unicodedata.category(ch).startswith("M") \
        or 0x1F3FB <= ord(ch) <= 0x1F3FF          # skin-tone modifiers


def precheck(signals: list[dict]) -> bool:
    """Whether redaction is worth attempting on a verdict with these signals, before looking
    for the values: there is a secret/PII/PHI signal, every such signal came from a detector
    whose matches have a span, and nothing in `_NEVER` is present. Passing this is necessary,
    not sufficient: the re-scan decides."""
    has_data = False
    for s in signals:
        cat = s.get("category") or ""
        if cat in _NEVER:
            return False
        if cat in REDACTABLE_CATEGORIES:
            if s.get("detector") not in _SPAN_DETECTORS:
                return False
            has_data = True
    return has_data


def find_spans(text: str, signals: list[dict], custom_pii: str = "") -> list[dict]:
    """`[{start, end, label}]`, sorted and non-overlapping, for the values behind the
    secret/PII/PHI signals in `signals`. Code-point offsets into `text` exactly as given."""
    from .excerpts import _spans

    cats = {s.get("category") for s in signals}
    kinds = set()
    if "secret_leak" in cats:
        kinds.add("secret")
    if "pii_exposure" in cats:
        kinds.add("pii")
    if "phi_exposure" in cats:
        kinds |= {"phi", "pii"}       # a patient record is identity + clinical context
    if not kinds or not text:
        return []
    # Contact details (an email, a phone number, a birth date) count only when the verdict
    # acted on them: a contact list, a pile of phone numbers, a personal or patient record.
    # Otherwise a support line in the same message is the person's business, not a leak.
    evidence = " ".join(f"{s.get('title', '')} {s.get('evidence', '')}" for s in signals
                        if s.get("category") in REDACTABLE_CATEGORIES)
    contacts = (CONTACT_LIST_TITLE in evidence or "phone numbers" in evidence
                or "personal record" in evidence or "patient record" in evidence)

    scan = text.translate(_HOMOGLYPH_TABLE)
    assert len(scan) == len(text)     # one for one, or every offset below would be wrong
    hits: list[tuple[int, int, str]] = []
    for sp in _spans(text, custom_pii, fuzzy=False):
        usable = [lbl for lbl in sp.labels if contacts or lbl not in _CONTACT_LABELS]
        if not usable:
            continue
        if sp.kind not in kinds and not ("pii" in kinds and sp.kind == "phi"):
            continue
        hits.append((sp.start, sp.end, _friendly(usable[0])))
    # An unformatted nine-digit SSN counts in the detector only beside the words that name it;
    # the masker has no such rule (its digit-run class is off here), so add it the same way.
    if "pii" in kinds and SSN_CONTEXT_RE.search(scan):
        for m in SSN_NODASH_RE.finditer(scan):
            if _valid_ssn9(m.group(0)):
                hits.append((m.start(), m.end(), "SSN"))
    if not hits:
        return []
    # Every occurrence of each value, not only the ones a context-gated rule saw.
    seen: dict[str, str] = {}
    for s, e, label in hits:
        seen.setdefault(text[s:e], label)
    for value, label in seen.items():
        if len(value) < 4:
            continue                      # too short to look for on its own
        i = text.find(value)
        while i != -1:
            hits.append((i, i + len(value), label))
            i = text.find(value, i + 1)
    hits.sort(key=lambda h: (h[0], -h[1]))
    out: list[dict] = []
    for s, e, label in hits:
        while e < len(text) and _clings(text[e]):
            e += 1
        if out and s < out[-1]["end"]:
            out[-1]["end"] = max(out[-1]["end"], e)
        else:
            out.append({"start": s, "end": e, "label": label})
    return out


def with_utf16(text: str, spans: list[dict]) -> list[dict]:
    """`spans` with `start16`/`end16` added: the same offsets in UTF-16 code units, which is
    how JavaScript indexes a string. Each astral character (an emoji, some CJK) before a
    point counts once in code points and twice in UTF-16."""
    out = []
    cp = u16 = 0
    for sp in sorted(spans, key=lambda x: x["start"]):
        pos = {}
        for target in (sp["start"], sp["end"]):
            while cp < target:
                u16 += 2 if ord(text[cp]) > 0xFFFF else 1
                cp += 1
            pos[target] = u16
        out.append({"start": sp["start"], "end": sp["end"],
                    "start16": pos[sp["start"]], "end16": pos[sp["end"]], "label": sp["label"]})
    return out


def apply(text: str, spans: list[dict]) -> str:
    """`text` with each span replaced by its marker. Right to left, so earlier offsets stay
    valid while later ones are rewritten — the same order a client must use."""
    for sp in sorted(spans, key=lambda x: x["start"], reverse=True):
        text = text[:sp["start"]] + placeholder(sp["label"]) + text[sp["end"]:]
    return text
