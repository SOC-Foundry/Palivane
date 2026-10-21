"""Masked context for a finding: the few words around each match, with the sensitive part gone.

A finding that says "SSN" or "High-risk command" tells an analyst *what* fired but not whether
it was real: a customer's record or a made-up example in a README, `curl | bash` against an
installer the team uses daily or against a paste site. This module builds the evidence an
analyst needs to answer that, and nothing more:

  * a short window (about 80 characters either side) around each match, with every secret and
    identifier in it replaced by a `«redacted:label»` marker, or
  * for a tool call, the command or path that was run, masked the same way.

It is deliberately stricter than `redaction.redact_text`, which protects whole stored prompts.
This text is *shown to people*, so it also masks emails, phone numbers, birth dates and long
digit runs, keeps the NAME of a credential variable (`AWS_SECRET_ACCESS_KEY=«redacted»` says
which secret leaked; `redact_text` swallows the name), and scans a normalized copy of the text so
zero-width characters, fullwidth letters and Cyrillic lookalikes cannot hide a key from the mask
the way they cannot hide it from the detector.

What it does NOT do: it cannot mask a name, an address or free-form prose, because nothing here
can tell them from any other words. That is why the feature is opt-in per organization, expires
with the stored-content TTL, and never rides alert, SIEM, S3-lake or analyst payloads. See
`Finding.evidence_context`.

Fail-closed by construction: the only way text leaves this module is `_render`, which replaces
every span first, and replaces a span the window only touches WHOLE, so a match is never cut in
half and left half-visible.
"""
from __future__ import annotations

import json
import logging
import re
import unicodedata
from dataclasses import dataclass, field

from .detectors.normalize import _HOMOGLYPH_TABLE, _ZERO_WIDTH
from .detectors.patterns import (EVASION_PATTERNS, PRIVATE_KEY_BLOCK_RE, SECRET_PATTERNS,
                                 custom_patterns, custom_pii_patterns, find_high_entropy_tokens)
from .detectors.shadow_ai import (CC_CANDIDATE_RE, EMAIL_RE, PHONE_RE, SSN_RE, _DOB_CUED_RE,
                                  _PHI_CONTEXT, _PHI_STRONG, _PHI_VALIDATED, _PII_CONTEXT,
                                  _PII_STRONG, _PII_STRUCT, _PII_VALIDATED, _luhn_ok)

_log = logging.getLogger(__name__)

WINDOW = 80            # characters of context either side of a match
MAX_TEXT = 400         # hard cap on one stored excerpt
MAX_TARGET = 300       # a command or path is shown whole, up to this
MAX_SCAN = 100_000     # never scan more than this much of one input
MAX_ENTRIES = 8        # signals with an excerpt, per finding
VERSION = 1

_CRED = "credential"

# `password=…`, `api_key: …`, `export SECRET_TOKEN=…`: the same left-hand sides the detector's
# "Credential assignment" rule reads, but split in two so the NAME survives and only the value
# is masked.
_CRED_RE = re.compile(
    r"(?i)(\b\w*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|"
    r"access[_-]?token|client[_-]?secret|auth[_-]?token|token)\s*[:=]\s*[\"']?)([^\s\"']{8,})")
# A value that is only a reference to a variable names no secret: `$API_TOKEN`, `${TOKEN}`.
# Showing it is what tells an analyst "this command reads the credential, it does not contain it".
_VARIABLE_REF_RE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?[\"')]*$")
# `Authorization: Bearer <token>` / `Basic <b64>`: the scheme word stays, the token goes.
_BEARER_RE = re.compile(
    r"(?i)\b(bearer|basic)(\s+)((?=[A-Za-z0-9._~+/=-]*\d)[A-Za-z0-9._~+/=-]{8,}|[A-Za-z0-9._~+/=-]{16,})")
_DIGIT_RUN_RE = re.compile(r"(?<!\d)\d{9,}(?!\d)")
_HEX_RE = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{32,}(?![0-9A-Za-z])")

# A shell tool carries a command, so its excerpt is labelled one.
_SHELL_TOOLS = frozenset({
    "bash", "sh", "zsh", "fish", "shell", "powershell", "pwsh", "cmd", "terminal",
    "run_command", "run_shell_command", "run_terminal_cmd", "execute_command", "exec",
    "exec_command", "local_shell", "shell_command"})

_SECRET_CATS = frozenset({"secret_leak", "credential_at_rest"})
_PERSONAL_CATS = frozenset({"pii_exposure", "phi_exposure"})

_LABEL_SAFE_RE = re.compile(r"[^\w .+/()-]")


@dataclass
class _Span:
    start: int
    end: int
    kind: str                                   # secret | pii | phi
    labels: list[str] = field(default_factory=list)

    def placeholder(self) -> str:
        label = self.labels[0] if self.labels else "value"
        if label == _CRED:
            return "«redacted»"
        return f"«redacted:{_LABEL_SAFE_RE.sub('', label)[:40].strip() or 'value'}»"


# --- normalization ---------------------------------------------------------------------

def _visible(text: str) -> str:
    """The text as a person (and the model) would read it: compatibility forms folded, hidden
    characters gone, control characters gone. Scanning and display both use this copy, so what
    is masked is what is shown."""
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH.sub("", text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return text.replace("\r\n", "\n").replace("\r", "\n")


# --- spans -----------------------------------------------------------------------------

def _spans(shown: str, custom_pii: str = "", fuzzy: bool = True) -> list[_Span]:
    """Every region of `shown` that must not be displayed, merged and sorted. Matching runs on a
    homoglyph-folded copy of the same length, so a lookalike letter cannot hide a key from the
    mask; the characters displayed are still the real ones.

    `fuzzy` adds the two classes that are only worth masking in free text, where a long hex run or
    a long digit run is as likely a key or an account number as anything else. A detector's own
    structured evidence keeps them: a commit SHA, an image digest or a timestamp is what an
    analyst needs to read there, and masking it would only cost a finding its meaning."""
    scan = shown.translate(_HOMOGLYPH_TABLE)
    hits: list[tuple[int, int, str, str]] = []

    def add(rx, label: str, kind: str, group: int = 0, ok=None) -> None:
        for m in rx.finditer(scan):
            if ok is not None and not ok(m):
                continue
            s, e = m.span(group)
            e = s + len(scan[s:e].rstrip(" -"))   # a card match swallows the space after its last digit
            if e > s:
                hits.append((s, e, label, kind))

    for label, rx in SECRET_PATTERNS:
        if label != "Credential assignment":
            add(rx, label, "secret")
    add(PRIVATE_KEY_BLOCK_RE, "Private key block", "secret")
    for label, rx in EVASION_PATTERNS:
        add(rx, label, "secret")
    for label, rx in custom_patterns():
        add(rx, label, "secret")
    add(_CRED_RE, _CRED, "secret", group=2,
        ok=lambda m: not _VARIABLE_REF_RE.match(m.group(2)))
    add(_BEARER_RE, "bearer token", "secret", group=3)
    if fuzzy:
        add(_HEX_RE, "hex", "secret")
    for tok in find_high_entropy_tokens(scan):
        full = tok[:-1] if tok.endswith("…") else tok
        if len(full) >= 10:
            for m in re.finditer(re.escape(full) + r"[A-Za-z0-9_\-]*", scan):
                hits.append((m.start(), m.end(), "high-entropy", "secret"))

    add(SSN_RE, "SSN", "pii")
    add(CC_CANDIDATE_RE, "card", "pii",
        ok=lambda m: _luhn_ok(re.sub(r"[ -]", "", m.group(0))))
    add(EMAIL_RE, "email", "pii")
    add(PHONE_RE, "phone", "pii")
    add(_DOB_CUED_RE, "date of birth", "pii")
    if fuzzy:
        add(_DIGIT_RUN_RE, "number", "pii")
    for label, rx in custom_pii_patterns(custom_pii):
        add(rx, label, "pii")
    # Every identifier class the detector can flag, so an excerpt for a PII/PHI finding never shows
    # the value that raised it. Context-gated classes (a passport number, an MRN) are masked only
    # when their context word is present, exactly as the detector reads them; a validated class
    # is masked whenever its check digit passes, with or without the context word.
    for label, rx, _w in _PII_STRONG + _PII_STRUCT:
        add(rx, label, "pii")
    for label, ctx_re, val_re, _w in _PII_CONTEXT:
        if ctx_re.search(scan):
            add(val_re, label, "pii")
    for label, _ctx, cand_re, valid, _w in _PII_VALIDATED:
        add(cand_re, label, "pii", ok=lambda m, v=valid: v(m.group(0)))
    for _label, rx, _w in _PHI_STRONG:
        add(rx, "PHI", "phi")
    for _label, ctx_re, val_re, _w in _PHI_CONTEXT:
        if ctx_re.search(scan):
            add(val_re, "PHI", "phi")
    for _label, _ctx, cand_re, valid, _w in _PHI_VALIDATED:
        add(cand_re, "PHI", "phi", ok=lambda m, v=valid: v(m.group(0)))

    hits.sort(key=lambda h: (h[0], -h[1]))
    merged: list[_Span] = []
    for s, e, label, kind in hits:
        if merged and s < merged[-1].end:
            cur = merged[-1]
            cur.end = max(cur.end, e)
            if label not in cur.labels:
                cur.labels.append(label)
            if kind == "secret":
                cur.kind = "secret"
        else:
            merged.append(_Span(s, e, kind, [label]))
    return merged


def _render(shown: str, spans: list[_Span], lo: int, hi: int) -> str:
    """`shown[lo:hi]` with every span it touches replaced WHOLE by its marker: a window edge that
    lands inside a match shows the marker, never the half of the match that fell inside."""
    out: list[str] = []
    pos = lo
    for sp in spans:
        if sp.end <= lo:
            continue
        if sp.start >= hi:
            break
        if sp.start > pos:
            out.append(shown[pos:sp.start])
        out.append(sp.placeholder())
        pos = max(pos, sp.end)
    if pos < hi:
        out.append(shown[pos:hi])
    return "".join(out)


def mask_text(text: str, custom_pii: str = "", *, fuzzy: bool = False) -> str:
    """`text` with every secret and identifier replaced by a marker. For short strings (a
    signal's detail or evidence); an excerpt of a long one goes through `build`. Text with
    nothing to mask comes back exactly as it was written (a detector's `…` stays a `…`)."""
    if not text:
        return text
    full = _visible(text)
    shown = full[:MAX_SCAN]
    spans = _spans(shown, custom_pii, fuzzy)
    if not spans:
        # Never hand back what was not scanned: past the scan limit the text is cut, not passed on.
        return text if len(full) <= MAX_SCAN else shown
    return _render(shown, spans, 0, len(shown))


def clean_signals(signals: list[dict], custom_pii: str = "") -> list[dict]:
    """The signal list as it is stored: `detail` and `evidence` masked. A detector that quotes
    the text it matched (the dangerous-command rule quotes up to 80 characters of the command)
    would otherwise store a credential that happened to sit inside the quoted part."""
    out = []
    for s in signals:
        s2 = dict(s)
        for key in ("detail", "evidence"):
            v = s2.get(key)
            if isinstance(v, str) and v:
                try:
                    s2[key] = mask_text(v, custom_pii)
                except Exception:
                    # Fail closed. A line that cannot be checked is not stored: losing one line of
                    # evidence beats failing the ingest, and beats storing a quoted credential.
                    _log.warning("could not mask a signal's %s; stored empty", key, exc_info=True)
                    s2[key] = ""
        out.append(s2)
    return out


# --- excerpts --------------------------------------------------------------------------

def _tidy(text: str) -> str:
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n[ \t]*(?:\n[ \t]*)+", "\n\n", text)
    return text.strip()


def _window(shown: str, spans: list[_Span], a: int, b: int) -> dict | None:
    lo, hi = max(0, a - WINDOW), min(len(shown), b + WINDOW)
    text = _tidy(_render(shown, spans, lo, hi))
    if not text:
        return None
    cut_after = hi < len(shown)
    if len(text) > MAX_TEXT:
        text, cut_after = text[:MAX_TEXT], True
    return {"text": text, "cut": [lo > 0, cut_after]}


def _whole(shown: str, spans: list[_Span], limit: int = MAX_TARGET) -> dict | None:
    hi = min(len(shown), limit)
    text = _tidy(_render(shown, spans, 0, hi))
    if not text:
        return None
    return {"text": text[:MAX_TEXT], "cut": [False, hi < len(shown) or len(text) > MAX_TEXT]}


def _find(shown: str, needle: str) -> int:
    if not needle:
        return -1
    i = shown.find(needle)
    if i >= 0:
        return i
    m = re.search(re.escape(needle), shown, re.I)
    return m.start() if m else -1


def _where(item, shell: bool) -> str:
    """What the excerpt is an excerpt OF, so the console can say so."""
    surface = getattr(item.surface, "value", item.surface)
    if surface in ("mcp", "agent_tools"):
        return "command" if shell else "call"
    if surface in ("ai_usage", "llm_io"):
        return "response" if (item.subject or "").startswith("LLM response") else "prompt"
    if surface in ("collab", "a2a"):
        return "message"
    return "content"


# Categories whose evidence is a phrase the detector quoted from the text (an injection
# phrase, a confidentiality marker), so the phrase is the anchor.
_PHRASE_CATS = frozenset({"prompt_injection", "jailbreak", "data_exfiltration",
                          "confidential_data", "source_code_leak"})


def _phrases(evidence: str) -> list[str]:
    """Literal phrases a detector quoted as its evidence ('ignore all previous'), as opposed to
    labels ('SSN') and key=value summaries ('tool=Bash')."""
    out = []
    for part in re.split(r"[;,]\s*", evidence or ""):
        part = part.strip().rstrip("…").strip()
        if 4 <= len(part) <= 200 and "=" not in part:
            out.append(part)
    return out


def build(item, signals: list[dict], *, custom_pii: str = "") -> list[dict]:
    """Excerpts for the signals that have something to show: `[{i, text, where, cut}]`, `i`
    being the signal's index in `signals`. Nothing for a signal with no locatable match (an
    unsanctioned destination, a classifier score), and nothing is ever guessed: if the match
    cannot be found in the text, the signal gets no excerpt."""
    meta = item.metadata or {}
    shell = str(meta.get("tool") or item.channel or "").lower() in _SHELL_TOOLS
    where = _where(item, shell)
    agentic = where in ("command", "call")

    body = _visible(item.content or "")[:MAX_SCAN]
    spans = _spans(body, custom_pii)
    # An agent tool call's content is its arguments plus the resource it names; the command
    # and the path are shown from their own fields, so each is masked on its own.
    args = _visible(str(meta.get("args_text") or ""))[:MAX_SCAN] if agentic else ""
    args_spans = _spans(args, custom_pii) if args else spans
    resource = _visible(str(meta.get("resource") or ""))[:MAX_SCAN] if agentic else ""

    def around_match(labels: str, kinds: set[str]) -> dict | None:
        """The window around the span the signal is about: the one whose label the signal's
        evidence names, else the first of that kind."""
        cands = [sp for sp in spans if sp.kind in kinds]
        if not cands:
            return None
        low = labels.lower()
        pick = next((sp for sp in cands if any(lab.lower() in low for lab in sp.labels)), cands[0])
        return _window(body, spans, pick.start, pick.end)

    entries: list[dict] = []
    for i, sig in enumerate(signals):
        if len(entries) >= MAX_ENTRIES:
            break
        cat = sig.get("category", "")
        ev = sig.get("evidence") or ""
        label = where
        found: dict | None = None

        if cat in _SECRET_CATS:
            found = around_match(ev, {"secret"})
        elif cat in _PERSONAL_CATS:
            found = around_match(ev, {"pii", "phi"})
        elif agentic and cat == "dangerous_command":
            # The detector quotes the command it matched in `detail`; anchor on it, else show
            # the command from its start.
            text = args or body
            quoted = re.search(r"pattern: (.+)\Z", sig.get("detail") or "", re.S)
            needle = quoted.group(1)[:60] if quoted else ""
            at = _find(text, needle)
            found = (_window(text, args_spans, at, at + len(needle)) if at >= 0
                     else _whole(text, args_spans))
        elif agentic and cat == "sensitive_resource_access":
            # The path the call targets: the resource field when the client sent one (a file
            # tool), else the first line of the arguments (a shell command that names it).
            if resource:
                found, label = _whole(resource, _spans(resource, custom_pii)), "path"
            else:
                first = (args or body).split("\n", 1)[0]
                found = _whole(first, _spans(first, custom_pii))
        elif cat in _PHRASE_CATS:
            for phrase in _phrases(ev):
                at = _find(body, phrase)
                if at >= 0:
                    found = _window(body, spans, at, at + len(phrase))
                    break

        if found:
            entries.append({"i": i, "text": found["text"], "where": label, "cut": found["cut"]})
    return entries


# --- storage ---------------------------------------------------------------------------

def dumps(entries: list[dict]) -> str:
    return json.dumps({"v": VERSION, "items": entries}, ensure_ascii=False, separators=(",", ":")) \
        if entries else ""


def loads(blob: str) -> list[dict]:
    """The stored entries, tolerant of anything unexpected (an old shape, a damaged row): the
    detail view must open even if the context cannot be read."""
    try:
        data = json.loads(blob) if blob else {}
    except (TypeError, ValueError):
        return []
    items = data.get("items") if isinstance(data, dict) else None
    out = []
    for it in items or []:
        if (isinstance(it, dict) and type(it.get("i")) is int and isinstance(it.get("text"), str)
                and it["text"]):
            cut = it.get("cut")
            out.append({"i": it["i"], "text": it["text"][:MAX_TEXT],
                        "where": it.get("where") if isinstance(it.get("where"), str) else "content",
                        "cut": [bool(cut[0]), bool(cut[1])]
                        if isinstance(cut, list) and len(cut) == 2 else [False, False]})
    return out


def merge(signals: list[dict], entries: list[dict]) -> list[dict]:
    """`signals` with each entry attached to its signal as `context`."""
    out = [dict(s) for s in signals or []]
    for e in entries:
        if 0 <= e["i"] < len(out):
            out[e["i"]]["context"] = {"text": e["text"], "where": e["where"], "cut": e["cut"]}
    return out
