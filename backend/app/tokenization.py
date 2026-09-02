"""Reversible tokenization for gateway traffic: the provider never sees the real value.

The gateway already stands between a client and OpenAI/Anthropic/Gemini, scoring prompts
on the way out. Scoring alone still lets the value through. Tokenizing substitutes a
stable placeholder after the scan and puts the real value back into the answer, so the
model can reason over the structure of a record without the provider ever holding it:

    "reformat this: SSN 123-45-6789"   ->   "reformat this: SSN PLV_USSN_CB96E4"
    "...for PLV_USSN_CB96E4"           ->   "...for 123-45-6789"

The map lives in the request handler's locals for the length of one exchange and is never
written anywhere. That is the same rule the client-side tokenizer follows and it matters
here too: a stored plaintext-to-token vault would be the sensitive data again, in one
high-value place, and Palivane's whole data-handling promise is that the verdict is kept
and the text is not.

Detection is NOT reimplemented. The pattern tables in detectors.shadow_ai are walked
directly, with the same context gating and the same validators, because a second copy of
those rules would drift from the detector the first time a format changed and the drift
would be silent: prompts would be scored on one set of patterns and tokenized on another.

Secrets are deliberately out of scope. A credential must not reach the provider in any
form, tokenized or otherwise; the gateway blocks those instead.
"""
from __future__ import annotations

import re
import secrets as _secrets

from .detectors.patterns import custom_pii_patterns
from .detectors.shadow_ai import (CC_CANDIDATE_RE, SSN_CONTEXT_RE, SSN_NODASH_RE, SSN_RE,
                                  _PII_CONTEXT, _PII_STRONG, _PII_STRUCT, _PII_VALIDATED,
                                  _TEST_CARDS, _luhn_ok, _valid_ssn9)

TOKEN_RE = re.compile(r"PLV_[A-Z0-9]{2,12}_[0-9A-F]{6}")
MAX_CHARS = 200_000          # a prompt larger than this is not worth the regex sweep


def _slug(label: str) -> str:
    """Short readable tag so a model can tell two kinds of value apart. Same scheme as the
    client-side tokenizer, so a token minted by either is recognisable to both."""
    words = [w for w in re.split(r"[^A-Za-z0-9]+", label) if w]
    out = "".join(w[0] for w in words).upper() if len(words) > 1 else (words[0].upper() if words else "PII")
    return out[:12] or "PII"


def _matches(text: str, extra_patterns: str = "") -> dict[str, str]:
    """{raw value: label} for every personal-data match, using the detector's own tables."""
    found: dict[str, str] = {}

    def take(label: str, value: str) -> None:
        # Very short matches are not worth substituting and risk mangling ordinary prose.
        if len(value) >= 6:
            found.setdefault(value, label)

    # SSN and payment cards are matched by their own module-level regexes rather than by
    # one of the tables, with the same validators the detector applies: an unformatted
    # nine-digit run only counts near the words that name it, and a card must pass Luhn.
    for m in SSN_RE.finditer(text):
        if _valid_ssn9(re.sub(r"\D", "", m.group(0))):
            take("US Social Security number", m.group(0))
    if SSN_CONTEXT_RE.search(text):
        for m in SSN_NODASH_RE.finditer(text):
            if _valid_ssn9(m.group(0)):
                take("US Social Security number", m.group(0))
    for m in CC_CANDIDATE_RE.finditer(text):
        # The candidate regex is `(?:\d[ -]?){13,16}`, so a match can end on the separator
        # after the last digit. Substituting that verbatim eats the space and welds the
        # token to the next word. Trim to the digits the value actually is.
        raw = m.group(0).rstrip(" -")
        digits = re.sub(r"[ -]", "", raw)
        if len(digits) >= 13 and _luhn_ok(digits) and digits not in _TEST_CARDS:
            take("payment card number", raw)
    for label, rx, _w in _PII_STRONG:
        for m in rx.finditer(text):
            take(label, m.group(0))
    for label, ctx_re, val_re, _w in _PII_CONTEXT:
        if ctx_re.search(text):
            for m in val_re.finditer(text):
                take(label, m.group(0))
    for label, ctx_re, cand_re, valid, _w in _PII_VALIDATED:
        if ctx_re is not None and not ctx_re.search(text):
            continue
        for m in cand_re.finditer(text):
            if valid(m.group(0)):
                take(label, m.group(0))
    for label, rx, _w in _PII_STRUCT:
        for m in rx.finditer(text):
            take(label, m.group(0))
    for label, rx in custom_pii_patterns(extra_patterns):
        for m in rx.finditer(text):
            take(label, m.group(0))
    return found


def tokenize(text: str, extra_patterns: str = "",
             mapping: dict[str, str] | None = None) -> tuple[str, dict[str, str]]:
    """`text` with personal data replaced by tokens, plus the {token: original} map.

    Pass an existing `mapping` to extend it: one prompt is many strings (several messages,
    a system block), and the same person appearing in two of them must get the same token
    or the model cannot tell it is the same person.

    Longest values first, so a short value sitting inside a longer one cannot leave a
    fragment of the longer one behind.
    """
    mapping = mapping if mapping is not None else {}
    if not text or len(text) > MAX_CHARS:
        return text, mapping
    seen = {v: t for t, v in mapping.items()}
    for val, label in sorted(_matches(text, extra_patterns).items(),
                             key=lambda kv: len(kv[0]), reverse=True):
        token = seen.get(val)
        if token is None:
            token = f"PLV_{_slug(label)}_{_secrets.token_hex(3).upper()}"
            while token in mapping:
                token = f"PLV_{_slug(label)}_{_secrets.token_hex(3).upper()}"
            mapping[token] = val
            seen[val] = token
        text = text.replace(val, token)
    return text, mapping


def detokenize(text: str, mapping: dict[str, str]) -> str:
    """Put the real values back. Case-insensitive, because a model does not always echo a
    token verbatim. Tokens the map does not know are left alone rather than deleted."""
    if not mapping or not text:
        return text
    lower = {t.lower(): v for t, v in mapping.items()}
    return re.sub(TOKEN_RE.pattern,
                  lambda m: lower.get(m.group(0).lower(), m.group(0)), text, flags=re.I)


# --- streaming ------------------------------------------------------------------------
# A streamed answer arrives in chunks that can split a token down the middle, so reversing
# one chunk at a time would emit half a token and then an orphan tail. Work in BYTES: a
# token is pure ASCII by construction, so a multi-byte character split across the same
# boundary passes through untouched, which decoding chunk-by-chunk would not guarantee.

TOKEN_MAX = 4 + 12 + 1 + 6        # "PLV_" + slug + "_" + hex, the longest a token can be
_TOKEN_RE_B = re.compile(rb"PLV_[A-Z0-9]{2,12}_[0-9A-F]{6}", re.I)


def detokenize_bytes(data: bytes, mapping: dict[str, str]) -> bytes:
    """detokenize over raw bytes, for a response body that was never decoded."""
    if not mapping or not data:
        return data
    lower = {t.lower().encode(): v.encode() for t, v in mapping.items()}
    return _TOKEN_RE_B.sub(lambda m: lower.get(m.group(0).lower(), m.group(0)), data)


# Any PREFIX of a token, anchored at the end of the buffer. The complete form is excluded
# by capping the hex run at five: six means the token is finished and safe to substitute.
# Matching only the whole "PLV_" literal is not enough — with one-byte chunks the "P" is
# released before the "L" arrives, and the token is never seen at all.
_PARTIAL_RE_B = re.compile(rb"P(?:L(?:V(?:_(?:[A-Z0-9]{1,12}(?:_[0-9A-F]{0,5})?)?)?)?)?$", re.I)


def _emit_upto(buf: bytes) -> int:
    """How much of `buf` can be released without risking a half-written token.

    Everything, unless the tail is the beginning of one — then stop there and keep the rest
    for the next chunk. A stray trailing "P" costs a few bytes of delay and is flushed when
    the stream ends, which is the right way to be wrong.
    """
    m = _PARTIAL_RE_B.search(buf)
    if m and not _TOKEN_RE_B.match(buf, m.start()):
        return m.start()
    return len(buf)


def detokenize_stream(chunks, mapping: dict[str, str]):
    """Wrap a byte-chunk iterator, reversing tokens as they go.

    Holds back only a possible partial token (at most 23 bytes), so the client still sees
    output arrive live: this is not buffering the response.
    """
    if not mapping:
        yield from chunks
        return
    carry = b""
    for chunk in chunks:
        buf = carry + chunk
        cut = _emit_upto(buf)
        carry = buf[cut:]
        if cut:
            yield detokenize_bytes(buf[:cut], mapping)
    if carry:
        yield detokenize_bytes(carry, mapping)


def detokenize_obj(obj, mapping: dict[str, str]):
    """detokenize every string in a response payload, whatever shape it is. Structure is
    untouched: only string leaves change, and a token cannot collide with a key name."""
    if not mapping:
        return obj
    if isinstance(obj, str):
        return detokenize(obj, mapping)
    if isinstance(obj, list):
        return [detokenize_obj(x, mapping) for x in obj]
    if isinstance(obj, dict):
        return {k: detokenize_obj(v, mapping) for k, v in obj.items()}
    return obj


# Where prompt text actually lives in each provider's request body. Only these are
# rewritten: walking every string would also hit model names, tool schemas and ids.
def tokenize_payload(payload: dict, extra_patterns: str = "") -> tuple[dict, dict[str, str]]:
    """A copy of `payload` with prompt text tokenized, plus the map to reverse it.

    Covers the OpenAI chat shape (`messages[].content`, string or typed blocks) and the
    Anthropic shape (the same plus a top-level `system`). Anything else is returned
    unchanged with an empty map, which fails safe: no tokens out means nothing to reverse.
    """
    mapping: dict[str, str] = {}

    def do_content(c):
        if isinstance(c, str):
            out, _ = tokenize(c, extra_patterns, mapping)
            return out
        if isinstance(c, list):
            blocks = []
            for b in c:
                if isinstance(b, dict) and isinstance(b.get("text"), str):
                    b = dict(b)
                    b["text"], _ = tokenize(b["text"], extra_patterns, mapping)
                blocks.append(b)
            return blocks
        return c

    out = dict(payload)
    if isinstance(out.get("system"), str):
        out["system"], _ = tokenize(out["system"], extra_patterns, mapping)
    elif isinstance(out.get("system"), list):
        out["system"] = do_content(out["system"])
    msgs = out.get("messages")
    if isinstance(msgs, list):
        out["messages"] = [({**m, "content": do_content(m["content"])}
                            if isinstance(m, dict) and "content" in m else m)
                           for m in msgs]

    # OpenAI Responses API (Codex CLI's default): `input` replaces `messages` and is a bare
    # string or a list of typed items; `instructions` is its system prompt.
    if isinstance(out.get("instructions"), str):
        out["instructions"], _ = tokenize(out["instructions"], extra_patterns, mapping)
    inp = out.get("input")
    if isinstance(inp, str):
        out["input"], _ = tokenize(inp, extra_patterns, mapping)
    elif isinstance(inp, list):
        out["input"] = [({**it, "content": do_content(it["content"])}
                         if isinstance(it, dict) and "content" in it else it)
                        for it in inp]

    # Gemini: text lives in parts[].text, under contents[] and the system instruction.
    def do_parts(node):
        if not isinstance(node, dict) or not isinstance(node.get("parts"), list):
            return node
        parts = []
        for part in node["parts"]:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                part = dict(part)
                part["text"], _ = tokenize(part["text"], extra_patterns, mapping)
            parts.append(part)
        return {**node, "parts": parts}

    if isinstance(out.get("contents"), list):
        out["contents"] = [do_parts(c) for c in out["contents"]]
    for key in ("systemInstruction", "system_instruction"):
        if isinstance(out.get(key), dict):
            out[key] = do_parts(out[key])
    return out, mapping
