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

import json
import re
import secrets as _secrets

from .detectors.patterns import custom_pii_patterns
from .detectors.shadow_ai import (CC_CANDIDATE_RE, SSN_CONTEXT_RE, SSN_NODASH_RE, SSN_RE,
                                  _PII_CONTEXT, _PII_STRONG, _PII_STRUCT, _PII_VALIDATED,
                                  _TEST_CARDS, _luhn_ok, _valid_ssn9)

TOKEN_RE = re.compile(r"PLV_[A-Z0-9]{2,12}_[0-9A-F]{6}")
MAX_CHARS = 200_000          # one detector sweep covers at most this much text
OVERLAP = 2_000              # consecutive sweeps share this much, see _matches_windowed


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


def _matches_windowed(text: str, extra_patterns: str = "") -> dict[str, str]:
    """_matches over text of any length, as overlapping windows of at most MAX_CHARS.

    A long prompt cannot be skipped: the scan has already run, and this is the step that
    keeps the values out of the body the provider receives. Consecutive windows overlap by
    OVERLAP characters, so any value up to that long lies wholly inside at least one window
    and is found intact even when it straddles a boundary. Every personal-data format the
    detector knows is far shorter. A window edge can also cut a value and leave a fragment
    that still matches (a card's first thirteen digits can pass Luhn). That is harmless:
    substitution happens once over the whole text and prefers the longest value at each
    position, so the full value wins and the fragment is only replaced where it stands on
    its own. One difference from a single sweep: a context word (the "SSN" that lets a bare
    nine-digit run count) only qualifies values in the same window as it.

    The cost is bounded. Each window is one ordinary sweep of at most MAX_CHARS, and the
    windows advance by MAX_CHARS - OVERLAP, so the text is swept about 1.01 times over.
    The request body cap (settings.max_body_bytes, 12 MB by default) bounds the text, so
    the worst case is some sixty sweeps, not something that grows with the input.
    """
    if len(text) <= MAX_CHARS:
        return _matches(text, extra_patterns)
    found: dict[str, str] = {}
    step = MAX_CHARS - OVERLAP
    for start in range(0, len(text), step):
        for val, label in _matches(text[start:start + MAX_CHARS], extra_patterns).items():
            found.setdefault(val, label)
        if start + MAX_CHARS >= len(text):
            break
    return found


def tokenize(text: str, extra_patterns: str = "",
             mapping: dict[str, str] | None = None) -> tuple[str, dict[str, str]]:
    """`text` with personal data replaced by tokens, plus the {token: original} map.

    Pass an existing `mapping` to extend it: one prompt is many strings (several messages,
    a system block), and the same person appearing in two of them must get the same token
    or the model cannot tell it is the same person.

    Longest values first, so a short value sitting inside a longer one cannot leave a
    fragment of the longer one behind. Substitution is one regex pass with the values as
    alternatives in that order, not one str.replace per value: a large prompt can hold
    thousands of values, and the pass stays linear in the text however many there are.
    """
    mapping = mapping if mapping is not None else {}
    if not text:
        return text, mapping
    found = _matches_windowed(text, extra_patterns)
    if not found:
        return text, mapping
    seen = {v: t for t, v in mapping.items()}
    vals = sorted(found, key=len, reverse=True)
    for val in vals:
        if val in seen:
            continue
        token = f"PLV_{_slug(found[val])}_{_secrets.token_hex(3).upper()}"
        while token in mapping:
            token = f"PLV_{_slug(found[val])}_{_secrets.token_hex(3).upper()}"
        mapping[token] = val
        seen[val] = token
    rx = re.compile("|".join(map(re.escape, vals)))
    return rx.sub(lambda m: seen[m.group(0)], text), mapping


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


# A token that survives reversal is the one failure this feature has that no test can
# reach: it depends on whether a real model echoes a token intact. Deliberately LOOSER than
# TOKEN_RE, because the interesting case is a model that altered one — "PLV-USSN-A7C9D5",
# a stray case change, a split — none of which the strict pattern matches any more. What
# matters is that the user is looking at a placeholder instead of their own data.
_RESIDUAL_RE_B = re.compile(rb"\bPLV[-_ ][A-Za-z0-9]{2,12}[-_ ]", re.I)


def count_residuals(data: bytes | str) -> int:
    """How many Palivane tokens are still visible in text that has already been reversed."""
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return len(_RESIDUAL_RE_B.findall(data)) if data else 0


def detokenize_stream(chunks, mapping: dict[str, str], on_residual=None):
    """Wrap a byte-chunk iterator, reversing tokens as they go.

    Holds back only a possible partial token (at most 23 bytes), so the client still sees
    output arrive live: this is not buffering the response.
    """
    if not mapping:
        yield from chunks
        return
    carry = b""
    residual = 0
    for chunk in chunks:
        buf = carry + chunk
        cut = _emit_upto(buf)
        carry = buf[cut:]
        if cut:
            out = detokenize_bytes(buf[:cut], mapping)
            residual += count_residuals(out)
            yield out
    if carry:
        out = detokenize_bytes(carry, mapping)
        residual += count_residuals(out)
        yield out
    if residual and on_residual:
        on_residual(residual)


def detokenize_obj(obj, mapping: dict[str, str]):
    """detokenize every string in a response payload, whatever shape it is. Structure is
    untouched: only string leaves change, and a token cannot collide with a key name."""
    if not mapping:
        return obj
    if isinstance(obj, str):
        return _detokenize_str(obj, mapping)
    if isinstance(obj, list):
        return [detokenize_obj(x, mapping) for x in obj]
    if isinstance(obj, dict):
        return {k: detokenize_obj(v, mapping) for k, v in obj.items()}
    return obj


def _detokenize_str(text: str, mapping: dict[str, str]) -> str:
    """detokenize one string leaf, keeping a JSON-encoded string valid JSON.

    Tool-call `arguments` arrive as JSON text inside the reply (OpenAI chat and Responses
    both do this). A plain substitution drops the original value in raw, and a value with a
    quote, a backslash or a line break (a custom pattern, or an Aadhaar number grouped
    across lines) would then break the JSON the client is about to parse. When the
    substitution does that to text that was valid JSON, the text is reversed structurally
    instead: parsed, reversed leaf by leaf, and serialized again, which escapes the values.
    """
    out = detokenize(text, mapping)
    if out == text or text.lstrip()[:1] not in ("{", "["):
        return out
    try:
        json.loads(out)
        return out                      # still valid: keep the model's own formatting
    except ValueError:
        pass
    try:
        parsed = json.loads(text)
    except ValueError:
        return out                      # was never JSON; plain-text reversal is right
    return json.dumps(detokenize_obj(parsed, mapping), ensure_ascii=False)


# Where prompt text actually lives in each provider's request body. In a body of a known
# shape only these are rewritten: walking every string would also hit model names, tool
# schemas and ids. A body of no known shape is walked anyway; see _tokenize_any_shape.
def tokenize_payload(payload: dict, extra_patterns: str = "") -> tuple[dict, dict[str, str]]:
    """A copy of `payload` with prompt text tokenized, plus the map to reverse it.

    Covers OpenAI chat (`messages[].content`), Anthropic (`system` plus messages), the
    Responses API (`instructions` and `input`), and Gemini (`contents[].parts` and
    `systemInstruction` / `system_instruction`). Only string text fields are rewritten.

    Tool traffic is prompt text too and is covered in each shape, because tool inputs and
    outputs carry whatever the tools read (a customer record, a file) and whatever the
    model asked for with them: Anthropic `tool_result` content (a string or nested blocks),
    `tool_use` `input` and plain-text `document` sources; OpenAI chat
    `tool_calls[].function.arguments` (and the legacy `function_call`) beside `role: "tool"`
    content; Responses `function_call` / `custom_tool_call` / `local_shell_call` items and
    every `*_call_output` item; Gemini `functionCall.args` and `functionResponse.response`.
    Only values are rewritten, never tool names, ids or the `tools[]` schemas.

    A body with none of those fields falls back to _tokenize_any_shape, which rewrites
    every string in it. Returning it unchanged would look safe (no tokens out, nothing to
    reverse) but it is the opposite: the values go to the provider in the clear.
    """
    if not isinstance(payload, dict) or not any(k in payload for k in _PROMPT_KEYS):
        return _tokenize_any_shape(payload, extra_patterns)
    mapping: dict[str, str] = {}

    def tok(text: str) -> str:
        return tokenize(text, extra_patterns, mapping)[0]

    def walk(node):
        """Every string value under a structured tool input or output, keys untouched."""
        if isinstance(node, str):
            return tok(node)
        if isinstance(node, list):
            return [walk(x) for x in node]
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        return node

    def do_json_text(text):
        r"""Tool-call `arguments`: a JSON document carried as a string.

        Parsed, walked and serialized again rather than tokenized as raw text. The raw text
        is the ESCAPED form, so detection would run on `\n`, `\"` and `é` instead of
        the values (an Aadhaar number grouped across lines, or anything next to a non-ASCII
        character under ensure_ascii, is missed), and a custom pattern free to match a
        quote or a backslash could cut an escape in half and hand the provider broken JSON.
        On the parsed form detection sees the real values and the serializer escapes
        whatever replaces them, whatever the pattern. A token alone could not break JSON
        (it is PLV_, upper-case letters, digits and underscores), but the raw-text route
        cannot promise the same about the span it replaces. If nothing matched, the
        original text goes out byte for byte. Text that is not valid JSON has no
        structure to break, so it is tokenized as it stands.
        """
        if not isinstance(text, str) or not text:
            return text
        try:
            parsed = json.loads(text)
        except ValueError:
            return tok(text)
        if not isinstance(parsed, (dict, list, str)):
            # A bare number is valid JSON too, and a tool output of just a card number is
            # one. Walking it would skip the number, so it is tokenized as text instead.
            return tok(text)
        new = walk(parsed)
        return text if new == parsed else json.dumps(new, ensure_ascii=False)

    def do_block(b):
        if not isinstance(b, dict):
            return b
        b = dict(b)
        if isinstance(b.get("text"), str):
            b["text"] = tok(b["text"])
        kind = b.get("type")
        if not isinstance(kind, str):
            return b
        # Anthropic tool_result / mcp_tool_result: a string or a list of nested blocks.
        if kind.endswith("tool_result") and "content" in b:
            b["content"] = do_content(b["content"])
        # Anthropic tool_use / server_tool_use / mcp_tool_use: the model's own call,
        # replayed in history. `input` is a parsed object here, not a string.
        if kind.endswith("tool_use") and "input" in b:
            b["input"] = walk(b["input"])
        # A plain-text document is the user's text by another name.
        src = b.get("source")
        if kind == "document" and isinstance(src, dict):
            if src.get("type") == "text" and isinstance(src.get("data"), str):
                b["source"] = {**src, "data": tok(src["data"])}
            elif src.get("type") == "content" and "content" in src:
                b["source"] = {**src, "content": do_content(src["content"])}
        return b

    def do_content(c):
        if isinstance(c, str):
            return tok(c)
        if isinstance(c, list):
            return [do_block(b) for b in c]
        return c

    def do_message(m):
        """An OpenAI chat or Anthropic message: its content, plus OpenAI's tool calls."""
        if not isinstance(m, dict):
            return m
        m = dict(m)
        if "content" in m:
            m["content"] = do_content(m["content"])
        calls = m.get("tool_calls")
        if isinstance(calls, list):
            m["tool_calls"] = [
                ({**tc, "function": {**tc["function"],
                                     "arguments": do_json_text(tc["function"].get("arguments"))}}
                 if isinstance(tc, dict) and isinstance(tc.get("function"), dict)
                 and "arguments" in tc["function"] else tc)
                for tc in calls]
        fc = m.get("function_call")                     # pre-`tools` OpenAI chat
        if isinstance(fc, dict) and "arguments" in fc:
            m["function_call"] = {**fc, "arguments": do_json_text(fc["arguments"])}
        return m

    def do_item(it):
        """A Responses API input item: a message, a tool call, or a tool's output."""
        if not isinstance(it, dict):
            return it
        it = do_message(it)
        kind = it.get("type")
        if not isinstance(kind, str):
            return it
        if kind.endswith("_call"):
            if isinstance(it.get("arguments"), str):        # function_call
                it["arguments"] = do_json_text(it["arguments"])
            if isinstance(it.get("input"), str):            # custom_tool_call
                it["input"] = tok(it["input"])
            act = it.get("action")
            if kind == "local_shell_call" and isinstance(act, dict):
                it["action"] = {**act, **{k: walk(act[k]) for k in ("command", "env")
                                          if k in act}}
        if kind.endswith("_call_output") and "output" in it:
            # Usually a string, and often JSON text a tool returned: that is walked as JSON
            # so the output stays valid. A list is content items, like a message's.
            o = it["output"]
            it["output"] = do_json_text(o) if isinstance(o, str) else do_content(o)
        return it

    out = dict(payload)
    if isinstance(out.get("system"), str):
        out["system"], _ = tokenize(out["system"], extra_patterns, mapping)
    elif isinstance(out.get("system"), list):
        out["system"] = do_content(out["system"])
    msgs = out.get("messages")
    if isinstance(msgs, list):
        out["messages"] = [do_message(m) for m in msgs]

    # OpenAI Responses API (Codex CLI's default): `input` replaces `messages` and is a bare
    # string or a list of typed items; `instructions` is its system prompt.
    if isinstance(out.get("instructions"), str):
        out["instructions"], _ = tokenize(out["instructions"], extra_patterns, mapping)
    inp = out.get("input")
    if isinstance(inp, str):
        out["input"], _ = tokenize(inp, extra_patterns, mapping)
    elif isinstance(inp, list):
        out["input"] = [do_item(it) for it in inp]

    # Gemini: text lives in parts[].text, under contents[] and the system instruction.
    def do_parts(node):
        if not isinstance(node, dict) or not isinstance(node.get("parts"), list):
            return node
        parts = []
        for part in node["parts"]:
            if isinstance(part, dict):
                part = dict(part)
                if isinstance(part.get("text"), str):
                    part["text"] = tok(part["text"])
                # The model's call and the tool's answer, as parsed objects; the REST API
                # takes both spellings. `name` and `id` are left as they are.
                for key, field in (("functionCall", "args"), ("function_call", "args"),
                                   ("functionResponse", "response"),
                                   ("function_response", "response")):
                    fn = part.get(key)
                    if isinstance(fn, dict) and field in fn:
                        part[key] = {**fn, field: walk(fn[field])}
            parts.append(part)
        return {**node, "parts": parts}

    if isinstance(out.get("contents"), list):
        out["contents"] = [do_parts(c) for c in out["contents"]]
    for key in ("systemInstruction", "system_instruction"):
        if isinstance(out.get(key), dict):
            out[key] = do_parts(out[key])
    return out, mapping


_PROMPT_KEYS = ("system", "messages", "instructions", "input", "contents",
                "systemInstruction", "system_instruction")


def _tokenize_any_shape(payload, extra_patterns: str = "") -> tuple[object, dict[str, str]]:
    """Every string value in a body tokenize_payload does not recognize, keys untouched.

    The gateway forwards whatever body it was given, so a shape this module has not been
    taught (a legacy `prompt` completion, a provider field added next month) would
    otherwise reach the provider with its personal data intact. Refusing the request
    instead would break a client that did nothing wrong. Walking every string is what the
    recognized shapes avoid, because it also reaches model names, ids and tool schemas,
    but only a value that matches a personal-data pattern is ever changed, so ordinary
    fields pass through as they were. The top-level `model` is skipped all the same: a
    fine-tuned model id can carry a long digit run that passes Luhn, and rewriting it would
    send the request to a model that does not exist. The reply is reversed whatever its
    shape (detokenize_obj), so the caller still gets the real values back.
    """
    mapping: dict[str, str] = {}

    def walk(node):
        if isinstance(node, str):
            return tokenize(node, extra_patterns, mapping)[0]
        if isinstance(node, list):
            return [walk(x) for x in node]
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        return node

    if isinstance(payload, dict):
        return {k: (v if k == "model" else walk(v)) for k, v in payload.items()}, mapping
    return walk(payload), mapping
