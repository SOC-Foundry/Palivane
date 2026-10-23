"""Gateway tokenization: the provider never sees the real value, the client still does.

The security claim is narrow and worth pinning precisely: detection must run on the
plaintext, the upstream must receive tokens, and the caller must get their data back.
"""

from __future__ import annotations

import json
import re

from app.tokenization import (MAX_CHARS, OVERLAP, TOKEN_RE, detokenize, detokenize_obj,
                              tokenize, tokenize_payload)

SSN = "123-45-6789"
CARD = "4539578763621486"          # Luhn-valid and not one of the known test cards


def test_round_trips():
    text = f"Reformat SSN {SSN} on card {CARD}."
    out, m = tokenize(text)
    assert SSN not in out and CARD not in out
    assert detokenize(out, m) == text


def test_one_person_gets_one_token_across_several_messages():
    """Split across messages, the same value must still read as the same person."""
    payload = {"messages": [{"role": "user", "content": f"about {SSN}"},
                            {"role": "user", "content": f"and again {SSN}"}]}
    out, m = tokenize_payload(payload)
    tokens = [TOKEN_RE.search(x["content"]).group(0) for x in out["messages"]]
    assert tokens[0] == tokens[1] and len(m) == 1


def test_only_prompt_text_is_rewritten():
    """Walking every string would also hit model names, ids and tool schemas."""
    payload = {"model": "gpt-4o", "temperature": 0.2,
               "messages": [{"role": "user", "content": f"SSN {SSN}"}]}
    out, _ = tokenize_payload(payload)
    assert out["model"] == "gpt-4o" and out["temperature"] == 0.2


def test_typed_content_blocks_are_handled():
    payload = {"messages": [{"role": "user", "content": [
        {"type": "text", "text": f"SSN {SSN}"}, {"type": "image", "source": {"x": 1}}]}]}
    out, m = tokenize_payload(payload)
    assert SSN not in out["messages"][0]["content"][0]["text"]
    assert out["messages"][0]["content"][1] == {"type": "image", "source": {"x": 1}}
    assert len(m) == 1


def test_anthropic_system_block_is_covered():
    payload = {"system": f"The customer SSN is {SSN}", "messages": []}
    out, m = tokenize_payload(payload)
    assert SSN not in out["system"] and len(m) == 1


def test_the_original_payload_is_not_mutated():
    """The caller keeps the plaintext for scoring and logging; we hand back a copy."""
    payload = {"messages": [{"role": "user", "content": f"SSN {SSN}"}]}
    tokenize_payload(payload)
    assert payload["messages"][0]["content"] == f"SSN {SSN}"


def test_a_card_match_does_not_swallow_the_following_word():
    """The candidate regex can match a trailing separator; substituting that verbatim
    welds the token to the next word."""
    out, m = tokenize(f"charge card {CARD} today")
    assert out.endswith(" today") and "today" not in "".join(m.values())


def test_known_test_cards_are_left_alone():
    out, m = tokenize("card 4242424242424242")
    assert m == {} and "4242424242424242" in out


def test_response_is_reversed_through_any_shape():
    _, m = tokenize(f"SSN {SSN}")
    tok = next(iter(m))
    resp = {"choices": [{"message": {"content": f"Record {tok} is fine.",
                                     "role": "assistant"}}], "id": "abc"}
    out = detokenize_obj(resp, m)
    assert out["choices"][0]["message"]["content"] == f"Record {SSN} is fine."
    assert out["id"] == "abc" and out["choices"][0]["message"]["role"] == "assistant"


def test_a_token_the_model_invented_is_left_alone():
    _, m = tokenize(f"SSN {SSN}")
    assert detokenize("see PLV_USSN_ABCDEF", m) == "see PLV_USSN_ABCDEF"


def test_an_unknown_payload_shape_is_tokenized_anyway():
    """Returning an unrecognized body unchanged sends its values to the provider. Every
    string in it is tokenized instead, and the reply still reverses."""
    payload = {"model": "ft:gpt-4o:acme:4539578763621486", "max_tokens": 16,
               "prompt": f"SSN {SSN}",          # neither messages nor system
               "metadata": {"notes": [f"card {CARD}", "plain"]}}
    out, m = tokenize_payload(payload)
    assert SSN not in json.dumps(out) and CARD not in json.dumps(out["metadata"])
    # Keys, non-string values and the model id are left as they were.
    assert out["model"] == payload["model"] and out["max_tokens"] == 16
    assert out["metadata"]["notes"][1] == "plain"
    assert detokenize_obj(out, m) == payload
    assert payload["prompt"] == f"SSN {SSN}"     # the original is not mutated


# --- prompts over MAX_CHARS ---------------------------------------------------------------
# One detector sweep covers MAX_CHARS. A longer prompt used to come back untouched, which
# sent every value in it to the provider; it is now swept in overlapping windows.

def _filler(n: int) -> str:
    return ("lorem ipsum dolor sit amet " * (n // 27 + 1))[:n]


def test_a_prompt_over_the_cap_is_tokenized_and_reverses():
    text = _filler(MAX_CHARS + 50_000) + f" SSN {SSN} at the very end."
    out, m = tokenize(text)
    assert SSN not in out and TOKEN_RE.search(out)
    assert detokenize(out, m) == text


def test_a_value_straddling_a_window_boundary_is_one_token():
    """A value cut by a window edge must be found whole (by the next window, thanks to the
    overlap), not missed and not split into two tokens. The first window ends at
    MAX_CHARS; the second starts OVERLAP before it."""
    text = _filler(MAX_CHARS - 8) + " " + f"{CARD} then SSN {SSN} " + _filler(MAX_CHARS) + f" again {CARD}"
    # CARD spans MAX_CHARS - 7 .. MAX_CHARS + 9: across the end of the first window.
    assert text.index(CARD) < MAX_CHARS < text.index(CARD) + len(CARD)
    out, m = tokenize(text)
    assert CARD not in out and SSN not in out
    card_tokens = [t for t, v in m.items() if v == CARD]
    assert len(card_tokens) == 1 and out.count(card_tokens[0]) == 2
    # No fragment of the card was minted as a value of its own and left half the digits.
    assert not any(v != CARD and v in CARD for v in m.values())
    assert not re.search(r"\d{4}", re.sub(TOKEN_RE.pattern, "", out))
    assert detokenize(out, m) == text


def test_a_value_straddling_the_overlap_start_is_one_token():
    """The other edge: a value across the start of the second window sits wholly inside
    the first, and the second sees only its tail."""
    start2 = MAX_CHARS - OVERLAP
    text = _filler(start2 - 5) + " " + CARD + " " + _filler(MAX_CHARS)
    assert text.index(CARD) < start2 < text.index(CARD) + len(CARD)
    out, m = tokenize(text)
    assert CARD not in out and list(m.values()) == [CARD]
    assert detokenize(out, m) == text


def test_a_long_prompt_shares_tokens_with_the_rest_of_the_payload():
    payload = {"system": f"Customer SSN {SSN}",
               "messages": [{"role": "user",
                             "content": _filler(MAX_CHARS * 2) + f" SSN {SSN}"}]}
    out, m = tokenize_payload(payload)
    tok = TOKEN_RE.search(out["system"]).group(0)
    assert out["messages"][0]["content"].endswith(f" SSN {tok}") and len(m) == 1


def test_off_by_default():
    from app.config import settings
    assert settings.gateway_tokenize is False


# --- end to end through the gateway ---------------------------------------------------
# The claim this feature makes is a three-part one, and only an end-to-end test pins all
# three at once: detection sees the plaintext, the PROVIDER receives tokens, and the
# caller gets their own data back.

def test_provider_gets_tokens_and_the_caller_gets_plaintext(client, monkeypatch):
    from app import gateway
    monkeypatch.setattr(gateway.settings, "gateway_tokenize", True)
    monkeypatch.setattr(gateway.settings, "gateway_enforce", False)
    # An org that tokenizes has chosen substitution over refusal for these categories, so
    # the block-the-certain default is off: otherwise a confirmed PII leak is stopped
    # before tokenization can make it safe to send. See _tokenize_out.
    monkeypatch.setattr(gateway.settings, "gateway_enforce_secrets", False)
    monkeypatch.setattr(gateway, "resolve_upstream", lambda *a, **k: ("https://up", "key"))

    seen = {}

    def fake_post(path, payload, request, base, key):
        seen["payload"] = payload
        # Echo the token back the way a model would.
        text = payload["messages"][0]["content"]
        return 200, {"content": [{"type": "text", "text": f"Understood: {text}"}],
                     "model": "claude-3", "role": "assistant"}

    monkeypatch.setattr(gateway, "_post_upstream_anthropic", fake_post)
    r = client.post("/v1/messages", json={
        "model": "claude-3", "max_tokens": 16,
        "messages": [{"role": "user", "content": f"Reformat this record: SSN {SSN}"}]})
    assert r.status_code == 200

    # 1. the provider never saw the real value
    sent = seen["payload"]["messages"][0]["content"]
    assert SSN not in sent and TOKEN_RE.search(sent)

    # 2. the caller got it back
    out = r.json()["content"][0]["text"]
    assert SSN in out and not TOKEN_RE.search(out)


def test_an_unrecognized_shape_does_not_reach_the_provider_in_the_clear(client, monkeypatch):
    """The legacy Anthropic text-completion body (`prompt`, no `messages`) is a shape
    tokenize_payload has no case for. It is still forwarded, so it must still be tokenized,
    and the caller must still get the value back."""
    from app import gateway
    monkeypatch.setattr(gateway.settings, "gateway_tokenize", True)
    monkeypatch.setattr(gateway.settings, "gateway_enforce", False)
    monkeypatch.setattr(gateway.settings, "gateway_enforce_secrets", False)
    monkeypatch.setattr(gateway, "resolve_upstream", lambda *a, **k: ("https://up", "key"))
    seen = {}

    def fake_post(path, payload, request, base, key):
        seen["payload"] = payload
        return 200, {"completion": f"Understood: {payload['prompt']}", "model": "claude-2"}

    monkeypatch.setattr(gateway, "_post_upstream_anthropic", fake_post)
    r = client.post("/v1/messages", json={
        "model": "claude-2", "max_tokens_to_sample": 16,
        "prompt": f"\n\nHuman: Reformat SSN {SSN} and card {CARD}\n\nAssistant:"})
    assert r.status_code == 200
    sent = json.dumps(seen["payload"])
    assert SSN not in sent and CARD not in sent and TOKEN_RE.search(sent)
    assert seen["payload"]["model"] == "claude-2"
    out = r.json()["completion"]
    assert SSN in out and CARD in out and not TOKEN_RE.search(out)


def test_scoring_runs_on_the_plaintext_not_the_tokens(client, monkeypatch):
    """Tokenizing before scoring would make every verdict a verdict about placeholders."""
    from app import gateway
    monkeypatch.setattr(gateway.settings, "gateway_tokenize", True)
    monkeypatch.setattr(gateway, "resolve_upstream", lambda *a, **k: ("https://up", "key"))
    monkeypatch.setattr(gateway, "_post_upstream_anthropic",
                        lambda *a, **k: (200, {"content": [], "role": "assistant"}))
    scored = {}
    real_capture = gateway._capture

    def spy(prompt, *a, **k):
        scored["prompt"] = prompt
        return real_capture(prompt, *a, **k)

    monkeypatch.setattr(gateway, "_capture", spy)
    client.post("/v1/messages", json={
        "model": "claude-3", "max_tokens": 16,
        "messages": [{"role": "user", "content": f"SSN {SSN}"}]})
    assert SSN in scored["prompt"] and not TOKEN_RE.search(scored["prompt"])


def test_disabled_means_the_payload_is_untouched(client, monkeypatch):
    from app import gateway
    monkeypatch.setattr(gateway.settings, "gateway_tokenize", False)
    monkeypatch.setattr(gateway.settings, "gateway_enforce_secrets", False)
    monkeypatch.setattr(gateway, "resolve_upstream", lambda *a, **k: ("https://up", "key"))
    seen = {}

    def fake_post(path, payload, request, base, key):
        seen["payload"] = payload
        return 200, {"content": [], "role": "assistant"}

    monkeypatch.setattr(gateway, "_post_upstream_anthropic", fake_post)
    client.post("/v1/messages", json={
        "model": "claude-3", "max_tokens": 16,
        "messages": [{"role": "user", "content": f"SSN {SSN}"}]})
    assert seen["payload"]["messages"][0]["content"] == f"SSN {SSN}"


# --- streaming --------------------------------------------------------------------------
# Claude Code, Cursor, Codex and Gemini CLI all stream by default, so tokenization that
# only covers the buffered path does not apply to the tools people actually use.

def test_a_token_split_across_chunks_still_reverses():
    """The reason streaming needs its own path: a chunk boundary can fall anywhere."""
    from app.tokenization import detokenize_stream
    _, m = tokenize(f"SSN {SSN}")
    tok = next(iter(m))
    full = f'data: {{"text":"for {tok} ok, help"}}\n\n'.encode()
    want = full.replace(tok.encode(), SSN.encode())
    for size in (1, 2, 3, 5, 7, 11, 23, 64, 4096):
        chunks = [full[i:i + size] for i in range(0, len(full), size)]
        assert b"".join(detokenize_stream(iter(chunks), m)) == want, f"chunk size {size}"


def test_streaming_holds_back_only_a_partial_token():
    """It must stay a stream: holding the whole response would defeat the purpose."""
    from app.tokenization import TOKEN_MAX, detokenize_stream
    _, m = tokenize(f"SSN {SSN}")
    big = b"x" * 10_000
    first = next(iter(detokenize_stream(iter([big]), m)))
    assert len(first) >= len(big) - TOKEN_MAX


def test_streaming_with_no_tokens_is_a_passthrough():
    from app.tokenization import detokenize_stream
    chunks = [b"data: hello\n", b"data: world\n"]
    assert list(detokenize_stream(iter(chunks), {})) == chunks


def test_text_that_merely_starts_like_a_token_survives():
    """A stray "P" at a chunk edge is held back briefly and must still come out intact."""
    from app.tokenization import detokenize_stream
    _, m = tokenize(f"SSN {SSN}")
    full = b"PLEASE help P PL PLV PLV_ and PLV_NOPE_ZZZZZZ done"
    for size in (1, 4, 9):
        chunks = [full[i:i + size] for i in range(0, len(full), size)]
        assert b"".join(detokenize_stream(iter(chunks), m)) == full


def test_streaming_provider_gets_tokens_and_client_gets_plaintext(client, monkeypatch):
    """End to end on the monitor-mode streaming path, which is what a CLI actually hits."""
    from app import gateway
    monkeypatch.setattr(gateway.settings, "gateway_tokenize", True)
    monkeypatch.setattr(gateway.settings, "gateway_enforce", False)
    monkeypatch.setattr(gateway.settings, "gateway_enforce_secrets", False)
    monkeypatch.setattr(gateway.settings, "gateway_scan_responses", False)
    monkeypatch.setattr(gateway, "resolve_upstream", lambda *a, **k: ("https://up", "key"))
    seen = {}

    def fake_passthrough(url, payload, headers, model="", tool="", principal=None, tokens=None):
        from fastapi.responses import StreamingResponse
        from app.tokenization import detokenize_stream
        seen["payload"] = payload
        echo = payload["messages"][0]["content"].encode()
        chunks = [echo[i:i + 3] for i in range(0, len(echo), 3)]   # awkward on purpose
        return StreamingResponse(detokenize_stream(iter(chunks), tokens or {}),
                                 media_type="text/event-stream")

    monkeypatch.setattr(gateway, "_passthrough_stream", fake_passthrough)
    r = client.post("/v1/messages", json={
        "model": "claude-3", "max_tokens": 16, "stream": True,
        "messages": [{"role": "user", "content": f"Reformat SSN {SSN}"}]})
    assert r.status_code == 200
    assert SSN not in seen["payload"]["messages"][0]["content"]        # provider
    assert SSN in r.text and not TOKEN_RE.search(r.text)               # client


# --- the other two providers -------------------------------------------------------------
# Codex CLI defaults to the Responses API and Gemini CLI to generateContent, so covering
# only the chat/messages shapes left the two most likely CLI clients untokenized.

def test_responses_api_string_input():
    payload = {"model": "gpt-5", "input": f"Reformat SSN {SSN}"}
    out, m = tokenize_payload(payload)
    assert SSN not in out["input"] and len(m) == 1


def test_responses_api_item_list_and_instructions_share_one_token():
    """`instructions` is the Responses system prompt; the same person in both must read as
    the same person to the model."""
    payload = {"input": [{"role": "user",
                          "content": [{"type": "input_text", "text": f"SSN {SSN}"}]}],
               "instructions": f"The customer is {SSN}"}
    out, m = tokenize_payload(payload)
    assert len(m) == 1
    tok = next(iter(m))
    assert tok in out["input"][0]["content"][0]["text"] and tok in out["instructions"]


def test_gemini_parts_and_system_instruction():
    payload = {"contents": [{"role": "user", "parts": [{"text": f"SSN {SSN}"},
                                                       {"inlineData": {"mimeType": "image/png"}}]}],
               "systemInstruction": {"parts": [{"text": f"about {SSN}"}]}}
    out, m = tokenize_payload(payload)
    assert len(m) == 1
    assert SSN not in out["contents"][0]["parts"][0]["text"]
    assert SSN not in out["systemInstruction"]["parts"][0]["text"]
    # a non-text part is structure, not prompt, and must survive untouched
    assert out["contents"][0]["parts"][1] == {"inlineData": {"mimeType": "image/png"}}


def test_gemini_snake_case_system_instruction():
    """The REST API accepts both spellings; the SDK sends one and raw callers the other."""
    out, m = tokenize_payload({"system_instruction": {"parts": [{"text": f"SSN {SSN}"}]}})
    assert len(m) == 1 and SSN not in out["system_instruction"]["parts"][0]["text"]


def test_gemini_end_to_end(client, monkeypatch):
    from app import gateway
    monkeypatch.setattr(gateway.settings, "gateway_tokenize", True)
    monkeypatch.setattr(gateway.settings, "gateway_enforce_secrets", False)
    monkeypatch.setattr(gateway.settings, "gateway_scan_responses", False)
    monkeypatch.setattr(gateway, "resolve_upstream", lambda *a, **k: ("https://up", "key"))
    seen = {}

    def fake_forward(model, method, payload, request, base, key):
        from fastapi.responses import Response as R
        seen["payload"] = payload
        echoed = payload["contents"][0]["parts"][0]["text"]
        import json as _j
        return R(content=_j.dumps({"candidates": [{"content": {"parts": [{"text": echoed}]}}]}).encode(),
                 status_code=200, media_type="application/json")

    monkeypatch.setattr(gateway, "_forward_gemini", fake_forward)
    r = client.post("/v1beta/models/gemini-2.5-pro:generateContent", json={
        "contents": [{"role": "user", "parts": [{"text": f"Reformat SSN {SSN}"}]}]})
    assert r.status_code == 200
    assert SSN not in seen["payload"]["contents"][0]["parts"][0]["text"]   # provider
    assert SSN in r.text and not TOKEN_RE.search(r.text)                   # client


# --- per-tenant opt-in and the residual counter ------------------------------------------
# GATEWAY_TOKENIZE alone is all tenants or none, which makes a pilot impossible: turning it
# on changes what every customer's provider receives at once.

def test_a_tenant_can_opt_in_while_the_deployment_default_is_off(client, monkeypatch,
                                                                 db_factory):
    from app import gateway
    from app.models import Tenant
    monkeypatch.setattr(gateway.settings, "gateway_tokenize", False)      # deployment: off
    monkeypatch.setattr(gateway.settings, "gateway_enforce_secrets", False)
    monkeypatch.setattr(gateway.settings, "gateway_scan_responses", False)
    monkeypatch.setattr(gateway, "resolve_upstream", lambda *a, **k: ("https://up", "key"))
    db = db_factory()
    db.query(Tenant).filter(Tenant.slug == "acme").first().gateway_tokenize = True
    db.commit(); db.close()

    seen = {}

    def fake_post(path, payload, request, base, key):
        seen["payload"] = payload
        return 200, {"content": [], "role": "assistant"}

    monkeypatch.setattr(gateway, "_post_upstream_anthropic", fake_post)
    client.post("/v1/messages", json={"model": "claude-3", "max_tokens": 8,
                                      "messages": [{"role": "user", "content": f"SSN {SSN}"}]})
    assert SSN not in seen["payload"]["messages"][0]["content"]


def test_a_tenant_can_opt_out_while_the_deployment_default_is_on(client, monkeypatch,
                                                                 db_factory):
    from app import gateway
    from app.models import Tenant
    monkeypatch.setattr(gateway.settings, "gateway_tokenize", True)       # deployment: on
    monkeypatch.setattr(gateway.settings, "gateway_enforce_secrets", False)
    monkeypatch.setattr(gateway, "resolve_upstream", lambda *a, **k: ("https://up", "key"))
    db = db_factory()
    db.query(Tenant).filter(Tenant.slug == "acme").first().gateway_tokenize = False
    db.commit(); db.close()

    seen = {}

    def fake_post(path, payload, request, base, key):
        seen["payload"] = payload
        return 200, {"content": [], "role": "assistant"}

    monkeypatch.setattr(gateway, "_post_upstream_anthropic", fake_post)
    client.post("/v1/messages", json={"model": "claude-3", "max_tokens": 8,
                                      "messages": [{"role": "user", "content": f"SSN {SSN}"}]})
    assert seen["payload"]["messages"][0]["content"] == f"SSN {SSN}"


def test_residuals_catch_a_model_that_mangled_a_token():
    """The one failure no test can reach directly: it depends on real model behaviour. The
    detector is looser than TOKEN_RE on purpose, because a mangled token no longer matches
    the strict pattern and the user is still reading a placeholder."""
    from app.tokenization import count_residuals
    assert count_residuals("all good, 123-45-6789") == 0        # a clean reversal
    assert count_residuals("see PLV-USSN-A7C9D5") == 1          # separators changed
    assert count_residuals("see PLV_USSN_ABCDEF") == 1          # not in our map
    assert count_residuals("PLVDATA is a product name") == 0    # not token-shaped


def test_the_stream_reports_residuals_once_at_the_end():
    from app.tokenization import detokenize_stream, tokenize
    _, m = tokenize(f"SSN {SSN}")
    got = []
    list(detokenize_stream(iter([b"a PLV-USSN-DEAD01 b", b" PLV-PCN-BEEF02"]), m, got.append))
    assert got == [2]


# --- tool traffic inside the recognized shapes -------------------------------------------
# Tool inputs and outputs are prompt text the provider reads like any other: a tool result
# is whatever the tool fetched (a customer record), and the arguments are what the model
# asked for with it. Each shape keeps them in its own field, and each must be tokenized.

RECORD = f"customer SSN {SSN}, card {CARD}"
TOOLS = [{"name": "lookup", "description": f"looks up an SSN such as {SSN}",
          "input_schema": {"type": "object", "properties": {"ssn": {"type": "string"}}}}]


def _no_pii(obj) -> bool:
    s = json.dumps(obj)
    return SSN not in s and CARD not in s


def test_anthropic_tool_result_string_and_nested_blocks():
    payload = {"model": "claude-3", "tools": TOOLS, "messages": [
        {"role": "assistant", "content": [
            {"type": "tool_use", "id": "toolu_1", "name": "lookup", "input": {"ssn": SSN}}]},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_1", "content": RECORD},
            {"type": "tool_result", "tool_use_id": "toolu_2", "content": [
                {"type": "text", "text": f"record: {CARD}"},
                {"type": "image", "source": {"type": "base64", "data": "AAAA"}}]}]}]}
    out, m = tokenize_payload(payload)
    assert _no_pii(out["messages"]) and len(m) == 2
    # one person, one token, across the call, the string result and the nested result
    tok_ssn = next(t for t, v in m.items() if v == SSN)
    assert out["messages"][0]["content"][0]["input"] == {"ssn": tok_ssn}
    assert tok_ssn in out["messages"][1]["content"][0]["content"]
    # ids, names and the tool definitions are not prompt text
    assert out["tools"] == TOOLS
    assert out["messages"][0]["content"][0]["id"] == "toolu_1"
    assert out["messages"][0]["content"][0]["name"] == "lookup"
    assert out["messages"][1]["content"][1]["tool_use_id"] == "toolu_2"
    assert out["messages"][1]["content"][1]["content"][1] == \
        {"type": "image", "source": {"type": "base64", "data": "AAAA"}}
    assert detokenize_obj(out["messages"], m) == payload["messages"]
    assert payload["messages"][1]["content"][0]["content"] == RECORD    # not mutated


def test_anthropic_text_document_is_tokenized():
    payload = {"messages": [{"role": "user", "content": [
        {"type": "document", "source": {"type": "text", "media_type": "text/plain",
                                        "data": RECORD}},
        {"type": "document", "source": {"type": "content",
                                        "content": [{"type": "text", "text": RECORD}]}}]}]}
    out, m = tokenize_payload(payload)
    assert _no_pii(out) and len(m) == 2
    assert detokenize_obj(out, m) == payload


def test_openai_tool_call_arguments_and_tool_message():
    args = json.dumps({"ssn": SSN, "note": f"card\n{CARD}", "n": 3})
    payload = {"model": "gpt-4o",
               "tools": [{"type": "function", "function": {
                   "name": "lookup", "description": f"e.g. {SSN}",
                   "parameters": {"type": "object"}}}],
               "messages": [
                   {"role": "user", "content": "look them up"},
                   {"role": "assistant", "content": None, "tool_calls": [
                       {"id": "call_1", "type": "function",
                        "function": {"name": "lookup", "arguments": args}}]},
                   {"role": "tool", "tool_call_id": "call_1", "content": RECORD},
                   {"role": "assistant", "function_call": {"name": "lookup",
                                                           "arguments": args}}]}
    out, m = tokenize_payload(payload)
    assert _no_pii(out["messages"]) and len(m) == 2
    call = out["messages"][1]["tool_calls"][0]
    assert call["id"] == "call_1" and call["function"]["name"] == "lookup"
    parsed = json.loads(call["function"]["arguments"])            # still valid JSON
    assert parsed["n"] == 3 and TOKEN_RE.fullmatch(parsed["ssn"])
    assert parsed["note"].startswith("card\n")
    assert json.loads(out["messages"][3]["function_call"]["arguments"]) == parsed
    assert out["tools"] == payload["tools"]
    assert out["messages"][2]["tool_call_id"] == "call_1"
    back = detokenize_obj(out, m)
    assert json.loads(back["messages"][1]["tool_calls"][0]["function"]["arguments"]) == \
        json.loads(args)
    assert back["messages"][2]["content"] == RECORD


def test_arguments_without_personal_data_go_out_byte_for_byte():
    args = '{ "city" :"Paris",  "days": 3 }'
    payload = {"messages": [{"role": "assistant", "tool_calls": [
        {"id": "c", "type": "function", "function": {"name": "f", "arguments": args}}]}]}
    out, m = tokenize_payload(payload)
    assert out["messages"][0]["tool_calls"][0]["function"]["arguments"] == args and not m


def test_arguments_that_are_not_json_are_still_tokenized():
    payload = {"messages": [{"role": "assistant", "tool_calls": [
        {"id": "c", "type": "function",
         "function": {"name": "f", "arguments": f'{{"ssn": "{SSN}"'}}]}]}  # truncated
    out, m = tokenize_payload(payload)
    assert _no_pii(out) and len(m) == 1


def test_responses_function_call_and_output_items():
    tools = [{"type": "function", "name": "lookup", "description": f"e.g. {SSN}",
              "parameters": {}}]
    payload = {"model": "gpt-5", "instructions": "be brief", "tools": tools, "input": [
        {"role": "user", "content": [{"type": "input_text", "text": "go"}]},
        {"type": "function_call", "call_id": "call_1", "name": "lookup",
         "arguments": json.dumps({"ssn": SSN})},
        {"type": "function_call_output", "call_id": "call_1",
         "output": json.dumps({"record": RECORD})},
        {"type": "function_call_output", "call_id": "call_2", "output": RECORD},
        {"type": "function_call_output", "call_id": "call_3",
         "output": [{"type": "input_text", "text": RECORD}]},
        {"type": "custom_tool_call", "call_id": "call_4", "name": "patch",
         "input": f"set ssn {SSN}"},
        {"type": "custom_tool_call_output", "call_id": "call_4", "output": RECORD},
        {"type": "local_shell_call", "call_id": "call_5", "id": "ls_1",
         "action": {"type": "exec", "command": ["grep", SSN, "db.csv"]}},
        {"type": "local_shell_call_output", "call_id": "call_5", "output": CARD}]}
    out, m = tokenize_payload(payload)
    assert _no_pii(out["input"]) and len(m) == 2
    items = out["input"]
    assert json.loads(items[1]["arguments"])["ssn"] in m
    assert TOKEN_RE.search(json.loads(items[2]["output"])["record"])
    assert [it.get("call_id") for it in items[1:]] == [
        "call_1", "call_1", "call_2", "call_3", "call_4", "call_4", "call_5", "call_5"]
    assert items[1]["name"] == "lookup" and items[7]["action"]["command"][0] == "grep"
    assert out["tools"] == tools
    assert detokenize_obj(out, m) == payload


def test_gemini_function_call_and_response_parts():
    tools = [{"functionDeclarations": [{"name": "lookup", "description": f"e.g. {SSN}"}]}]
    payload = {"tools": tools, "contents": [
        {"role": "model", "parts": [{"functionCall": {"name": "lookup", "id": "fc1",
                                                      "args": {"ssn": SSN}}}]},
        {"role": "user", "parts": [{"functionResponse": {"name": "lookup", "id": "fc1",
                                                         "response": {"record": RECORD}}}]},
        {"role": "user", "parts": [{"function_response": {"name": "lookup",
                                                          "response": {"r": [CARD]}}}]}]}
    out, m = tokenize_payload(payload)
    assert _no_pii(out["contents"]) and len(m) == 2
    fc = out["contents"][0]["parts"][0]["functionCall"]
    assert fc["name"] == "lookup" and fc["id"] == "fc1" and fc["args"]["ssn"] in m
    assert out["tools"] == tools
    assert detokenize_obj(out, m) == payload


def test_a_token_in_generated_arguments_reverses_to_valid_json():
    """The model writes a token into a tool call's JSON-string arguments. Reversing must
    leave valid JSON even when the real value needs escaping there (a quote, a newline)."""
    m = {"PLV_XY_ABCDEF": 'say "hi"\nnow', "PLV_USSN_123456": SSN}
    reply = {"choices": [{"message": {"tool_calls": [{"function": {
        "name": "f", "arguments": '{"a": "PLV_XY_ABCDEF", "b": "PLV_USSN_123456"}'}}]}}],
        "output": [{"type": "function_call", "arguments": '{"b":"PLV_USSN_123456"}'}]}
    back = detokenize_obj(reply, m)
    args = json.loads(back["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"])
    assert args == {"a": 'say "hi"\nnow', "b": SSN}
    # nothing needed escaping here, so the model's own formatting is kept
    assert back["output"][0]["arguments"] == '{"b":"' + SSN + '"}'


def test_tokens_cannot_break_json():
    """Tokens are spliced into JSON text both ways; nothing in one needs escaping."""
    for _ in range(50):
        _, m = tokenize(f"SSN {SSN} card {CARD} IBAN GB82WEST12345698765432")
        assert len(m) == 3
        for t in m:
            assert re.fullmatch(r"PLV_[A-Z0-9]+_[0-9A-F]{6}", t)
            assert json.dumps(t) == f'"{t}"'


def _tokenizing(monkeypatch):
    from app import gateway
    monkeypatch.setattr(gateway.settings, "gateway_tokenize", True)
    monkeypatch.setattr(gateway.settings, "gateway_enforce", False)
    monkeypatch.setattr(gateway.settings, "gateway_enforce_secrets", False)
    monkeypatch.setattr(gateway.settings, "gateway_scan_responses", False)
    monkeypatch.setattr(gateway, "resolve_upstream", lambda *a, **k: ("https://up", "key"))
    return gateway


def _openai_stub(monkeypatch, gateway, seen, reply):
    """Stand in for the OpenAI-shape upstream: record the body, answer with reply(body)."""
    class _R:
        status_code = 200

        def json(self):
            return reply(seen["payload"])

    class _C:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, json=None, headers=None):
            seen["payload"] = json
            return _R()

    monkeypatch.setattr(gateway, "safe_client", lambda **k: _C())


def test_anthropic_tool_result_end_to_end(client, monkeypatch):
    gateway = _tokenizing(monkeypatch)
    seen = {}

    def fake_post(path, payload, request, base, key):
        seen["payload"] = payload
        # The model calls the next tool with the value it read from the result.
        tok = TOKEN_RE.search(payload["messages"][2]["content"][0]["content"][0]["text"])
        return 200, {"role": "assistant", "model": "claude-3", "content": [
            {"type": "tool_use", "id": "toolu_2", "name": "lookup",
             "input": {"ssn": tok.group(0)}}]}

    monkeypatch.setattr(gateway, "_post_upstream_anthropic", fake_post)
    r = client.post("/v1/messages", json={
        "model": "claude-3", "max_tokens": 16, "tools": TOOLS, "messages": [
            {"role": "user", "content": "find the customer"},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "toolu_1", "name": "lookup", "input": {"q": "x"}}]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_1", "content": [
                    {"type": "text", "text": RECORD}]}]}]})
    assert r.status_code == 200
    assert _no_pii(seen["payload"]["messages"])
    assert seen["payload"]["tools"] == TOOLS            # the schema keeps its example SSN
    assert r.json()["content"][0]["input"] == {"ssn": SSN}


def test_openai_tool_calls_end_to_end(client, monkeypatch):
    gateway = _tokenizing(monkeypatch)
    seen = {}

    def reply(sent):
        tok = TOKEN_RE.search(sent["messages"][2]["content"]).group(0)
        return {"choices": [{"index": 0, "message": {"role": "assistant", "tool_calls": [
            {"id": "call_2", "type": "function",
             "function": {"name": "charge", "arguments": json.dumps({"card": tok})}}]}}]}

    _openai_stub(monkeypatch, gateway, seen, reply)
    r = client.post("/v1/chat/completions", json={"model": "gpt-4o", "messages": [
        {"role": "user", "content": "charge them"},
        {"role": "assistant", "tool_calls": [{"id": "call_1", "type": "function", "function": {
            "name": "lookup", "arguments": json.dumps({"ssn": SSN})}}]},
        {"role": "tool", "tool_call_id": "call_1", "content": f"card {CARD}"}]})
    assert r.status_code == 200
    assert _no_pii(seen["payload"])
    json.loads(seen["payload"]["messages"][1]["tool_calls"][0]["function"]["arguments"])
    args = r.json()["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    assert json.loads(args) == {"card": CARD}


def test_responses_function_call_output_end_to_end(client, monkeypatch):
    gateway = _tokenizing(monkeypatch)
    seen = {}

    def reply(sent):
        tok = TOKEN_RE.search(sent["input"][2]["output"]).group(0)
        return {"output": [{"type": "function_call", "call_id": "call_2", "name": "charge",
                            "arguments": json.dumps({"card": tok})}]}

    _openai_stub(monkeypatch, gateway, seen, reply)
    r = client.post("/v1/responses", json={"model": "gpt-5", "input": [
        {"role": "user", "content": "charge them"},
        {"type": "function_call", "call_id": "call_1", "name": "lookup",
         "arguments": json.dumps({"ssn": SSN})},
        {"type": "function_call_output", "call_id": "call_1", "output": f"card {CARD}"}]})
    assert r.status_code == 200
    assert _no_pii(seen["payload"])
    assert json.loads(r.json()["output"][0]["arguments"]) == {"card": CARD}


def test_gemini_function_response_end_to_end(client, monkeypatch):
    gateway = _tokenizing(monkeypatch)
    seen = {}

    def fake_forward(model, method, payload, request, base, key):
        from fastapi.responses import Response as R
        seen["payload"] = payload
        tok = payload["contents"][1]["parts"][0]["functionResponse"]["response"]["card"]
        body = {"candidates": [{"content": {"parts": [
            {"functionCall": {"name": "charge", "args": {"card": tok}}}]}}]}
        return R(content=json.dumps(body).encode(), status_code=200,
                 media_type="application/json")

    monkeypatch.setattr(gateway, "_forward_gemini", fake_forward)
    r = client.post("/v1beta/models/gemini-2.5-pro:generateContent", json={"contents": [
        {"role": "model", "parts": [{"functionCall": {"name": "lookup", "args": {"ssn": SSN}}}]},
        {"role": "user", "parts": [{"functionResponse": {"name": "lookup",
                                                         "response": {"card": CARD}}}]}]})
    assert r.status_code == 200
    assert _no_pii(seen["payload"])
    assert r.json()["candidates"][0]["content"]["parts"][0]["functionCall"]["args"] == \
        {"card": CARD}
