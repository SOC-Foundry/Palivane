"""Gateway tokenization: the provider never sees the real value, the client still does.

The security claim is narrow and worth pinning precisely: detection must run on the
plaintext, the upstream must receive tokens, and the caller must get their data back.
"""

from __future__ import annotations

import re

from app.tokenization import (TOKEN_RE, detokenize, detokenize_obj, tokenize,
                              tokenize_payload)

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


def test_unknown_payload_shapes_fail_safe():
    """No tokens out means nothing to reverse, which is the safe direction to fail."""
    payload = {"prompt": f"SSN {SSN}"}          # neither messages nor system
    out, m = tokenize_payload(payload)
    assert m == {} and out == payload


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
