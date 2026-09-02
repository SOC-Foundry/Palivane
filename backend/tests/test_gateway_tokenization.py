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
