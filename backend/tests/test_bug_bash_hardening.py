"""Regression tests for the bug-bash hardening pass.

Each test pins one fix so it can't silently regress:
- gateway output-token clamp + daily gateway quota (cost-amplification backstops)
- streamed request-body cap (not just the Content-Length header)
- JWT issuer binding (enforced only when the token carries `iss`)
- encryption KDF upgrade stays backward-compatible (legacy ciphertext still decrypts)
- discovery-ingest string fields are length-bounded
"""

from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from app import gateway, metering, security
from app.gateway import _clamp_output_tokens

BENIGN = {"model": "gpt-4o", "messages": [{"role": "user", "content": "Summarize this."}]}


# --- gateway output-token clamp -------------------------------------------------------

def test_clamp_caps_openai_and_anthropic_max_tokens(monkeypatch):
    monkeypatch.setattr(gateway.settings, "gateway_max_output_tokens", 100)
    assert _clamp_output_tokens({"max_tokens": 999})["max_tokens"] == 100
    assert _clamp_output_tokens({"max_output_tokens": 999})["max_output_tokens"] == 100
    assert _clamp_output_tokens({"max_completion_tokens": 999})["max_completion_tokens"] == 100


def test_clamp_caps_gemini_generation_config(monkeypatch):
    monkeypatch.setattr(gateway.settings, "gateway_max_output_tokens", 100)
    assert _clamp_output_tokens({"generationConfig": {"maxOutputTokens": 999}})["generationConfig"]["maxOutputTokens"] == 100
    # Gemini also accepts a numeric string.
    assert _clamp_output_tokens({"generationConfig": {"maxOutputTokens": "999"}})["generationConfig"]["maxOutputTokens"] == "100"


def test_clamp_leaves_values_under_the_cap_and_is_noop_when_disabled(monkeypatch):
    monkeypatch.setattr(gateway.settings, "gateway_max_output_tokens", 100)
    assert _clamp_output_tokens({"max_tokens": 50})["max_tokens"] == 50
    monkeypatch.setattr(gateway.settings, "gateway_max_output_tokens", 0)
    assert _clamp_output_tokens({"max_tokens": 999})["max_tokens"] == 999


# --- daily gateway quota --------------------------------------------------------------

def test_daily_gateway_quota_blocks_when_exceeded(client, monkeypatch):
    # Benign traffic returns 200 (stub, no upstream), so anything blocking is the quota.
    monkeypatch.setattr(gateway.settings, "gateway_enforce", False)
    monkeypatch.setattr(gateway.settings, "gateway_rate_limit", 0)     # isolate from minute limit
    monkeypatch.setattr(metering.settings, "quota_gateway_per_day", 2)
    codes = [client.post("/v1/chat/completions", json=BENIGN).status_code for _ in range(3)]
    assert codes[:2] == [200, 200]
    assert codes[2] == 429


# --- streamed request-body cap (ASGI middleware) --------------------------------------

def _drive(chunks, cap, method="POST", content_length=None):
    """Run the body-size middleware over a fake ASGI request whose body arrives as `chunks`
    with NO Content-Length (the chunked-transfer case the header check can't see)."""
    from app.main import _BodySizeLimitMiddleware

    async def inner(scope, receive, send):
        body = b""
        while True:
            m = await receive()
            if m["type"] != "http.request":
                break
            body += m.get("body", b"")
            if not m.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body})

    headers = [(b"content-length", str(content_length).encode())] if content_length else []
    scope = {"type": "http", "method": method, "headers": headers}
    inbox = [{"type": "http.request", "body": c, "more_body": i < len(chunks) - 1}
             for i, c in enumerate(chunks)]
    inbox.append({"type": "http.disconnect"})
    it = iter(inbox)
    sent = []

    async def receive():
        return next(it)

    async def send(msg):
        sent.append(msg)

    asyncio.run(_BodySizeLimitMiddleware(inner, max_bytes=cap)(scope, receive, send))
    return sent[0]["status"], b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")


def test_chunked_body_over_cap_is_rejected_without_content_length():
    status, _ = _drive([b"x" * 6, b"y" * 6], cap=10)   # 12 bytes, no Content-Length
    assert status == 413


def test_body_under_cap_passes_through_and_is_replayed():
    status, echoed = _drive([b"hello ", b"world"], cap=100)
    assert status == 200 and echoed == b"hello world"


def test_get_requests_are_not_buffered():
    status, _ = _drive([], cap=10, method="GET")
    assert status == 200


# --- JWT issuer binding ---------------------------------------------------------------

def test_token_carries_issuer_and_wrong_issuer_is_rejected(monkeypatch):
    monkeypatch.setattr(security.settings, "jwt_iss", "https://app.example.com")
    tok = security.create_token({"sub": "1"})
    assert security.decode_token(tok)["iss"] == "https://app.example.com"
    # A token minted under a different issuer must not verify here.
    monkeypatch.setattr(security.settings, "jwt_iss", "https://evil.example.com")
    other = security.create_token({"sub": "1"})
    monkeypatch.setattr(security.settings, "jwt_iss", "https://app.example.com")
    with pytest.raises(security.TokenError):
        security.decode_token(other)


def test_legacy_token_without_issuer_still_verifies(monkeypatch):
    monkeypatch.setattr(security.settings, "jwt_iss", "")          # mint before iss existed
    legacy = security.create_token({"sub": "1"})
    assert "iss" not in security.decode_token(legacy)
    monkeypatch.setattr(security.settings, "jwt_iss", "https://app.example.com")
    assert security.decode_token(legacy)["sub"] == "1"            # grace: no forced logout


# --- encryption KDF upgrade is backward-compatible ------------------------------------

def test_new_encryption_round_trips():
    from app import crypto
    assert crypto.decrypt(crypto.encrypt("sk-secret-value")) == "sk-secret-value"


def test_legacy_sha256_ciphertext_still_decrypts():
    """Secrets written before the HKDF upgrade must keep opening."""
    import base64
    import hashlib

    from cryptography.fernet import Fernet

    from app import crypto
    secret = crypto._secret_bytes()
    legacy = Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret).digest()))
    old_ciphertext = legacy.encrypt(b"legacy-provider-key").decode()
    assert crypto.decrypt(old_ciphertext) == "legacy-provider-key"


# --- discovery-ingest field length caps -----------------------------------------------

def test_discovery_event_rejects_oversized_strings():
    from app.schemas import DiscoveryEvent
    DiscoveryEvent(destination="https://ok.example.com")          # fine
    with pytest.raises(ValidationError):
        DiscoveryEvent(destination="x" * 5000)


def test_oauth_grant_rejects_oversized_strings():
    from app.schemas import OAuthGrant
    with pytest.raises(ValidationError):
        OAuthGrant(app_name="a" * 1000)
