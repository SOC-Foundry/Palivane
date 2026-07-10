"""Platform hardening: input/DoS bounds, write-only secrets, SSRF guards, constant-time MFA."""

from __future__ import annotations

import app.main as main
from app import oidc, totp
from app.schemas import MAX_CONTENT


def test_content_length_cap_413(client, monkeypatch):
    monkeypatch.setattr(main.settings, "max_body_bytes", 500)
    r = client.post("/api/analyze", json={"content": "x" * 2000, "surface": "llm_io"})
    assert r.status_code == 413


def test_oversized_content_field_422(client):
    r = client.post("/api/analyze", json={"content": "x" * (MAX_CONTENT + 1), "surface": "llm_io"})
    assert r.status_code == 422                     # Pydantic max_length rejects it


def test_alert_webhook_write_only(client):
    t = client.patch("/api/tenant", json={"alert_webhook": "https://hooks.slack.com/services/T/B/secr"}).json()
    assert t["alert_webhook_set"] is True
    assert "alert_webhook" not in t                 # the URL (may embed a token) is never returned
    me = client.get("/api/auth/me").json()
    assert me["tenant"]["alert_webhook_set"] is True and "alert_webhook" not in me["tenant"]


def test_security_headers_present(client):
    r = client.get("/api/health")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"


def test_oidc_ssrf_guard():
    import pytest
    for bad in ("http://169.254.169.254/.well-known/openid-configuration",
                "http://127.0.0.1:6379/", "http://10.0.0.5/token"):
        with pytest.raises(oidc.OIDCError):
            oidc._safe(bad)
    assert oidc._safe("https://8.8.8.8/token") == "https://8.8.8.8/token"  # public host allowed


def test_recovery_code_consume_constant_time_still_correct():
    codes = totp.generate_recovery_codes(4)
    stored = [totp.hash_code(c) for c in codes]
    # wrong code -> None; correct code -> remaining (that hash removed)
    assert totp.consume_recovery(stored, "not-a-real-code") is None
    remaining = totp.consume_recovery(stored, codes[1])
    assert remaining is not None and totp.hash_code(codes[1]) not in remaining
    assert len(remaining) == 3
