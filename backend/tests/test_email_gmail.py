"""Gmail API transport: it's preferred when configured, and builds a correct
users.messages.send request (HTTPS — the only Gmail path that works from Cloud Run)."""

from __future__ import annotations

import base64
import json

from app import email as em


def test_gmail_configured_and_enabled(monkeypatch):
    monkeypatch.setattr(em.settings, "mail_from", "noreply@palivane.io")
    monkeypatch.setattr(em.settings, "gmail_sa_json", '{"client_email":"x","private_key":"y"}')
    monkeypatch.setattr(em.settings, "gmail_send_as", "david@palivane.io")
    assert em._gmail_configured() is True
    assert em.enabled() is True


def test_send_prefers_gmail_over_smtp_and_cf(monkeypatch):
    monkeypatch.setattr(em.settings, "mail_from", "noreply@palivane.io")
    monkeypatch.setattr(em.settings, "gmail_sa_json", '{"client_email":"x","private_key":"y"}')
    monkeypatch.setattr(em.settings, "gmail_send_as", "david@palivane.io")
    monkeypatch.setattr(em.settings, "smtp_host", "smtp-relay.gmail.com")  # would be next in line
    used = []
    monkeypatch.setattr(em, "_send_gmail", lambda *a: used.append("gmail"))
    monkeypatch.setattr(em, "_send_smtp", lambda *a: used.append("smtp"))
    monkeypatch.setattr(em, "_send_cf", lambda *a: used.append("cf"))
    em._send_sync("to@example.com", "Subj", "Body")
    assert used == ["gmail"]


def test_send_gmail_builds_correct_request(monkeypatch):
    monkeypatch.setattr(em.settings, "mail_from", "noreply@palivane.io")
    monkeypatch.setattr(em, "_gmail_token", lambda: "ya29.fake-token")

    captured = {}

    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"id":"18f...abc","labelIds":["SENT"]}'

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["auth"] = req.headers.get("Authorization")
        captured["body"] = json.loads(req.data)
        return FakeResp()

    monkeypatch.setattr(em.urllib.request, "urlopen", fake_urlopen)
    em._send_gmail("dana@example.com", "Reset your Palivane password", "Click here")

    assert captured["url"] == em._GMAIL_SEND_URL
    assert captured["method"] == "POST"
    assert captured["auth"] == "Bearer ya29.fake-token"
    # The raw message is urlsafe-base64 of an RFC822 message carrying our From/To/Subject.
    raw = base64.urlsafe_b64decode(captured["body"]["raw"]).decode()
    assert "From: noreply@palivane.io" in raw
    assert "To: dana@example.com" in raw
    assert "Subject: Reset your Palivane password" in raw


def test_send_gmail_raises_without_message_id(monkeypatch):
    monkeypatch.setattr(em.settings, "mail_from", "noreply@palivane.io")
    monkeypatch.setattr(em, "_gmail_token", lambda: "t")

    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"error":{"code":403}}'

    monkeypatch.setattr(em.urllib.request, "urlopen", lambda req, timeout=None: FakeResp())
    import pytest
    with pytest.raises(RuntimeError):
        em._send_gmail("x@example.com", "s", "b")
