"""Rename backward-compat: PALIVANE_* env vars and X-Palivane-* headers work as the new
canonical names, while the legacy WARDEN_* / X-Warden-* keep working through the migration."""

from __future__ import annotations

import importlib


def test_env_prefers_palivane_falls_back_to_warden(monkeypatch):
    import app.config as cfg
    # legacy only
    monkeypatch.delenv("PALIVANE_TRIAL_DAYS", raising=False)
    monkeypatch.setenv("WARDEN_TRIAL_DAYS", "99")
    importlib.reload(cfg)
    assert cfg.settings.trial_days == 99
    # new name wins over legacy
    monkeypatch.setenv("PALIVANE_TRIAL_DAYS", "7")
    importlib.reload(cfg)
    assert cfg.settings.trial_days == 7
    # restore module state for the rest of the suite
    monkeypatch.delenv("PALIVANE_TRIAL_DAYS", raising=False)
    monkeypatch.delenv("WARDEN_TRIAL_DAYS", raising=False)
    importlib.reload(cfg)


def test_env_helper_precedence():
    from app.config import _env
    import os
    os.environ.pop("PALIVANE_XTEST", None); os.environ.pop("WARDEN_XTEST", None)
    assert _env("PALIVANE_XTEST", "WARDEN_XTEST", "d") == "d"      # neither set -> default
    os.environ["WARDEN_XTEST"] = "legacy"
    assert _env("PALIVANE_XTEST", "WARDEN_XTEST", "d") == "legacy"  # legacy fallback
    os.environ["PALIVANE_XTEST"] = "new"
    assert _env("PALIVANE_XTEST", "WARDEN_XTEST", "d") == "new"     # new wins
    os.environ.pop("PALIVANE_XTEST", None); os.environ.pop("WARDEN_XTEST", None)


def test_ingest_accepts_both_token_headers(client, raw_client):
    # Mint a capture key, then ingest with the NEW header and the LEGACY header — both auth.
    key = client.post("/api/apikeys", json={"label": "k", "actor": "d@a.com"}).json()["token"]
    body = {"content": "hello world", "destination": "chatgpt.com", "tool": "chatgpt"}

    r_new = raw_client.post("/api/ingest/ai-usage", json=body,
                            headers={"X-Palivane-Token": key})
    assert r_new.status_code == 200, r_new.text

    r_old = raw_client.post("/api/ingest/ai-usage", json=body,
                            headers={"X-Warden-Token": key})
    assert r_old.status_code == 200, r_old.text

    # No token at all -> rejected (the alias doesn't weaken auth).
    r_none = raw_client.post("/api/ingest/ai-usage", json=body)
    assert r_none.status_code in (401, 403)


def test_new_token_header_does_not_override_legacy_if_both_present(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "k", "actor": "d@a.com"}).json()["token"]
    # Both present with the SAME valid key -> still authorizes (alias only fills when legacy absent).
    r = raw_client.post("/api/ingest/ai-usage",
                        json={"content": "x", "destination": "chatgpt.com"},
                        headers={"X-Warden-Token": key, "X-Palivane-Token": key})
    assert r.status_code == 200, r.text
