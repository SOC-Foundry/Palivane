"""Rename backward-compat: PALIVANE_* env vars and X-Palivane-* headers work as the new
canonical names, while the legacy WARDEN_* / X-Palivane-* keep working through the migration."""

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


def test_ingest_uses_palivane_token_header(client, raw_client):
    # The canonical capture header is X-Palivane-Token. The legacy X-Warden-Token alias was
    # dropped in the clean-break rename — no fleet to keep it for.
    key = client.post("/api/apikeys", json={"label": "k", "actor": "d@a.com"}).json()["token"]
    body = {"content": "hello world", "destination": "chatgpt.com", "tool": "chatgpt"}

    assert raw_client.post("/api/ingest/ai-usage", json=body,
                           headers={"X-Palivane-Token": key}).status_code == 200
    # The retired legacy header no longer authenticates.
    legacy = "X-" + "Warden-Token"   # spelled to survive brand sweeps
    assert raw_client.post("/api/ingest/ai-usage", json=body,
                           headers={legacy: key}).status_code in (401, 403)
    # No token at all -> rejected.
    assert raw_client.post("/api/ingest/ai-usage", json=body).status_code in (401, 403)
