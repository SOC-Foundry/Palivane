"""Clean-break rename: PALIVANE_* env vars and X-Palivane-* headers are the ONLY
canonical names — the legacy WARDEN_* / X-Warden-* are no longer read."""

from __future__ import annotations

import importlib


def test_env_reads_palivane_only(monkeypatch):
    import app.config as cfg
    # The retired WARDEN_* name is ignored (no fallback anymore).
    monkeypatch.delenv("PALIVANE_TRIAL_DAYS", raising=False)
    monkeypatch.setenv("WARDEN_TRIAL_DAYS", "99")
    importlib.reload(cfg)
    assert cfg.settings.trial_days == 14        # default — WARDEN_ not consulted
    # The PALIVANE_ name is honored.
    monkeypatch.setenv("PALIVANE_TRIAL_DAYS", "7")
    importlib.reload(cfg)
    assert cfg.settings.trial_days == 7
    monkeypatch.delenv("PALIVANE_TRIAL_DAYS", raising=False)
    monkeypatch.delenv("WARDEN_TRIAL_DAYS", raising=False)
    importlib.reload(cfg)


def test_env_helper_reads_name_or_default():
    from app.config import _env
    import os
    os.environ.pop("PALIVANE_XTEST", None)
    assert _env("PALIVANE_XTEST", "d") == "d"      # unset -> default
    os.environ["PALIVANE_XTEST"] = "set"
    assert _env("PALIVANE_XTEST", "d") == "set"    # present -> value
    os.environ.pop("PALIVANE_XTEST", None)


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
