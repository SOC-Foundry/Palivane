"""Config hygiene: secret-manager values often carry a trailing newline
(`echo | gcloud secrets versions add`) — compared tokens must strip it, or no
pasted token can ever match (the /admin operator-console lockout)."""

from __future__ import annotations

import importlib


def test_compared_tokens_are_stripped(monkeypatch):
    monkeypatch.setenv("WARDEN_METRICS_TOKEN", "op-token\n")
    monkeypatch.setenv("EXTENSION_INGEST_TOKEN", " ext-token\n")
    import app.config as config
    importlib.reload(config)
    try:
        s = config.Settings()
        assert s.metrics_token == "op-token"
        assert s.extension_ingest_token == "ext-token"
    finally:
        monkeypatch.undo()
        importlib.reload(config)  # restore module state from the real environment
