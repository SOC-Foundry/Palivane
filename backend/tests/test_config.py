"""Config hygiene: secret-manager values often carry a trailing newline
(`echo | gcloud secrets versions add`) — compared tokens must strip it, or no
pasted token can ever match (the /admin operator-console lockout)."""

from __future__ import annotations

import importlib


def test_compared_tokens_are_stripped(monkeypatch):
    import app.config as config
    # Every module that did `from .config import settings` captured THIS object at import.
    original_settings = config.settings
    monkeypatch.setenv("PALIVANE_METRICS_TOKEN", "op-token\n")
    monkeypatch.setenv("EXTENSION_INGEST_TOKEN", " ext-token\n")
    importlib.reload(config)
    try:
        s = config.Settings()
        assert s.metrics_token == "op-token"
        assert s.extension_ingest_token == "ext-token"
    finally:
        monkeypatch.undo()
        importlib.reload(config)  # restore module state from the real environment
        # ...but reload() BINDS A NEW Settings() to config.settings, while app.main and
        # everything else still reference the old one. Diverged like that, a later test
        # doing `monkeypatch.setattr(app.config.settings, ...)` patches an object no
        # production code reads — it just silently does nothing, and the test asserts
        # against unpatched real config. That is how test_oauth_security's self-host
        # issuer guard came to fail only when xdist happened to schedule this module
        # into the same worker first. Put the original object back.
        config.settings = original_settings


def test_every_module_shares_one_settings_object():
    """`from .config import settings` captures the object, not the module attribute, so a
    module that rebinds config.settings (importlib.reload does) leaves the rest of the app
    reading a different instance. Nothing fails loudly when that happens — patches aimed at
    app.config.settings just stop reaching production code, and the tests relying on them
    quietly assert against real config instead.

    This is the tripwire. If it fails, something reloaded app.config and did not restore the
    original object; look there rather than at whatever test started failing.
    """
    import app.config as config
    from app import auth, main

    assert main.settings is config.settings
    assert auth.settings is config.settings
