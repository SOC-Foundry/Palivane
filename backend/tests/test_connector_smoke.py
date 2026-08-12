"""Smoke-CLI plumbing (scripts/connector_smoke.py) — monkeypatched fetchers, no live HTTP.

The CLI imports the same app.saas_connectors module these tests patch, so swapping a
PLATFORMS fetch entry here is exactly what the script executes."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from app import saas_connectors as sc

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "connector_smoke.py"
_spec = importlib.util.spec_from_file_location("connector_smoke", _SCRIPT)
smoke = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(smoke)

_ROWS = [
    {"app_name": "Claude", "app_id": "A1", "user": "", "provider": "slack",
     "scopes": ["channels:history", "chat:write"]},
    {"app_name": "Some CRM", "app_id": "A2", "user": "", "provider": "slack", "scopes": []},
]


def test_pass_path_reports_and_never_echoes_secrets(monkeypatch, capsys):
    seen = {}
    def fake_fetch(creds):
        seen.update(creds)
        return list(_ROWS)
    monkeypatch.setitem(sc.PLATFORMS["slack"], "fetch", fake_fetch)
    rc = smoke.run(["--platform", "slack", "--admin-token", "xoxp-supersecret"])
    out = capsys.readouterr().out
    assert rc == 0 and "SMOKE: PASS" in out
    assert "2 grant row(s)" in out and "shape: OK" in out
    assert seen["admin_token"] == "xoxp-supersecret"   # the real fetcher got the flag value
    assert "xoxp-supersecret" not in out               # ... but it is never printed
    assert "scopes=2" in out and "user=no" in out      # redacted sample line


def test_env_credentials_and_truncation_sentinel(monkeypatch, capsys):
    monkeypatch.setenv("PALIVANE_SMOKE_SLACK_ADMIN_TOKEN", "xoxp-from-env")
    seen = {}
    def fake_fetch(creds):
        seen.update(creds)
        return list(_ROWS) + [{"app_name": "__truncated_at_2000_users__", "app_id": "",
                               "user": "", "provider": "slack", "scopes": []}]
    monkeypatch.setitem(sc.PLATFORMS["slack"], "fetch", fake_fetch)
    rc = smoke.run(["--platform", "slack"])
    out = capsys.readouterr().out
    assert rc == 0 and "SMOKE: PASS" in out
    assert seen["admin_token"] == "xoxp-from-env"      # env var reached the fetcher
    assert "$PALIVANE_SMOKE_SLACK_ADMIN_TOKEN" in out  # sourcing is reported
    assert "xoxp-from-env" not in out
    assert "1 truncation sentinel(s)" in out and "__truncated_at_2000_users__" in out
    assert "2 grant row(s)" in out                     # sentinel not counted as a grant


def test_auth_failure_surfaces_fetcher_hint(monkeypatch, capsys):
    """Slack has no separate token exchange — an in-band auth error must fail the smoke
    with the fetcher's actionable hint intact."""
    def boom(creds):
        raise sc.ConnectorError("Slack API error missing_scope: token lacks "
                                "admin.apps:read — reinstall the admin app with that scope")
    monkeypatch.setitem(sc.PLATFORMS["slack"], "fetch", boom)
    rc = smoke.run(["--platform", "slack", "--admin-token", "xoxp-weak"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "fetch: FAIL" in out and "admin.apps:read" in out
    assert out.rstrip().endswith("SMOKE: FAIL")


def test_separate_auth_leg_failure_stops_before_fetch(monkeypatch, capsys):
    monkeypatch.setattr(
        sc, "_microsoft_access_token",
        lambda creds: (_ for _ in ()).throw(
            sc.ConnectorError("HTTP 401 from login.microsoftonline.com: AADSTS7000215 "
                              "invalid client secret")))
    monkeypatch.setitem(sc.PLATFORMS["microsoft_365"], "fetch",
                        lambda creds: (_ for _ in ()).throw(
                            AssertionError("fetch must not run after auth failed")))
    rc = smoke.run(["--platform", "microsoft_365", "--tenant-id", "t1",
                    "--client-id", "app", "--client-secret", "nope"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "auth: FAIL" in out and "AADSTS7000215" in out and "SMOKE: FAIL" in out


def test_separate_auth_leg_success_is_reported(monkeypatch, capsys):
    monkeypatch.setattr(sc, "_microsoft_access_token", lambda creds: "tok")
    monkeypatch.setitem(sc.PLATFORMS["microsoft_365"], "fetch", lambda creds: [
        {"app_name": "ChatGPT", "app_id": "aaa-111", "user": "alice@acme.com",
         "provider": "microsoft", "scopes": ["Files.Read"]}])
    rc = smoke.run(["--platform", "microsoft_365", "--tenant-id", "t1",
                    "--client-id", "app", "--client-secret", "s3cret"])
    out = capsys.readouterr().out
    assert rc == 0 and "SMOKE: PASS" in out
    assert "auth: OK" in out and "tok" not in out.replace("token", "")
    assert "user=yes" in out and "alice@acme.com" not in out   # redacted by default


def test_full_flag_prints_complete_rows(monkeypatch, capsys):
    monkeypatch.setitem(sc.PLATFORMS["slack"], "fetch", lambda creds: [
        {"app_name": "Gong", "app_id": "0Sc1", "user": "alice@acme.com",
         "provider": "slack", "scopes": ["calls:read"]}])
    rc = smoke.run(["--platform", "slack", "--admin-token", "x", "--full"])
    out = capsys.readouterr().out
    assert rc == 0 and "SMOKE: PASS" in out
    assert "alice@acme.com" in out and "calls:read" in out     # --full shows the raw rows


def test_shape_violation_fails(monkeypatch, capsys):
    monkeypatch.setitem(sc.PLATFORMS["slack"], "fetch", lambda creds: [
        {"app_name": "OK", "app_id": "A1", "user": "", "provider": "slack", "scopes": []},
        {"app_name": "No scopes key", "app_id": "A2", "user": "", "provider": "slack"},
        {"app_name": "Bad scopes", "app_id": "A3", "user": "", "provider": "slack",
         "scopes": "not-a-list"},
    ])
    rc = smoke.run(["--platform", "slack", "--admin-token", "x"])
    out = capsys.readouterr().out
    assert rc == 1 and "SMOKE: FAIL" in out
    assert "shape: FAIL" in out and "2 row(s) violate" in out
    assert "missing=['scopes']" in out                         # key drift is named


def test_notion_manual_only_skips_cleanly(capsys):
    rc = smoke.run(["--platform", "notion"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "SMOKE: SKIP" in out and "manual-export-only" in out
    assert "oauth-grants" in out                # points at the manual ingest path


def test_unknown_platform_is_a_usage_error(capsys):
    rc = smoke.run(["--platform", "carrier_pigeon"])
    out = capsys.readouterr().out
    assert rc == 2 and "google_workspace" in out   # lists the valid keys


def test_credential_value_can_be_a_file(monkeypatch, tmp_path, capsys):
    """A field value naming a file is replaced by its contents (service-account key files)."""
    key = tmp_path / "sa.json"
    key.write_text('{"client_email": "sa@p.iam", "private_key": "k"}')
    seen = {}
    monkeypatch.setattr(sc, "_google_access_token", lambda creds: "tok")
    def fake_fetch(creds):
        seen.update(creds)
        return list(_ROWS)
    monkeypatch.setitem(sc.PLATFORMS["google_workspace"], "fetch", fake_fetch)
    rc = smoke.run(["--platform", "google_workspace",
                    "--service-account-json", str(key), "--admin-email", "admin@acme.com"])
    assert rc == 0
    assert seen["service_account_json"] == key.read_text()
    assert "SMOKE: PASS" in capsys.readouterr().out
