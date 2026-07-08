"""MDM policy-pack generator + /api/policy-pack (agentless enforcement config)."""

from __future__ import annotations

import json

from app import policy_pack as pp
from app import users as users_cli


def test_vscode_allowlist_mode():
    s = json.loads(pp.vscode_extension_policy(["ms-python.python"], ["bad.ext"]))
    allowed = s["extensions.allowed"]
    assert allowed["*"] is False                 # deny-all default in allowlist mode
    assert allowed["ms-python.python"] is True
    assert allowed["bad.ext"] is False


def test_vscode_denylist_only():
    s = json.loads(pp.vscode_extension_policy([], ["bad.ext"]))
    allowed = s["extensions.allowed"]
    assert "*" not in allowed                     # no allowlist -> don't deny-all
    assert allowed["bad.ext"] is False


def test_proxy_profiles():
    mac = pp.macos_proxy_profile("proxy.acme.com", 8081)
    assert "proxy.acme.com" in mac and "com.apple.proxy.http.global" in mac
    reg = pp.windows_proxy_reg("proxy.acme.com", 8081)
    assert "ProxyServer" in reg and "proxy.acme.com:8081" in reg


def test_forcelist_webstore_vs_self_hosted():
    assert pp.chrome_forcelist("abc123") == "abc123;https://clients2.google.com/service/update2/crx"
    # Self-hosted: force-install from your own updates.xml, no Web Store.
    assert pp.chrome_forcelist("abc123", "https://cdn.corp/updates.xml") == "abc123;https://cdn.corp/updates.xml"


def test_extension_updates_xml():
    xml = pp.extension_updates_xml("abc123", "https://cdn.corp/warden.crx", "0.5.0")
    assert 'appid="abc123"' in xml and 'codebase="https://cdn.corp/warden.crx"' in xml
    assert 'version="0.5.0"' in xml and "gupdate" in xml


def test_pack_self_hosted_extension_opt_in():
    # Default (Web Store): no updates.xml, forcelist points at the store.
    default = pp.render_pack("https://w", "abc123", "", 8081, [], [])
    assert "extension-updates.xml" not in default
    assert "clients2.google.com" in default["chrome-edge-forcelist.txt"]
    # Self-hosted: updates.xml emitted, forcelist points at it.
    sh = pp.render_pack("https://w", "abc123", "", 8081, [], [],
                        ext_update_url="https://cdn.corp/updates.xml",
                        ext_crx_url="https://cdn.corp/warden.crx")
    assert "extension-updates.xml" in sh
    assert sh["chrome-edge-forcelist.txt"] == "abc123;https://cdn.corp/updates.xml"
    assert "https://cdn.corp/warden.crx" in sh["extension-updates.xml"]


def test_forcelist_and_pack():
    assert pp.chrome_forcelist("abc123").startswith("abc123;https://clients2.google.com")
    pack = pp.render_pack("https://w.acme.com/", "abc123", "proxy.acme.com", 8081,
                          ["ms-python.python"], ["bad.ext"])
    assert set(pack) >= {"README.txt", "vscode-extensions.json", "macos-proxy.mobileconfig",
                         "windows-proxy.reg", "chrome-edge-forcelist.txt",
                         "claude-managed-settings.json", "openai.env", "gemini.txt",
                         "cursor-hooks.json", "cursor.txt", "warden-secrets.plist",
                         "warden-secrets.cron", "warden-secrets-task.xml", "ca-note.txt"}


def test_secrets_schedule_artifacts_default_to_trufflehog():
    # Default engine drives TruffleHog on the scheduled run.
    plist = pp.secrets_launchd("https://w.acme.com/", "/opt/warden-secrets")
    assert "net.tachtech.warden.secrets" in plist and "/opt/warden-secrets" in plist
    assert "<string>--engine</string><string>trufflehog</string>" in plist
    cron = pp.secrets_cron("https://w.acme.com", "/opt/warden-secrets")
    assert "0 3 * * *" in cron and "/opt/warden-secrets --engine trufflehog" in cron
    xml = pp.secrets_win_task("https://w.acme.com", r"C:\Program Files\Warden\warden-secrets.exe")
    assert "ScheduleByDay" in xml and "<Arguments>--engine trufflehog</Arguments>" in xml


def test_secrets_schedule_engine_configurable():
    assert "gitleaks" in pp.secrets_cron("https://w", "/opt/warden-secrets", "gitleaks")
    # An unknown/empty engine emits the plain built-in command (no --engine).
    assert "--engine" not in pp.secrets_cron("https://w", "/opt/warden-secrets", "")


def test_policy_pack_endpoint_secrets_engine(client):
    r = client.get("/api/policy-pack?secrets_engine=gitleaks")
    assert r.status_code == 200
    assert "gitleaks" in r.json()["artifacts"]["warden-secrets.cron"]


def test_cursor_hooks_registers_security_events():
    h = json.loads(pp.cursor_hooks("/opt/warden-cursor-hook"))
    assert h["version"] == 1
    for ev in ("beforeSubmitPrompt", "beforeShellExecution", "beforeMCPExecution",
               "beforeReadFile", "afterFileEdit"):
        assert h["hooks"][ev][0]["command"] == "/opt/warden-cursor-hook"


def test_cursor_note_explains_pinning_and_planes():
    note = pp.cursor_note("https://w.acme.com/", "/opt/warden-cursor-hook")
    assert "pins" in note.lower() and "beforeSubmitPrompt" in note
    assert "warden-mcp" in note and "git" in note.lower()
    assert "https://w.acme.com/v1" in note                        # optional override URL


def test_openai_env_routes_to_gateway():
    env = pp.openai_env("https://w.acme.com/")
    assert 'OPENAI_BASE_URL="https://w.acme.com/v1"' in env
    assert 'OPENAI_API_BASE="https://w.acme.com/v1"' in env       # legacy SDK var too
    assert 'OPENAI_API_KEY="ak_' in env


def test_gemini_config_points_at_v1beta():
    cfg = pp.gemini_config("https://w.acme.com/")
    assert "https://w.acme.com/v1beta/models/{model}:generateContent" in cfg
    assert "generativelanguage.googleapis.com" in cfg             # notes the proxy path
    assert 'base_url="https://w.acme.com"' in cfg                 # SDK http_options snippet


def test_claude_managed_settings():
    s = json.loads(pp.claude_managed_settings("https://w.acme.com/", "/opt/warden-hook",
                                              "/opt/warden-posture"))
    # Gateway routing + Warden credentials in env (the ak_ token doubles as ingest auth).
    assert s["env"]["ANTHROPIC_BASE_URL"] == "https://w.acme.com/v1"
    assert s["env"]["WARDEN_URL"] == "https://w.acme.com"
    assert s["env"]["ANTHROPIC_AUTH_TOKEN"] == s["env"]["WARDEN_TOKEN"]
    assert s["env"]["WARDEN_TOKEN"].startswith("ak_")
    # Route C hooks at the deployed script paths.
    pre = s["hooks"]["PreToolUse"][0]["hooks"][0]
    assert pre["command"] == "/opt/warden-hook" and pre["timeout"] == 10
    sess = s["hooks"]["SessionStart"][0]["hooks"][0]["command"]
    assert sess == "/opt/warden-posture --async --quiet"


def test_pack_includes_claude_settings_from_endpoint(client):
    r = client.get("/api/policy-pack?base_url=https://w.acme.com&hook_path=/opt/wh")
    assert r.status_code == 200
    s = json.loads(r.json()["artifacts"]["claude-managed-settings.json"])
    assert s["env"]["ANTHROPIC_BASE_URL"] == "https://w.acme.com/v1"
    assert s["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "/opt/wh"


def test_pack_uses_per_tenant_ide_lists(client):
    client.patch("/api/tenant", json={"ide_ext_denylist": "myorg.badext"})
    r = client.get("/api/policy-pack")
    vscode = json.loads(r.json()["artifacts"]["vscode-extensions.json"])
    assert vscode["extensions.allowed"]["myorg.badext"] is False


def test_endpoint_admin_only(client, db_factory):
    r = client.get("/api/policy-pack?proxy_host=proxy.acme.com")
    assert r.status_code == 200
    arts = r.json()["artifacts"]
    assert "vscode-extensions.json" in arts and "proxy.acme.com" in arts["macos-proxy.mobileconfig"]

    # analyst is refused
    db = db_factory()
    users_cli.create_user(db, "acme", "analyst2@acme.com", "password123", "analyst")
    db.close()
    at = client.post("/api/auth/login",
                     json={"email": "analyst2@acme.com", "password": "password123"}).json()["access_token"]
    r2 = client.get("/api/policy-pack", headers={"Authorization": f"Bearer {at}"})
    assert r2.status_code == 403
