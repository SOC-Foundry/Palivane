"""Bootstrap-installer generator + /api/provision endpoint (self-enrolling)."""

from __future__ import annotations

import pytest

from app import provision


def test_macos_script_self_enrolls():
    s = provision.render("macos", "https://palivane.corp/", "et_secret123", extension_id="abc123")
    assert s.startswith("#!/usr/bin/env bash")
    assert "et_secret123" in s                    # carries the enrollment token
    assert "/api/enroll" in s                      # self-enrolls at runtime
    assert "managed-settings.json" in s
    assert "abc123" in s                           # extension id in policy block


def test_windows_script_self_enrolls():
    s = provision.render("windows", "https://palivane.corp", "et_win", extension_id="xyz")
    assert "et_win" in s
    assert "/api/enroll" in s
    assert "ClaudeCode" in s and "managed-settings.json" in s
    assert "3rdparty\\extensions\\xyz\\policy" in s
    assert "Google\\Chrome" in s and "Microsoft\\Edge" in s


def test_linux_script_self_enrolls():
    s = provision.render("linux", "https://palivane.corp/", "et_lin", extension_id="lnx123")
    assert s.startswith("#!/usr/bin/env bash")
    assert "et_lin" in s                                   # carries the enrollment token
    assert "/api/enroll" in s                               # self-enrolls at runtime
    assert "/etc/claude-code" in s                          # Linux managed-settings path
    assert "managed-settings.json" in s
    assert "pacman" in s                                    # Arch package-manager path
    assert "lnx123" in s                                    # extension id in browser policy
    assert "/etc/chromium/policies/managed" in s           # Linux browser managed-policy dir
    assert "3rdparty" in s                                  # Chromium managed-storage schema


def test_default_keeps_claude_codes_own_auth():
    # Default (no route_gateway): Claude Code keeps its own sign-in (Pro/Max subscription).
    # The settings block must not touch ANTHROPIC_*, and forceLoginMethod locks login to
    # claude.ai so a fleet can't silently drift onto API-key billing.
    for plat in ("macos", "linux", "windows"):
        s = provision.render(plat, "https://palivane.corp", "et_x", extension_id="e")
        assert '"ANTHROPIC_BASE_URL"' not in s and "ANTHROPIC_BASE_URL =" not in s
        assert "ANTHROPIC_AUTH_TOKEN" not in s
        assert "forceLoginMethod" in s and "claudeai" in s


def test_route_gateway_opt_in_wires_gateway():
    # Opt-in gateway routing: ANTHROPIC_BASE_URL points at the gateway (no /v1 — the SDK
    # appends it) and auth comes from apiKeyHelper, so the org's provider key is billed.
    for plat in ("macos", "linux"):
        s = provision.render(plat, "https://palivane.corp", "et_x", extension_id="e",
                             route_gateway=True)
        assert '"ANTHROPIC_BASE_URL": "$PALIVANE_URL"' in s and "$PALIVANE_URL/v1" not in s
        assert "forceLoginMethod" not in s
    w = provision.render("windows", "https://palivane.corp", "et_x", extension_id="e",
                         route_gateway=True)
    assert 'ANTHROPIC_BASE_URL = "$PalivaneUrl"' in w
    assert "forceLoginMethod" not in w


def test_installers_are_self_healing():
    # Gateway auth goes through apiKeyHelper (palivane-reenroll), not a baked static key, so a
    # revoked device key re-enrolls itself with no re-push.
    for plat, ext in (("macos", "abc"), ("linux", "lnx"), ("windows", "win")):
        s = provision.render(plat, "https://palivane.corp", "et_x", extension_id=ext,
                             route_gateway=True)
        assert "apiKeyHelper" in s and "palivane-reenroll" in s
        assert "ANTHROPIC_AUTH_TOKEN" not in s          # no static gateway key baked in
        assert "palivane-reenroll" in s                   # helper fetched/wired at install


def test_windows_apikeyhelper_is_python_free():
    # A Windows fleet can't be assumed to have Python; the apiKeyHelper is native PowerShell
    # (palivane-reenroll.ps1, fetched at install), invoked via powershell -File. Wired into
    # settings only in gateway mode, but the helper itself must always be Python-free.
    s = provision.render("windows", "https://palivane.corp", "et_win", extension_id="xyz",
                         route_gateway=True)
    assert "palivane-reenroll.ps1" in s                       # native PS helper, not the py CLI
    assert "/cli/palivane-reenroll.ps1" in s                  # fetched from the backend
    assert "powershell" in s and "-File" in s               # invoked without Python
    assert "python" not in s                                # no Python dependency anywhere


def test_browser_policy_carries_enroll_token_not_static_key():
    # The extension self-enrolls its own per-device key from the enrollment token — the
    # installer no longer bakes a static ingest key into the managed policy.
    lin = provision.render("linux", "https://palivane.corp", "et_lin", extension_id="lnx")
    policy = lin.split("3rdparty", 1)[1]
    assert '"enrollToken": "$ENROLL_TOKEN"' in policy and '"token":' not in policy
    win = provision.render("windows", "https://palivane.corp", "et_win", extension_id="xyz")
    assert 'Set-ItemProperty -Path $regkey -Name "enrollToken"' in win


def test_arch_alias_renders_linux():
    assert provision.render("arch", "https://x", "et_a") == provision.render("linux", "https://x", "et_a")


def test_provision_endpoint_serves_linux(client):
    r = client.post("/api/provision", json={"platform": "linux", "base_url": "https://palivane.corp"})
    assert r.status_code == 200, r.text
    assert set(r.json()["scripts"]) == {"linux"}
    s = r.json()["scripts"]["linux"]
    assert "#!/usr/bin/env bash" in s
    assert "ANTHROPIC_BASE_URL" not in s and "forceLoginMethod" in s   # subscription default


def test_provision_endpoint_route_gateway_opt_in(client):
    r = client.post("/api/provision", json={"platform": "linux", "base_url": "https://palivane.corp",
                                            "route_gateway": True})
    assert r.status_code == 200, r.text
    s = r.json()["scripts"]["linux"]
    assert '"ANTHROPIC_BASE_URL": "$PALIVANE_URL"' in s and "forceLoginMethod" not in s


def test_unknown_platform_rejected():
    with pytest.raises(ValueError):
        provision.render("android", "https://x", "et_")


def test_provision_endpoint_mints_enroll_token_and_returns_scripts(client):
    r = client.post("/api/provision", json={
        "platform": "both", "base_url": "https://palivane.corp", "extension_id": "myextid"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body["scripts"]) == {"macos", "windows"}
    assert body["enroll_token_prefix"].startswith("et_")
    assert "et_" in body["scripts"]["macos"] and "/api/enroll" in body["scripts"]["macos"]
    assert "myextid" in body["scripts"]["windows"]
    # The enrollment token is now listed for the tenant.
    toks = client.get("/api/enroll/tokens").json()["enrollment_tokens"]
    assert any(t["prefix"] == body["enroll_token_prefix"] for t in toks)


def test_provisioned_installer_enrolls_a_device_end_to_end(client, raw_client):
    # Generate an installer, extract its embedded enrollment token, and use it as a device
    # would — confirming the whole loop yields a working per-device key.
    body = client.post("/api/provision", json={"platform": "macos", "base_url": "https://palivane.corp"}).json()
    import re
    et = re.search(r'ENROLL_TOKEN="(et_[^"]+)"', body["scripts"]["macos"]).group(1)
    r = raw_client.post("/api/enroll", json={"token": et, "device": "mac-42@acme.com"})
    assert r.status_code == 200
    assert r.json()["token"].startswith("ak_")
    assert any(k["actor"] == "mac-42@acme.com" for k in client.get("/api/apikeys").json()["api_keys"])


def test_provision_uses_configured_extension_id_by_default(client, monkeypatch):
    import app.main as main
    monkeypatch.setattr(main.settings, "extension_id", "storeassignedid123")
    r = client.post("/api/provision", json={"platform": "windows", "base_url": "https://palivane.corp"})
    assert "storeassignedid123" in r.json()["scripts"]["windows"]   # no explicit id passed
    # explicit id in the request still overrides the configured default
    r2 = client.post("/api/provision", json={"platform": "windows", "base_url": "https://palivane.corp",
                                             "extension_id": "override99"})
    assert "override99" in r2.json()["scripts"]["windows"]


def test_provision_is_admin_only(client, db_factory):
    from app import users as users_cli
    db = db_factory()
    users_cli.create_user(db, "acme", "analyst@acme.com", "password123", "analyst")
    db.close()
    at = client.post("/api/auth/login", json={"email": "analyst@acme.com", "password": "password123"}).json()["access_token"]
    r = client.post("/api/provision", json={"platform": "macos", "base_url": "https://x"},
                    headers={"Authorization": f"Bearer {at}"})
    assert r.status_code == 403
