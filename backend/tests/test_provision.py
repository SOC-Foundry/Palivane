"""Bootstrap-installer generator + /api/provision endpoint (self-enrolling)."""

from __future__ import annotations

import pytest

from app import provision


def test_macos_script_self_enrolls():
    s = provision.render("macos", "https://warden.corp/", "et_secret123", extension_id="abc123")
    assert s.startswith("#!/usr/bin/env bash")
    assert "et_secret123" in s                    # carries the enrollment token
    assert "/api/enroll" in s                      # self-enrolls at runtime
    assert '"ANTHROPIC_BASE_URL": "$WARDEN_URL"' in s and "$WARDEN_URL/v1" not in s
    assert "managed-settings.json" in s
    assert "abc123" in s                           # extension id in policy block


def test_windows_script_self_enrolls():
    s = provision.render("windows", "https://warden.corp", "et_win", extension_id="xyz")
    assert "et_win" in s
    assert "/api/enroll" in s
    assert "ClaudeCode" in s and "managed-settings.json" in s
    assert "3rdparty\\extensions\\xyz\\policy" in s
    assert "Google\\Chrome" in s and "Microsoft\\Edge" in s


def test_linux_script_self_enrolls():
    s = provision.render("linux", "https://warden.corp/", "et_lin", extension_id="lnx123")
    assert s.startswith("#!/usr/bin/env bash")
    assert "et_lin" in s                                   # carries the enrollment token
    assert "/api/enroll" in s                               # self-enrolls at runtime
    assert '"ANTHROPIC_BASE_URL": "$WARDEN_URL"' in s and "$WARDEN_URL/v1" not in s
    assert "/etc/claude-code" in s                          # Linux managed-settings path
    assert "managed-settings.json" in s
    assert "pacman" in s                                    # Arch package-manager path
    assert "lnx123" in s                                    # extension id in browser policy
    assert "/etc/chromium/policies/managed" in s           # Linux browser managed-policy dir
    assert "3rdparty" in s                                  # Chromium managed-storage schema


def test_installers_are_self_healing():
    # Gateway auth goes through apiKeyHelper (warden-reenroll), not a baked static key, so a
    # revoked device key re-enrolls itself with no re-push.
    for plat, ext in (("macos", "abc"), ("linux", "lnx"), ("windows", "win")):
        s = provision.render(plat, "https://warden.corp", "et_x", extension_id=ext)
        assert "apiKeyHelper" in s and "warden-reenroll" in s
        assert "ANTHROPIC_AUTH_TOKEN" not in s          # no static gateway key baked in
        assert "warden-reenroll" in s                   # helper fetched/wired at install


def test_windows_apikeyhelper_is_python_free():
    # A Windows fleet can't be assumed to have Python; the apiKeyHelper is native PowerShell
    # (warden-reenroll.ps1, fetched at install), invoked via powershell -File.
    s = provision.render("windows", "https://warden.corp", "et_win", extension_id="xyz")
    assert "warden-reenroll.ps1" in s                       # native PS helper, not the py CLI
    assert "/cli/warden-reenroll.ps1" in s                  # fetched from the backend
    assert "powershell" in s and "-File" in s               # invoked without Python
    assert "python" not in s                                # no Python dependency anywhere


def test_browser_policy_carries_enroll_token_not_static_key():
    # The extension self-enrolls its own per-device key from the enrollment token — the
    # installer no longer bakes a static ingest key into the managed policy.
    lin = provision.render("linux", "https://warden.corp", "et_lin", extension_id="lnx")
    policy = lin.split("3rdparty", 1)[1]
    assert '"enrollToken": "$ENROLL_TOKEN"' in policy and '"token":' not in policy
    win = provision.render("windows", "https://warden.corp", "et_win", extension_id="xyz")
    assert 'Set-ItemProperty -Path $regkey -Name "enrollToken"' in win


def test_arch_alias_renders_linux():
    assert provision.render("arch", "https://x", "et_a") == provision.render("linux", "https://x", "et_a")


def test_provision_endpoint_serves_linux(client):
    r = client.post("/api/provision", json={"platform": "linux", "base_url": "https://warden.corp"})
    assert r.status_code == 200, r.text
    assert set(r.json()["scripts"]) == {"linux"}
    assert "#!/usr/bin/env bash" in r.json()["scripts"]["linux"]


def test_unknown_platform_rejected():
    with pytest.raises(ValueError):
        provision.render("android", "https://x", "et_")


def test_provision_endpoint_mints_enroll_token_and_returns_scripts(client):
    r = client.post("/api/provision", json={
        "platform": "both", "base_url": "https://warden.corp", "extension_id": "myextid"})
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
    body = client.post("/api/provision", json={"platform": "macos", "base_url": "https://warden.corp"}).json()
    import re
    et = re.search(r'ENROLL_TOKEN="(et_[^"]+)"', body["scripts"]["macos"]).group(1)
    r = raw_client.post("/api/enroll", json={"token": et, "device": "mac-42@acme.com"})
    assert r.status_code == 200
    assert r.json()["token"].startswith("ak_")
    assert any(k["actor"] == "mac-42@acme.com" for k in client.get("/api/apikeys").json()["api_keys"])


def test_provision_uses_configured_extension_id_by_default(client, monkeypatch):
    import app.main as main
    monkeypatch.setattr(main.settings, "extension_id", "storeassignedid123")
    r = client.post("/api/provision", json={"platform": "windows", "base_url": "https://warden.corp"})
    assert "storeassignedid123" in r.json()["scripts"]["windows"]   # no explicit id passed
    # explicit id in the request still overrides the configured default
    r2 = client.post("/api/provision", json={"platform": "windows", "base_url": "https://warden.corp",
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
