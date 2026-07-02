"""Bootstrap-installer generator + /api/provision endpoint."""

from __future__ import annotations

import pytest

from app import provision


def test_macos_script_bakes_in_url_and_token():
    s = provision.render("macos", "https://warden.corp/", "ak_secret123", extension_id="abc123")
    assert "ANTHROPIC_BASE_URL" in s and "https://warden.corp/v1" in s   # trailing slash normalized
    assert "ak_secret123" in s
    assert "managed-settings.json" in s
    assert "abc123" in s                                                  # extension id in policy block
    assert s.startswith("#!/usr/bin/env bash")


def test_windows_script_sets_claude_code_and_browser_policy():
    s = provision.render("windows", "https://warden.corp", "ak_win", extension_id="xyz")
    assert "ANTHROPIC_BASE_URL" in s and "https://warden.corp/v1" in s
    assert "ak_win" in s
    assert "ClaudeCode" in s and "managed-settings.json" in s
    assert "3rdparty\\extensions\\xyz\\policy" in s                       # browser managed policy
    assert "Google\\Chrome" in s and "Microsoft\\Edge" in s


def test_unknown_platform_rejected():
    with pytest.raises(ValueError):
        provision.render("android", "https://x", "ak_")


def test_provision_endpoint_mints_key_and_returns_scripts(client):
    r = client.post("/api/provision", json={
        "platform": "both", "base_url": "https://warden.corp",
        "actor": "alice@acme.com", "extension_id": "myextid"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body["scripts"]) == {"macos", "windows"}
    assert body["key_prefix"].startswith("ak_")
    # The minted key appears in the scripts and is a real ak_ key.
    assert "ak_" in body["scripts"]["macos"]
    assert "myextid" in body["scripts"]["windows"]
    # The key is now listed for the tenant (created), without exposing the secret again.
    keys = client.get("/api/apikeys").json()["api_keys"]
    assert any(k["prefix"] == body["key_prefix"] and k["actor"] == "alice@acme.com" for k in keys)


def test_provision_is_admin_only(client, db_factory):
    from app import users as users_cli
    db = db_factory()
    users_cli.create_user(db, "acme", "analyst@acme.com", "password123", "analyst")
    db.close()
    at = client.post("/api/auth/login", json={"email": "analyst@acme.com", "password": "password123"}).json()["access_token"]
    r = client.post("/api/provision", json={"platform": "macos", "base_url": "https://x"},
                    headers={"Authorization": f"Bearer {at}"})
    assert r.status_code == 403
