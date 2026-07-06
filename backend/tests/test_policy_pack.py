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


def test_forcelist_and_pack():
    assert pp.chrome_forcelist("abc123").startswith("abc123;https://clients2.google.com")
    pack = pp.render_pack("https://w.acme.com/", "abc123", "proxy.acme.com", 8081,
                          ["ms-python.python"], ["bad.ext"])
    assert set(pack) >= {"README.txt", "vscode-extensions.json", "macos-proxy.mobileconfig",
                         "windows-proxy.reg", "chrome-edge-forcelist.txt", "ca-note.txt"}


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
