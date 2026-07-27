"""Public onboarding distribution: /install.sh and /cli/<name> serve the CLI + proxy addon,
allowlisted and path-traversal-safe, no auth required."""

from __future__ import annotations


def test_install_sh_served_public_with_baked_url(raw_client, monkeypatch):
    import app.distribution as dist
    monkeypatch.setattr(dist.settings, "public_base_url", "https://warden.tachtech.net")
    r = raw_client.get("/install.sh")
    assert r.status_code == 200
    assert "text/x-shellscript" in r.headers["content-type"]
    body = r.text
    assert body.startswith("#!/usr/bin/env bash")
    assert "https://warden.tachtech.net" in body
    assert "warden-connect" in body and "--desktop" in body
    assert ".warden/bin" in body
    # cli-only is the default proxy mode; --desktop and --no-proxy are the overrides
    assert 'PROXY_MODE="cli-only"' in body
    assert "--no-proxy" in body
    # cli-only threads through to the sudo-free proxy install
    assert 'warden-desktop" install --cli-only' in body


def test_cli_scripts_served(raw_client):
    for name in ("warden-connect", "warden-reenroll", "warden-reenroll.ps1", "warden-hook",
                 "warden-desktop", "warden-desktop.ps1", "warden_addon.py"):
        r = raw_client.get(f"/cli/{name}")
        assert r.status_code == 200, name
        assert len(r.text) > 100
    # warden-connect is a python CLI; warden-desktop is bash; both start with a shebang
    assert raw_client.get("/cli/warden-connect").text.startswith("#!")
    assert raw_client.get("/cli/warden-desktop").text.startswith("#!/usr/bin/env bash")
    # the Windows desktop installer is PowerShell (comment-block header, not a shebang)
    assert raw_client.get("/cli/warden-desktop.ps1").text.startswith("<#")


def test_windows_scripts_not_in_bash_installer(raw_client):
    # install.sh is bash — the PowerShell endpoints are served but never auto-installed;
    # the header points Windows users at warden-desktop.ps1 instead.
    body = raw_client.get("/install.sh").text
    assert 'curl -fsSL "$WARDEN_URL/cli/$t"' in body
    tools_line = [ln for ln in body.splitlines() if ln.startswith("TOOLS=")][0]
    assert ".ps1" not in tools_line
    assert "warden-desktop.ps1" in body  # Windows one-liner note in the header comment


def test_unknown_and_traversal_rejected(raw_client):
    assert raw_client.get("/cli/warden-nope").status_code == 404
    assert raw_client.get("/cli/secrets.py").status_code == 404
    # path traversal never resolves to an allowlisted entry
    for bad in ("..%2f..%2fetc%2fpasswd", "../config.py", "warden-connect/../main.py"):
        assert raw_client.get(f"/cli/{bad}").status_code in (404, 400)


def test_install_falls_back_when_url_unset(raw_client, monkeypatch):
    import app.distribution as dist
    monkeypatch.setattr(dist.settings, "public_base_url", "")
    body = raw_client.get("/install.sh").text
    assert "https://warden.tachtech.net" in body   # sensible default


def test_installer_covers_fish_path(raw_client):
    body = raw_client.get("/install.sh").text
    # fish doesn't read POSIX rc files — the installer must drop a conf.d snippet too.
    assert "fish/conf.d" in body and "fish_add_path" in body
    # and still handles bash/zsh
    assert ".bashrc" in body and ".zshrc" in body
