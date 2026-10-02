"""Public onboarding distribution: /install.sh and /cli/<name> serve the CLI + proxy addon,
allowlisted and path-traversal-safe, no auth required."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest


def _prompt_section(body: str) -> str:
    """The flag parsing and the desktop-coverage question, lifted out of the served installer
    so it can run by itself. Nothing in it touches the machine: it sets variables, may ask one
    question, and stops before the signature check and the downloads."""
    start = body.index('PROXY_MODE="cli-only"')
    end = body.index("# The release-signing public key this installer pins")
    return "set -euo pipefail\n" + body[start:end] + '\necho "PROXY_MODE=$PROXY_MODE"\n'


def test_install_sh_served_public_with_baked_url(raw_client, monkeypatch):
    import app.distribution as dist
    monkeypatch.setattr(dist.settings, "public_base_url", "https://selfhosted.example.com")
    r = raw_client.get("/install.sh")
    assert r.status_code == 200
    assert "text/x-shellscript" in r.headers["content-type"]
    body = r.text
    assert body.startswith("#!/usr/bin/env bash")
    assert "https://selfhosted.example.com" in body
    assert "palivane-connect" in body and "--desktop" in body
    assert ".palivane/bin" in body
    # cli-only is the default proxy mode; --desktop and --no-proxy are the overrides
    assert 'PROXY_MODE="cli-only"' in body
    assert "--no-proxy" in body
    # cli-only threads through to the sudo-free proxy install
    assert 'palivane-desktop" install --cli-only' in body


def test_install_prompts_for_desktop_coverage_interactively(raw_client):
    # No proxy flag given: the installer must ask (via /dev/tty, so it works even under
    # `curl | bash`) whether to extend to desktop apps + browsers, defaulting to NO so a
    # non-interactive pipe stays sudo-free and never hangs. And it must say plainly, in
    # cli-only mode, that native desktop apps are NOT covered.
    body = raw_client.get("/install.sh").text
    assert 'PROXY_EXPLICIT=' in body                       # explicit flags skip the prompt
    assert "have_tty" in body and "read ans < /dev/tty" in body      # asks on the terminal
    assert "[y/N]" in body                                 # default no
    assert "NOT covered: native desktop apps" in body      # honest coverage summary
    # `[ -r /dev/tty ]` / `[ -e /dev/tty ]` are not "there is a terminal": the node exists and
    # is world-readable on every machine. Both prompts must ask have_tty, which opens it.
    assert "[ -r /dev/tty ]" not in body and "[ -e /dev/tty ]" not in body


def test_install_without_a_terminal_does_not_stop_at_the_prompt(raw_client):
    # `curl … | bash` from CI, Docker, cloud-init or `ssh host cmd` has no controlling terminal.
    # /dev/tty is still there and still readable, so a permission test says "ask", opening it
    # fails (ENXIO), and under `set -e` the installer used to end right there with nothing
    # installed and no flag to blame. It has to carry on with the default (cli-only).
    script = _prompt_section(raw_client.get("/install.sh").text)
    r = subprocess.run(["bash", "-c", script], stdin=subprocess.DEVNULL, capture_output=True,
                       text=True, timeout=30,
                       start_new_session=True)       # setsid: no controlling terminal, even from a shell
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "PROXY_MODE=cli-only" in r.stdout
    assert "/dev/tty" not in r.stderr, r.stderr      # nor a stray error for the user to wonder about


def _with_terminal(script: str, typed: bytes, *flags: str) -> subprocess.CompletedProcess:
    """Run `script` with a controlling terminal (a pty) and `typed` waiting on it, the way an
    interactive `curl … | bash` sees the world: stdin is not the terminal, /dev/tty is."""
    try:
        master, slave = os.openpty()
    except OSError:
        pytest.skip("no pty on this machine")
    os.close(master); os.close(slave)
    # pty.spawn hands the child the terminal as stdin too; `curl … | bash` does not (stdin is
    # the pipe carrying the script), and an implementation that read stdin instead of
    # /dev/tty would pass if this left it as the terminal. So take stdin away.
    script = "exec < /dev/null\n" + script
    runner = ("import pty, sys; "
              "sys.exit(pty.spawn(['bash', '-c', sys.argv[1], 'palivane-install', *sys.argv[2:]]) >> 8)")
    return subprocess.run([sys.executable, "-c", runner, script, *flags], input=typed,
                          capture_output=True, timeout=30)


@pytest.mark.parametrize("typed, mode", [(b"y\n", "desktop"), (b"Y\n", "desktop"),
                                         (b"n\n", "cli-only"), (b"\n", "cli-only")])
def test_install_with_a_terminal_still_asks(raw_client, typed, mode):
    # The other half of the fix: a person at a terminal is still asked, and the default is no.
    script = _prompt_section(raw_client.get("/install.sh").text)
    r = _with_terminal(script, typed)
    assert r.returncode == 0, r.stdout + r.stderr
    assert b"[y/N]" in r.stdout, r.stdout                       # the question was put
    assert f"PROXY_MODE={mode}".encode() in r.stdout, r.stdout


@pytest.mark.parametrize("flag, mode", [("--cli-only", "cli-only"), ("--no-proxy", "none"),
                                        ("--desktop", "desktop")])
def test_an_explicit_proxy_flag_is_never_asked_about(raw_client, flag, mode):
    # A flag is the answer. With a terminal present and a "y" waiting on it, the installer
    # must not put the question or take that "y" for the flag's answer.
    script = _prompt_section(raw_client.get("/install.sh").text)
    r = _with_terminal(script, b"y\n", flag)
    assert r.returncode == 0, r.stdout + r.stderr
    assert b"[y/N]" not in r.stdout, r.stdout
    assert f"PROXY_MODE={mode}".encode() in r.stdout, r.stdout


def test_cli_scripts_served(raw_client):
    for name in ("palivane-connect", "palivane-reenroll", "palivane-reenroll.ps1", "palivane-hook",
                 "palivane-desktop", "palivane-desktop.ps1", "palivane_addon.py"):
        r = raw_client.get(f"/cli/{name}")
        assert r.status_code == 200, name
        assert len(r.text) > 100
    # palivane-connect is a python CLI; palivane-desktop is bash; both start with a shebang
    assert raw_client.get("/cli/palivane-connect").text.startswith("#!")
    assert raw_client.get("/cli/palivane-desktop").text.startswith("#!/usr/bin/env bash")
    # the Windows desktop installer is PowerShell (comment-block header, not a shebang)
    assert raw_client.get("/cli/palivane-desktop.ps1").text.startswith("<#")


def test_windows_scripts_not_in_bash_installer(raw_client):
    # install.sh is bash — the PowerShell endpoints are served but never auto-installed;
    # the header points Windows users at palivane-desktop.ps1 instead.
    body = raw_client.get("/install.sh").text
    assert 'curl -fsSL "$PALIVANE_URL/cli/$t"' in body
    tools_line = [ln for ln in body.splitlines() if ln.startswith("TOOLS=")][0]
    assert ".ps1" not in tools_line
    assert "palivane-desktop.ps1" in body  # Windows one-liner note in the header comment


def test_unknown_and_traversal_rejected(raw_client):
    assert raw_client.get("/cli/palivane-nope").status_code == 404
    assert raw_client.get("/cli/secrets.py").status_code == 404
    # path traversal never resolves to an allowlisted entry
    for bad in ("..%2f..%2fetc%2fpasswd", "../config.py", "palivane-connect/../main.py"):
        assert raw_client.get(f"/cli/{bad}").status_code in (404, 400)


def test_install_falls_back_when_url_unset(raw_client, monkeypatch):
    import app.distribution as dist
    monkeypatch.setattr(dist.settings, "public_base_url", "")
    body = raw_client.get("/install.sh").text
    assert "https://app.palivane.io" in body   # sensible default (new brand host)


def test_installer_covers_fish_path(raw_client):
    body = raw_client.get("/install.sh").text
    # fish doesn't read POSIX rc files — the installer must drop a conf.d snippet too.
    assert "fish/conf.d" in body and "fish_add_path" in body
    # and still handles bash/zsh
    assert ".bashrc" in body and ".zshrc" in body
