"""The desktop installer's network wiring — the parts that decide whether a device keeps
working when a VPN/ZTNA client is in the path.

Two regressions live here:

  * macOS service selection. `networksetup -listnetworkserviceorder` opens with the sentence
    "An asterisk (*) denotes that a network service is disabled." — which contains ") " and
    so was parsed as a service *name* by the original `awk -F') ' | head -1`. networksetup
    was handed that sentence and silently configured nothing, so macOS desktop coverage was
    zero while the install logged success. The first entry is also not necessarily the one
    carrying traffic: a VPN adapter (CloudflareWARP, a SASE client) often sits on top.

  * Upstream trust vs. upstream chaining. The CA/insecure flags used to be gated on
    PALIVANE_UPSTREAM_PROXY, which made them unreachable for a client that inspects TLS at
    L3 and offers no proxy to chain to (Cloudflare WARP with Gateway HTTP policies). Those
    users hit a cert error on every AI host with no supported escape hatch.

The installer is bash, so these drive it through `bash -c 'source ...'` with `networksetup`
stubbed on PATH. Sourcing is safe because the script's command dispatch is guarded by
`[ "${BASH_SOURCE[0]}" = "$0" ]`.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(REPO, "cli", "palivane-desktop")

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")

# Realistic `-listnetworkserviceorder` output: the header sentence, a WARP adapter first
# with no address, the real Wi-Fi service second, and a disabled service rendered "(*)".
SERVICE_ORDER = """An asterisk (*) denotes that a network service is disabled.
(1) CloudflareWARP
(Hardware Port: CloudflareWARP, Device: utun4)

(2) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(*) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)
"""


def _stub_networksetup(tmp_path, order: str, with_ip: str | None) -> str:
    """A fake `networksetup` on PATH. `with_ip` is the one service that reports an address."""
    d = tmp_path / "stub"
    d.mkdir(exist_ok=True)
    stub = d / "networksetup"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'case "$1" in\n'
        "  -listnetworkserviceorder)\n"
        f"    cat <<'ORDER'\n{order}ORDER\n"
        "    ;;\n"
        "  -getinfo)\n"
        f'    if [ "$2" = "{with_ip or "__none__"}" ]; then\n'
        "      printf 'DHCP Configuration\\nIP address: 192.168.1.20\\n'\n"
        "    else\n"
        "      printf 'Manual Configuration\\nIP address: none\\n'\n"
        "    fi ;;\n"
        "esac\n"
    )
    stub.chmod(0o755)
    return str(d)


def _run(snippet: str, path_prefix: str | None = None, env: dict | None = None) -> str:
    e = dict(os.environ)
    if path_prefix:
        e["PATH"] = path_prefix + os.pathsep + e["PATH"]
    e.update(env or {})
    p = subprocess.run(
        ["bash", "-c", f'source "{SCRIPT}"\n{snippet}'],
        capture_output=True, text=True, env=e, timeout=60,
    )
    assert p.returncode == 0, f"stdout={p.stdout!r} stderr={p.stderr!r}"
    return p.stdout


def test_script_is_sourceable_without_running_an_install():
    # The guard exists; sourcing must not dispatch into cmd_install.
    out = _run('echo "SOURCED_OK"')
    assert "SOURCED_OK" in out
    assert "install" not in out.lower().replace("sourced_ok", "")


def test_macos_service_skips_header_sentence_and_vpn_adapter(tmp_path):
    """The regression: never the header text, and never a VPN adapter that holds no address."""
    stub = _stub_networksetup(tmp_path, SERVICE_ORDER, with_ip="Wi-Fi")
    svc = _run("macos_primary_service", path_prefix=stub).strip()
    assert svc == "Wi-Fi"
    assert "asterisk" not in svc and "denotes" not in svc
    assert svc != "CloudflareWARP"


def test_macos_service_skips_disabled_entries(tmp_path):
    """"(*) Name" entries are disabled and must never be chosen, even as the fallback."""
    order = ("An asterisk (*) denotes that a network service is disabled.\n"
             "(*) Thunderbolt Bridge\n"
             "(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n"
             "\n"
             "(1) Ethernet\n"
             "(Hardware Port: Ethernet, Device: en1)\n")
    stub = _stub_networksetup(tmp_path, order, with_ip="Ethernet")
    assert _run("macos_primary_service", path_prefix=stub).strip() == "Ethernet"


def test_macos_service_falls_back_to_first_enabled_when_nothing_has_an_ip(tmp_path):
    """Installing while offline still yields a usable service name, not the header."""
    stub = _stub_networksetup(tmp_path, SERVICE_ORDER, with_ip=None)
    assert _run("macos_primary_service", path_prefix=stub).strip() == "CloudflareWARP"


def test_upstream_ca_applies_without_an_upstream_proxy():
    """The WARP case: TLS inspected at L3, so there is no proxy to chain to — the trust flag
    must still be emitted, and no --mode upstream: with it."""
    out = _run('UPSTREAM_PROXY=""; UPSTREAM_CA=/tmp/cf-root.pem; mitm_upstream_flags')
    assert "--set ssl_verify_upstream_trusted_ca=/tmp/cf-root.pem" in out
    assert "--mode upstream:" not in out


def test_upstream_insecure_applies_without_an_upstream_proxy():
    out = _run('UPSTREAM_PROXY=""; UPSTREAM_CA=""; UPSTREAM_INSECURE=1; mitm_upstream_flags')
    assert "--ssl-insecure" in out
    assert "--mode upstream:" not in out


def test_upstream_plist_ca_applies_without_an_upstream_proxy():
    """launchd (macOS) path must agree with the systemd one."""
    out = _run('UPSTREAM_PROXY=""; UPSTREAM_CA=/tmp/cf-root.pem; mitm_upstream_plist')
    assert "ssl_verify_upstream_trusted_ca=/tmp/cf-root.pem" in out
    assert "upstream:" not in out


def test_upstream_chaining_still_emits_every_flag():
    out = _run('UPSTREAM_PROXY=http://corp:8080; UPSTREAM_AUTH=u:p; '
               'UPSTREAM_CA=/tmp/corp.pem; mitm_upstream_flags')
    assert "--mode upstream:http://corp:8080" in out
    assert "--upstream-auth u:p" in out
    assert "--set ssl_verify_upstream_trusted_ca=/tmp/corp.pem" in out


def test_no_upstream_config_emits_nothing():
    out = _run('UPSTREAM_PROXY=""; UPSTREAM_AUTH=""; UPSTREAM_CA=""; UPSTREAM_INSECURE=""; '
               'mitm_upstream_flags')
    assert out.strip() == ""


def test_resolve_upstream_ca_merges_the_public_roots(tmp_path):
    """mitmproxy's option REPLACES the trust store, so a lone corporate root would break
    every upstream host it didn't sign. The bundle must contain both."""
    ca = tmp_path / "corp.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\nCORPROOT\n-----END CERTIFICATE-----\n")
    pub = tmp_path / "public.pem"
    pub.write_text("-----BEGIN CERTIFICATE-----\nPUBLICROOT\n-----END CERTIFICATE-----\n")
    wdir = tmp_path / "wdir"
    out = _run(
        f'WDIR="{wdir}"; UPSTREAM_CA="{ca}"\n'
        f'public_ca_bundle() {{ printf "%s\\n" "{pub}"; }}\n'
        'resolve_upstream_ca >/dev/null\n'
        'printf "RESOLVED=%s\\n" "$UPSTREAM_CA"\n'
        'cat "$UPSTREAM_CA"\n'
    )
    assert f"RESOLVED={wdir}/upstream-ca-bundle.pem" in out
    assert "CORPROOT" in out and "PUBLICROOT" in out


def test_no_proxy_defaults_exclude_tailnets_and_private_ranges():
    """Intranet/tailnet traffic must never take the proxy hop."""
    out = _run('printf "%s\\n" "$NO_PROXY_ALL"')
    for entry in ("localhost", "127.0.0.1", "::1", ".ts.net", "100.64.0.0/10",
                  "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
        assert entry in out, entry
