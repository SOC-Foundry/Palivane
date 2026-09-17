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


# --- status reports the capture PATH, not just whether a process is up --------------------

def test_status_check_names_the_consequence_not_the_mechanism():
    """`status` printed "proxy: active" while three independent failures kept Claude Desktop
    entirely uncaptured for a week: a revoked token (every scan 401s, fail open), no Electron
    --proxy-server override (traffic never reached the proxy), and a CA trusted in neither
    store. All three fail OPEN, so nothing blocked and nothing said so.

    A failure line has to say what breaks, because "NSS: no" means nothing to someone
    debugging this at 11pm.
    """
    out = _run('status_check "CA trusted by Electron apps (NSS)" 0 '
               '"Claude/ChatGPT desktop will show ERR_CERT_AUTHORITY_INVALID"; true')
    assert "FAIL" in out
    assert "ERR_CERT_AUTHORITY_INVALID" in out


def test_status_check_passes_quietly():
    out = _run('status_check "backend credential" 1; true')
    assert "ok" in out and "FAIL" not in out


def test_a_failed_check_marks_the_whole_run_bad():
    """One FAIL means capture is incomplete — the summary line exists so a passing-looking
    list cannot be skimmed past."""
    out = _run('STATUS_BAD=0; status_check "x" 1; status_check "y" 0 "z"; echo "BAD=$STATUS_BAD"')
    assert "BAD=1" in out


def test_svc_env_reads_the_installed_unit_not_the_shell(tmp_path):
    """status must report what the RUNNING proxy uses. Reading the caller's environment would
    have shown the new token while the service still held the revoked one — which is exactly
    the state that went unnoticed."""
    home = tmp_path / "home"
    (home / ".config/systemd/user").mkdir(parents=True)
    (home / ".config/systemd/user/palivane-proxy.service").write_text(
        "[Service]\nEnvironment=PALIVANE_URL=https://unit.example\n"
        "Environment=PALIVANE_TOKEN=ak_from_the_unit\n")
    # HOME, not HOME_DIR: the script sets HOME_DIR="${HOME}" at load, so overriding the
    # derived name is ignored and the test reads the developer's REAL unit file — which is
    # both a false pass and a way to print a live token into test output.
    out = _run('svc_env PALIVANE_TOKEN; svc_env PALIVANE_URL',
               env={"HOME": str(home), "OS": "Linux",
                    "PALIVANE_TOKEN": "ak_from_the_shell"})
    assert "ak_from_the_unit" in out
    assert "ak_from_the_shell" not in out
    assert "https://unit.example" in out


def test_status_probes_the_path_end_to_end_not_just_its_parts():
    """Every structural check passed while nothing from Claude Desktop was scanned.

    The proxy was running, the CA was trusted, the app was wired — and the addon read
    raw_content, so it handed gzip bytes to the parser and extracted nothing. A status
    command that only verifies the parts would have reported all-clear through the entire
    outage, which is what it did. So it sends a known-bad payload the way the app actually
    sends one (gzipped) and requires a refusal.
    """
    import inspect, pathlib
    src = pathlib.Path(SCRIPT).read_text()
    probe = src[src.index("a compressed prompt carrying PII is refused") - 1500:]
    assert "content-encoding: gzip" in probe, "the probe must be compressed like the real client"
    assert "000-00-0000" in probe, "use an unambiguously synthetic value"
    assert '"$probe_code" = "400"' in probe, "a refusal is the pass condition"
