"""MDM policy-pack generator — agentless enforcement config.

Produces the config artifacts an organization's **MDM** pushes to managed devices so the
*enforcement* side of Warden is handled without any Warden agent on the box:

- **VS Code extension allowlist** (`extensions.allowed`) — lets only approved extensions
  install and blocks known-bad ones (the enforcement counterpart to /api/scan/ide-extensions);
- **system proxy** (macOS `.mobileconfig`, Windows `.reg`) — routes egress through the
  Warden proxy so MCP/AI traffic is inspected;
- **browser extension force-install** (Chrome/Edge `ExtensionInstallForcelist`);
- a **CA deployment note** — the corporate/egress-proxy root CA must be trusted for TLS
  inspection (the cert itself is the org's; we only say where it goes).

Everything here is applied by the customer's MDM (Jamf/Intune/GPO), not by a Warden
process — so it's agentless. Pure string templating, unit-testable.
"""

from __future__ import annotations

import json


def vscode_extension_policy(allowed: list[str], denied: list[str]) -> str:
    """VS Code `extensions.allowed` settings. With an allowlist, deny-all-by-default (`*`)
    and permit the approved ids; always explicitly deny known-bad ids."""
    entries: dict[str, object] = {}
    if allowed:
        entries["*"] = False
        for e in allowed:
            entries[e] = True
    for d in denied:
        entries[d] = False
    return json.dumps({"extensions.allowed": entries}, indent=2)


def macos_proxy_profile(host: str, port: int) -> str:
    """A macOS configuration profile (.mobileconfig) setting a global manual HTTP/HTTPS proxy."""
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadIdentifier</key><string>net.tachtech.warden.proxy</string>
  <key>PayloadDisplayName</key><string>Warden egress proxy</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.proxy.http.global</string>
      <key>PayloadIdentifier</key><string>net.tachtech.warden.proxy.http</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>ProxyType</key><string>Manual</string>
      <key>HTTPEnable</key><integer>1</integer>
      <key>HTTPProxy</key><string>{host}</string>
      <key>HTTPPort</key><integer>{port}</integer>
      <key>HTTPSEnable</key><integer>1</integer>
      <key>HTTPSProxy</key><string>{host}</string>
      <key>HTTPSPort</key><integer>{port}</integer>
    </dict>
  </array>
</dict>
</plist>
'''


def windows_proxy_reg(host: str, port: int) -> str:
    """A Windows .reg setting the per-user WinINET proxy (push via MDM/GPO)."""
    return ("Windows Registry Editor Version 5.00\r\n\r\n"
            "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings]\r\n"
            '"ProxyEnable"=dword:00000001\r\n'
            f'"ProxyServer"="{host}:{port}"\r\n')


def chrome_forcelist(extension_id: str) -> str:
    """ExtensionInstallForcelist value for Chrome/Edge (force-install the Warden extension)."""
    eid = extension_id or "REPLACE_WITH_PUBLISHED_EXTENSION_ID"
    return f"{eid};https://clients2.google.com/service/update2/crx"


def ca_note() -> str:
    return (
        "Deploy your egress-proxy / corporate root CA to the SYSTEM trust store via MDM so "
        "TLS inspection (and thus MCP + AI-traffic inspection) works:\n"
        "  - macOS: a Certificate payload in a configuration profile (Jamf/Intune).\n"
        "  - Windows: push to 'Trusted Root Certification Authorities' via GPO/Intune.\n"
        "Without the CA, HTTPS bodies can't be inspected and the proxy fails open. "
        "Cert-pinned clients (e.g. Cursor's chat endpoint) bypass inspection regardless."
    )


def render_pack(base_url: str, extension_id: str, proxy_host: str, proxy_port: int,
                allowed_exts: list[str], denied_exts: list[str]) -> dict[str, str]:
    b = base_url.rstrip("/")
    readme = (
        "Warden MDM policy pack — apply these with your MDM (Jamf/Intune/GPO). No Warden\n"
        "agent is installed; the OS/editor/browser enforce the policy.\n\n"
        f"Warden backend: {b}\n"
        f"Egress proxy:   {proxy_host or '<set proxy_host>'}:{proxy_port}\n\n"
        "1. vscode-extensions.json  -> push as VS Code machine settings (locks extensions.allowed).\n"
        "2. macos-proxy.mobileconfig / windows-proxy.reg -> system proxy to the Warden proxy.\n"
        "3. chrome-edge-forcelist.txt -> ExtensionInstallForcelist (force-install the extension).\n"
        "4. ca-note.txt -> deploy your root CA to the system trust store (required for TLS inspection).\n"
    )
    return {
        "README.txt": readme,
        "vscode-extensions.json": vscode_extension_policy(allowed_exts, denied_exts),
        "macos-proxy.mobileconfig": macos_proxy_profile(proxy_host or "proxy.example.com", proxy_port),
        "windows-proxy.reg": windows_proxy_reg(proxy_host or "proxy.example.com", proxy_port),
        "chrome-edge-forcelist.txt": chrome_forcelist(extension_id),
        "ca-note.txt": ca_note(),
    }
