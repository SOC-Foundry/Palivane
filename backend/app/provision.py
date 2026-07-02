"""Bootstrap-installer generator.

Renders a single, prefilled setup script per OS that configures the endpoints Warden
governs — Claude Code (managed-settings.json), the browser extension (managed policy),
and optionally the desktop egress proxy (system proxy + CA) — with the tenant's base URL
and an API key baked in. The console mints a key and hands the user (or their MDM) one
artifact to run, instead of a page of manual steps.

Pure string templating (no I/O) so it's unit-testable; the API layer mints the key and
serves the result.
"""

from __future__ import annotations

# Chrome/Edge extension id once the extension is published (Web Store / self-hosted CRX).
# Until then the browser-policy block is emitted with this placeholder + a warning.
DEFAULT_EXTENSION_ID = "REPLACE_WITH_PUBLISHED_EXTENSION_ID"


def _v1(base_url: str) -> str:
    return base_url.rstrip("/") + "/v1"


def render_macos(base_url: str, token: str, extension_id: str, proxy_host: str = "") -> str:
    ext = extension_id or DEFAULT_EXTENSION_ID
    proxy_block = f'''
# --- 3. Desktop app (egress proxy) — optional; needs the Warden CA + admin ---
# Requires the mitmproxy/corporate CA trusted and the system proxy pointed at Warden.
# Uncomment and set PROXY_HOST; distribute the CA to $HOME/warden-ca.pem first.
# PROXY_HOST="{proxy_host or 'warden-proxy.corp:8081'}"
# sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$HOME/warden-ca.pem"
# networksetup -setsecurewebproxy "Wi-Fi" ${{PROXY_HOST%%:*}} ${{PROXY_HOST##*:}}
''' if True else ""
    return f'''#!/usr/bin/env bash
# Warden device setup (macOS). Generated for this org — contains a capture key; treat as secret.
set -euo pipefail
WARDEN_URL="{base_url.rstrip('/')}"
WARDEN_TOKEN="{token}"

echo "Configuring Claude Code..."
CC_DIR="/Library/Application Support/ClaudeCode"
sudo mkdir -p "$CC_DIR"
sudo tee "$CC_DIR/managed-settings.json" >/dev/null <<JSON
{{ "env": {{ "ANTHROPIC_BASE_URL": "{_v1(base_url)}", "ANTHROPIC_AUTH_TOKEN": "$WARDEN_TOKEN" }} }}
JSON
echo "  Claude Code -> $CC_DIR/managed-settings.json"

# --- 2. Browser extension config (Chrome/Edge) ---
# On macOS the extension is force-installed + configured via an MDM configuration profile
# (managed storage), not a file drop. Push this managed policy for extension id {ext}:
cat <<POLICY
  {{ "backendUrl": {{"Value": "$WARDEN_URL"}}, "token": {{"Value": "$WARDEN_TOKEN"}}, "enforce": {{"Value": true}} }}
POLICY
{proxy_block}
echo "Done. Restart Claude Code and your browser to apply."
'''


def render_windows(base_url: str, token: str, extension_id: str, proxy_host: str = "") -> str:
    ext = extension_id or DEFAULT_EXTENSION_ID
    return f'''# Warden device setup (Windows, run as Administrator in PowerShell).
# Generated for this org — contains a capture key; treat as secret.
$ErrorActionPreference = "Stop"
$WardenUrl   = "{base_url.rstrip('/')}"
$WardenToken = "{token}"

Write-Host "Configuring Claude Code..."
$ccDir = "C:\\Program Files\\ClaudeCode"
New-Item -ItemType Directory -Force -Path $ccDir | Out-Null
$cc = @{{ env = @{{ ANTHROPIC_BASE_URL = "{_v1(base_url)}"; ANTHROPIC_AUTH_TOKEN = $WardenToken }} }}
$cc | ConvertTo-Json -Depth 5 | Set-Content -Path "$ccDir\\managed-settings.json" -Encoding UTF8
Write-Host "  Claude Code -> $ccDir\\managed-settings.json"

Write-Host "Configuring browser extension managed policy (Chrome + Edge)..."
foreach ($vendor in @("Google\\Chrome", "Microsoft\\Edge")) {{
  $key = "HKLM:\\Software\\Policies\\$vendor\\3rdparty\\extensions\\{ext}\\policy"
  New-Item -Path $key -Force | Out-Null
  Set-ItemProperty -Path $key -Name "backendUrl" -Value $WardenUrl
  Set-ItemProperty -Path $key -Name "token"      -Value $WardenToken
  Set-ItemProperty -Path $key -Name "enforce"    -Value 1
}}
Write-Host "  Browser policy set for extension {ext}"

# --- Desktop app (egress proxy) — optional; needs the Warden CA + admin ---
# Import-Certificate -FilePath warden-ca.pem -CertStoreLocation Cert:\\LocalMachine\\Root
# $p = "{proxy_host or 'warden-proxy.corp:8081'}"
# Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' ProxyServer $p
# Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' ProxyEnable 1

Write-Host "Done. Restart Claude Code and your browser to apply."
'''


def render(platform: str, base_url: str, token: str,
           extension_id: str = "", proxy_host: str = "") -> str:
    if platform == "macos":
        return render_macos(base_url, token, extension_id, proxy_host)
    if platform == "windows":
        return render_windows(base_url, token, extension_id, proxy_host)
    raise ValueError(f"unknown platform: {platform!r}")
