"""Bootstrap-installer generator.

Renders a single, prefilled setup script per OS. The script carries a **reusable
enrollment token** (not a device key): at runtime each machine self-enrolls
(`POST /api/enroll` with its hostname/user) and receives its **own** per-device API key,
then configures the endpoints Palivane governs — Claude Code (managed-settings.json), the
browser extension (managed policy), and optionally the desktop proxy.

By default Claude Code **keeps its own sign-in** (Pro/Max subscription or API account):
managed-settings carries only the Palivane credentials for the local planes plus
`forceLoginMethod: "claudeai"` so users land on subscription login. With
`route_gateway=True` the installer instead reroutes Claude Code's API traffic through the
Palivane gateway (`ANTHROPIC_BASE_URL` + `apiKeyHelper`) — that bills the org's provider
key, not personal subscriptions.

Crucially the artifacts stay self-healing after install: with gateway routing, Claude
Code's gateway auth goes through `apiKeyHelper` (palivane-reenroll), and the browser
extension gets the enrollment token (not a static ingest key). So if a device key is
revoked/rotated, the machine re-enrolls on its own — no re-push to the fleet. One
installer serves everyone, and every device gets an independently-revocable, attributed
key.

Pure string templating (no I/O) so it's unit-testable; the API layer mints the
enrollment token and serves the result.
"""

from __future__ import annotations

# Fallback extension id when a caller passes none — the configured published id (see
# config.extension_id, the single source of truth). Read lazily so an env override applies.
def _default_extension_id() -> str:
    from .config import settings
    return settings.extension_id


def _base(base_url: str) -> str:
    return base_url.rstrip("/")


def _cc_settings_sh(route_gateway: bool) -> tuple[str, str]:
    """managed-settings.json body + install echo for the bash installers.
    Values are shell variables expanded by the heredoc at runtime."""
    if route_gateway:
        return ('{ "env": { "ANTHROPIC_BASE_URL": "$PALIVANE_URL", "PALIVANE_URL": "$PALIVANE_URL", '
                '"PALIVANE_TOKEN": "$KEY", "PALIVANE_ENROLL_TOKEN": "$ENROLL_TOKEN" }, '
                '"apiKeyHelper": "/usr/local/bin/palivane-reenroll" }',
                "gateway auth via apiKeyHelper — bills the org's provider key")
    return ('{ "env": { "PALIVANE_URL": "$PALIVANE_URL", "PALIVANE_TOKEN": "$KEY", '
            '"PALIVANE_ENROLL_TOKEN": "$ENROLL_TOKEN" }, "forceLoginMethod": "claudeai" }',
            "Claude Code keeps its own sign-in (Pro/Max); login locked to claude.ai")


def render_macos(base_url: str, enroll_token: str, extension_id: str, proxy_host: str = "",
                 route_gateway: bool = False) -> str:
    ext = extension_id or _default_extension_id()
    b = _base(base_url)
    cc_json, cc_note = _cc_settings_sh(route_gateway)
    return f'''#!/usr/bin/env bash
# Palivane device setup (macOS). Carries an ENROLLMENT token; each machine self-enrolls for
# its own per-device key. Claude Code's apiKeyHelper (palivane-reenroll) re-enrolls
# automatically if that key is ever revoked/rotated, so a revoked key self-heals without a
# re-push. Safe to run on many machines; treat the file as a secret.
set -euo pipefail
PALIVANE_URL="{b}"
ENROLL_TOKEN="{enroll_token}"
EXT_ID="{ext}"
DEVICE="$(whoami)@$(hostname -s 2>/dev/null || hostname)"

echo "Enrolling this device with Palivane as $DEVICE ..."
RESP=$(curl -fsS -X POST "$PALIVANE_URL/api/enroll" -H 'content-type: application/json' \\
  -d "{{\\"token\\":\\"$ENROLL_TOKEN\\",\\"device\\":\\"$DEVICE\\"}}")
KEY=$(printf '%s' "$RESP" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p')
if [ -z "$KEY" ]; then echo "Enrollment failed: $RESP" >&2; exit 1; fi
echo "  device key issued."

# Self-heal helper: Claude Code's apiKeyHelper runs this to fetch a live gateway key and
# re-enrolls if the device key is revoked. Reads config from /etc/warden/enroll.json (and
# inherits PALIVANE_* from managed-settings). Prime its cache with the key we just minted.
echo "Installing palivane-reenroll (apiKeyHelper) ..."
curl -fsSL "$PALIVANE_URL/cli/palivane-reenroll" -o /tmp/palivane-reenroll
sudo install -m 0755 /tmp/palivane-reenroll /usr/local/bin/palivane-reenroll
sudo mkdir -p /etc/warden
sudo tee /etc/warden/enroll.json >/dev/null <<JSON
{{ "url": "$PALIVANE_URL", "enroll_token": "$ENROLL_TOKEN", "device": "$DEVICE" }}
JSON
mkdir -p "$HOME/.palivane"; printf '%s' "$KEY" > "$HOME/.palivane/device-key"; chmod 600 "$HOME/.palivane/device-key"

echo "Configuring Claude Code ..."
CC_DIR="/Library/Application Support/ClaudeCode"
sudo mkdir -p "$CC_DIR"
sudo tee "$CC_DIR/managed-settings.json" >/dev/null <<JSON
{cc_json}
JSON
echo "  Claude Code -> $CC_DIR/managed-settings.json ({cc_note})"

# Browser extension (Chrome/Edge): push this managed policy via MDM (managed storage) for
# extension id $EXT_ID. It carries the ENROLLMENT token — the extension self-enrolls its
# own per-device key and re-enrolls if revoked (no static ingest key baked in):
cat <<POLICY
  {{ "backendUrl": {{"Value": "$PALIVANE_URL"}}, "enrollToken": {{"Value": "$ENROLL_TOKEN"}}, "enforce": {{"Value": true}} }}
POLICY

# Desktop app (egress proxy) — optional; needs the Palivane CA + admin. See docs.
echo "Done. Restart Claude Code and your browser to apply."
'''


def render_windows(base_url: str, enroll_token: str, extension_id: str, proxy_host: str = "",
                   route_gateway: bool = False) -> str:
    ext = extension_id or _default_extension_id()
    b = _base(base_url)
    if route_gateway:
        cc_ps = ('@{ env = @{ ANTHROPIC_BASE_URL = "$PalivaneUrl"; PALIVANE_URL = "$PalivaneUrl"; '
                 'PALIVANE_TOKEN = $Key; PALIVANE_ENROLL_TOKEN = $EnrollToken }; '
                 'apiKeyHelper = "powershell -NoProfile -ExecutionPolicy Bypass -File `"$Reenroll`"" }')
        cc_note = "gateway auth via apiKeyHelper — bills the org's provider key"
    else:
        cc_ps = ('@{ env = @{ PALIVANE_URL = "$PalivaneUrl"; PALIVANE_TOKEN = $Key; '
                 'PALIVANE_ENROLL_TOKEN = $EnrollToken }; forceLoginMethod = "claudeai" }')
        cc_note = "Claude Code keeps its own sign-in (Pro/Max); login locked to claude.ai"
    return f'''# Palivane device setup (Windows, run as Administrator in PowerShell). Carries an
# ENROLLMENT token; each machine self-enrolls for its own per-device key, and Claude Code's
# apiKeyHelper (palivane-reenroll.ps1) re-enrolls automatically if that key is revoked/rotated.
# The helper is native PowerShell — no Python required.
$ErrorActionPreference = "Stop"
$PalivaneUrl   = "{b}"
$EnrollToken = "{enroll_token}"
$Device      = "$env:USERNAME@$env:COMPUTERNAME"

Write-Host "Enrolling this device with Palivane as $Device ..."
$resp = Invoke-RestMethod -Method Post -Uri "$PalivaneUrl/api/enroll" -ContentType 'application/json' `
  -Body (@{{ token = $EnrollToken; device = $Device }} | ConvertTo-Json)
$Key = $resp.token
if (-not $Key) {{ throw "Enrollment failed" }}
Write-Host "  device key issued."

Write-Host "Installing palivane-reenroll (apiKeyHelper) ..."
$PalivaneDir = "$env:ProgramFiles\\Palivane"
New-Item -ItemType Directory -Force -Path $PalivaneDir | Out-Null
$Reenroll = "$PalivaneDir\\palivane-reenroll.ps1"
Invoke-RestMethod -Uri "$PalivaneUrl/cli/palivane-reenroll.ps1" -OutFile $Reenroll
$cfgDir = "$env:ProgramData\\Palivane"
New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
@{{ url = $PalivaneUrl; enroll_token = $EnrollToken; device = $Device }} | ConvertTo-Json |
  Set-Content -Path "$cfgDir\\enroll.json" -Encoding UTF8

Write-Host "Configuring Claude Code ..."
$ccDir = "C:\\Program Files\\ClaudeCode"
New-Item -ItemType Directory -Force -Path $ccDir | Out-Null
$cc = {cc_ps}
$cc | ConvertTo-Json -Depth 5 | Set-Content -Path "$ccDir\\managed-settings.json" -Encoding UTF8
Write-Host "  Claude Code -> $ccDir\\managed-settings.json ({cc_note})"

Write-Host "Configuring browser extension managed policy (Chrome + Edge) ..."
foreach ($vendor in @("Google\\Chrome", "Microsoft\\Edge")) {{
  $regkey = "HKLM:\\Software\\Policies\\$vendor\\3rdparty\\extensions\\{ext}\\policy"
  New-Item -Path $regkey -Force | Out-Null
  Set-ItemProperty -Path $regkey -Name "backendUrl"  -Value $PalivaneUrl
  Set-ItemProperty -Path $regkey -Name "enrollToken" -Value $EnrollToken
  Set-ItemProperty -Path $regkey -Name "enforce"     -Value 1
}}
Write-Host "  Browser policy set for extension {ext}"

# Desktop app (egress proxy) — optional; needs the Palivane CA + admin. See docs.
Write-Host "Done. Restart Claude Code and your browser to apply."
'''


def render_linux(base_url: str, enroll_token: str, extension_id: str, proxy_host: str = "",
                 route_gateway: bool = False) -> str:
    ext = extension_id or _default_extension_id()
    b = _base(base_url)
    cc_json, cc_note = _cc_settings_sh(route_gateway)
    return f'''#!/usr/bin/env bash
# Palivane device setup (Linux — Arch and derivatives; also Debian/Fedora). Carries an
# ENROLLMENT token; each machine self-enrolls for its own per-device key, and Claude Code's
# apiKeyHelper (palivane-reenroll) re-enrolls automatically if that key is revoked/rotated.
# Safe to run on many machines; treat the file as a secret. Needs sudo for system config.
set -euo pipefail
PALIVANE_URL="{b}"
ENROLL_TOKEN="{enroll_token}"
EXT_ID="{ext}"
DEVICE="$(whoami)@$(hostname -s 2>/dev/null || hostname)"

# curl is required; install it with the system package manager if missing (Arch: pacman).
if ! command -v curl >/dev/null 2>&1; then
  if   command -v pacman  >/dev/null 2>&1; then sudo pacman -Sy --needed --noconfirm curl
  elif command -v apt-get >/dev/null 2>&1; then sudo apt-get update && sudo apt-get install -y curl
  elif command -v dnf     >/dev/null 2>&1; then sudo dnf install -y curl
  else echo "curl not found and no supported package manager (pacman/apt/dnf)" >&2; exit 1; fi
fi

echo "Enrolling this device with Palivane as $DEVICE ..."
RESP=$(curl -fsS -X POST "$PALIVANE_URL/api/enroll" -H 'content-type: application/json' \\
  -d "{{\\"token\\":\\"$ENROLL_TOKEN\\",\\"device\\":\\"$DEVICE\\"}}")
KEY=$(printf '%s' "$RESP" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p')
if [ -z "$KEY" ]; then echo "Enrollment failed: $RESP" >&2; exit 1; fi
echo "  device key issued."

# Self-heal helper: Claude Code's apiKeyHelper runs this to fetch a live gateway key and
# re-enrolls if the device key is revoked. Reads config from /etc/warden/enroll.json (and
# inherits PALIVANE_* from managed-settings). Prime its cache with the key we just minted.
echo "Installing palivane-reenroll (apiKeyHelper) ..."
curl -fsSL "$PALIVANE_URL/cli/palivane-reenroll" -o /tmp/palivane-reenroll
sudo install -m 0755 /tmp/palivane-reenroll /usr/local/bin/palivane-reenroll
sudo mkdir -p /etc/warden
printf '%s\\n' "{{ \\"url\\": \\"$PALIVANE_URL\\", \\"enroll_token\\": \\"$ENROLL_TOKEN\\", \\"device\\": \\"$DEVICE\\" }}" | sudo tee /etc/warden/enroll.json >/dev/null
mkdir -p "$HOME/.palivane"; printf '%s' "$KEY" > "$HOME/.palivane/device-key"; chmod 600 "$HOME/.palivane/device-key"

echo "Configuring Claude Code ..."
CC_DIR="/etc/claude-code"
sudo mkdir -p "$CC_DIR"
sudo tee "$CC_DIR/managed-settings.json" >/dev/null <<JSON
{cc_json}
JSON
echo "  Claude Code -> $CC_DIR/managed-settings.json ({cc_note})"

# Browser extension (Chrome/Chromium/Edge): system-wide managed policy delivers this org's
# config to extension id $EXT_ID via Chromium's 3rdparty managed-storage schema. It carries
# the ENROLLMENT token — the extension self-enrolls its own per-device key (no static key).
echo "Configuring browser extension managed policy ..."
POLICY_JSON=$(cat <<JSON
{{ "3rdparty": {{ "extensions": {{ "$EXT_ID": {{ "backendUrl": "$PALIVANE_URL", "enrollToken": "$ENROLL_TOKEN", "enforce": true }} }} }} }}
JSON
)
for DIR in /etc/opt/chrome/policies/managed /etc/chromium/policies/managed /etc/opt/edge/policies/managed; do
  # Only configure browsers that are actually installed (their policy root exists).
  root="${{DIR%/policies/managed}}"
  [ -d "$root" ] || continue
  sudo mkdir -p "$DIR"
  printf '%s\\n' "$POLICY_JSON" | sudo tee "$DIR/palivane.json" >/dev/null
  echo "  policy -> $DIR/palivane.json"
done

# Desktop app (egress proxy) — optional; needs the Palivane CA + admin. See docs.
echo "Done. Restart Claude Code and your browser to apply."
'''


def render(platform: str, base_url: str, enroll_token: str,
           extension_id: str = "", proxy_host: str = "",
           route_gateway: bool = False) -> str:
    if platform == "macos":
        return render_macos(base_url, enroll_token, extension_id, proxy_host, route_gateway)
    if platform == "windows":
        return render_windows(base_url, enroll_token, extension_id, proxy_host, route_gateway)
    if platform in ("linux", "arch"):
        return render_linux(base_url, enroll_token, extension_id, proxy_host, route_gateway)
    raise ValueError(f"unknown platform: {platform!r}")
