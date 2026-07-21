"""Bootstrap-installer generator.

Renders a single, prefilled setup script per OS. The script carries a **reusable
enrollment token** (not a device key): at runtime each machine self-enrolls
(`POST /api/enroll` with its hostname/user) and receives its **own** per-device API key,
then configures the endpoints Warden governs — Claude Code (managed-settings.json), the
browser extension (managed policy), and optionally the desktop proxy.

Crucially the artifacts stay self-healing after install: Claude Code's gateway auth goes
through `apiKeyHelper` (warden-reenroll), and the browser extension gets the enrollment
token (not a static ingest key). So if a device key is revoked/rotated, the machine
re-enrolls on its own — no re-push to the fleet. One installer serves everyone, and every
device gets an independently-revocable, attributed key.

Pure string templating (no I/O) so it's unit-testable; the API layer mints the
enrollment token and serves the result.
"""

from __future__ import annotations

# Chrome/Edge extension id once the extension is published (Web Store / self-hosted CRX).
DEFAULT_EXTENSION_ID = "REPLACE_WITH_PUBLISHED_EXTENSION_ID"


def _base(base_url: str) -> str:
    return base_url.rstrip("/")


def render_macos(base_url: str, enroll_token: str, extension_id: str, proxy_host: str = "") -> str:
    ext = extension_id or DEFAULT_EXTENSION_ID
    b = _base(base_url)
    return f'''#!/usr/bin/env bash
# Warden device setup (macOS). Carries an ENROLLMENT token; each machine self-enrolls for
# its own per-device key. Claude Code's apiKeyHelper (warden-reenroll) re-enrolls
# automatically if that key is ever revoked/rotated, so a revoked key self-heals without a
# re-push. Safe to run on many machines; treat the file as a secret.
set -euo pipefail
WARDEN_URL="{b}"
ENROLL_TOKEN="{enroll_token}"
EXT_ID="{ext}"
DEVICE="$(whoami)@$(hostname -s 2>/dev/null || hostname)"

echo "Enrolling this device with Warden as $DEVICE ..."
RESP=$(curl -fsS -X POST "$WARDEN_URL/api/enroll" -H 'content-type: application/json' \\
  -d "{{\\"token\\":\\"$ENROLL_TOKEN\\",\\"device\\":\\"$DEVICE\\"}}")
KEY=$(printf '%s' "$RESP" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p')
if [ -z "$KEY" ]; then echo "Enrollment failed: $RESP" >&2; exit 1; fi
echo "  device key issued."

# Self-heal helper: Claude Code's apiKeyHelper runs this to fetch a live gateway key and
# re-enrolls if the device key is revoked. Reads config from /etc/warden/enroll.json (and
# inherits WARDEN_* from managed-settings). Prime its cache with the key we just minted.
echo "Installing warden-reenroll (apiKeyHelper) ..."
curl -fsSL "$WARDEN_URL/cli/warden-reenroll" -o /tmp/warden-reenroll
sudo install -m 0755 /tmp/warden-reenroll /usr/local/bin/warden-reenroll
sudo mkdir -p /etc/warden
sudo tee /etc/warden/enroll.json >/dev/null <<JSON
{{ "url": "$WARDEN_URL", "enroll_token": "$ENROLL_TOKEN", "device": "$DEVICE" }}
JSON
mkdir -p "$HOME/.warden"; printf '%s' "$KEY" > "$HOME/.warden/device-key"; chmod 600 "$HOME/.warden/device-key"

echo "Configuring Claude Code ..."
CC_DIR="/Library/Application Support/ClaudeCode"
sudo mkdir -p "$CC_DIR"
sudo tee "$CC_DIR/managed-settings.json" >/dev/null <<JSON
{{ "env": {{ "ANTHROPIC_BASE_URL": "$WARDEN_URL", "WARDEN_URL": "$WARDEN_URL", "WARDEN_TOKEN": "$KEY", "WARDEN_ENROLL_TOKEN": "$ENROLL_TOKEN" }}, "apiKeyHelper": "/usr/local/bin/warden-reenroll" }}
JSON
echo "  Claude Code -> $CC_DIR/managed-settings.json (gateway auth via apiKeyHelper)"

# Browser extension (Chrome/Edge): push this managed policy via MDM (managed storage) for
# extension id $EXT_ID. It carries the ENROLLMENT token — the extension self-enrolls its
# own per-device key and re-enrolls if revoked (no static ingest key baked in):
cat <<POLICY
  {{ "backendUrl": {{"Value": "$WARDEN_URL"}}, "enrollToken": {{"Value": "$ENROLL_TOKEN"}}, "enforce": {{"Value": true}} }}
POLICY

# Desktop app (egress proxy) — optional; needs the Warden CA + admin. See docs.
echo "Done. Restart Claude Code and your browser to apply."
'''


def render_windows(base_url: str, enroll_token: str, extension_id: str, proxy_host: str = "") -> str:
    ext = extension_id or DEFAULT_EXTENSION_ID
    b = _base(base_url)
    return f'''# Warden device setup (Windows, run as Administrator in PowerShell). Carries an
# ENROLLMENT token; each machine self-enrolls for its own per-device key, and Claude Code's
# apiKeyHelper (warden-reenroll) re-enrolls automatically if that key is revoked/rotated.
# Needs Python on PATH for the apiKeyHelper.
$ErrorActionPreference = "Stop"
$WardenUrl   = "{b}"
$EnrollToken = "{enroll_token}"
$Device      = "$env:USERNAME@$env:COMPUTERNAME"

Write-Host "Enrolling this device with Warden as $Device ..."
$resp = Invoke-RestMethod -Method Post -Uri "$WardenUrl/api/enroll" -ContentType 'application/json' `
  -Body (@{{ token = $EnrollToken; device = $Device }} | ConvertTo-Json)
$Key = $resp.token
if (-not $Key) {{ throw "Enrollment failed" }}
Write-Host "  device key issued."

Write-Host "Installing warden-reenroll (apiKeyHelper) ..."
$WardenDir = "$env:ProgramFiles\\Warden"
New-Item -ItemType Directory -Force -Path $WardenDir | Out-Null
$Reenroll = "$WardenDir\\warden-reenroll"
Invoke-RestMethod -Uri "$WardenUrl/cli/warden-reenroll" -OutFile $Reenroll
$cfgDir = "$env:ProgramData\\Warden"
New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
@{{ url = $WardenUrl; enroll_token = $EnrollToken; device = $Device }} | ConvertTo-Json |
  Set-Content -Path "$cfgDir\\enroll.json" -Encoding UTF8

Write-Host "Configuring Claude Code ..."
$ccDir = "C:\\Program Files\\ClaudeCode"
New-Item -ItemType Directory -Force -Path $ccDir | Out-Null
$cc = @{{ env = @{{ ANTHROPIC_BASE_URL = "$WardenUrl"; WARDEN_URL = "$WardenUrl"; WARDEN_TOKEN = $Key; WARDEN_ENROLL_TOKEN = $EnrollToken }}; apiKeyHelper = "python `"$Reenroll`"" }}
$cc | ConvertTo-Json -Depth 5 | Set-Content -Path "$ccDir\\managed-settings.json" -Encoding UTF8
Write-Host "  Claude Code -> $ccDir\\managed-settings.json (gateway auth via apiKeyHelper)"

Write-Host "Configuring browser extension managed policy (Chrome + Edge) ..."
foreach ($vendor in @("Google\\Chrome", "Microsoft\\Edge")) {{
  $regkey = "HKLM:\\Software\\Policies\\$vendor\\3rdparty\\extensions\\{ext}\\policy"
  New-Item -Path $regkey -Force | Out-Null
  Set-ItemProperty -Path $regkey -Name "backendUrl"  -Value $WardenUrl
  Set-ItemProperty -Path $regkey -Name "enrollToken" -Value $EnrollToken
  Set-ItemProperty -Path $regkey -Name "enforce"     -Value 1
}}
Write-Host "  Browser policy set for extension {ext}"

# Desktop app (egress proxy) — optional; needs the Warden CA + admin. See docs.
Write-Host "Done. Restart Claude Code and your browser to apply."
'''


def render_linux(base_url: str, enroll_token: str, extension_id: str, proxy_host: str = "") -> str:
    ext = extension_id or DEFAULT_EXTENSION_ID
    b = _base(base_url)
    return f'''#!/usr/bin/env bash
# Warden device setup (Linux — Arch and derivatives; also Debian/Fedora). Carries an
# ENROLLMENT token; each machine self-enrolls for its own per-device key, and Claude Code's
# apiKeyHelper (warden-reenroll) re-enrolls automatically if that key is revoked/rotated.
# Safe to run on many machines; treat the file as a secret. Needs sudo for system config.
set -euo pipefail
WARDEN_URL="{b}"
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

echo "Enrolling this device with Warden as $DEVICE ..."
RESP=$(curl -fsS -X POST "$WARDEN_URL/api/enroll" -H 'content-type: application/json' \\
  -d "{{\\"token\\":\\"$ENROLL_TOKEN\\",\\"device\\":\\"$DEVICE\\"}}")
KEY=$(printf '%s' "$RESP" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p')
if [ -z "$KEY" ]; then echo "Enrollment failed: $RESP" >&2; exit 1; fi
echo "  device key issued."

# Self-heal helper: Claude Code's apiKeyHelper runs this to fetch a live gateway key and
# re-enrolls if the device key is revoked. Reads config from /etc/warden/enroll.json (and
# inherits WARDEN_* from managed-settings). Prime its cache with the key we just minted.
echo "Installing warden-reenroll (apiKeyHelper) ..."
curl -fsSL "$WARDEN_URL/cli/warden-reenroll" -o /tmp/warden-reenroll
sudo install -m 0755 /tmp/warden-reenroll /usr/local/bin/warden-reenroll
sudo mkdir -p /etc/warden
printf '%s\\n' "{{ \\"url\\": \\"$WARDEN_URL\\", \\"enroll_token\\": \\"$ENROLL_TOKEN\\", \\"device\\": \\"$DEVICE\\" }}" | sudo tee /etc/warden/enroll.json >/dev/null
mkdir -p "$HOME/.warden"; printf '%s' "$KEY" > "$HOME/.warden/device-key"; chmod 600 "$HOME/.warden/device-key"

echo "Configuring Claude Code ..."
CC_DIR="/etc/claude-code"
sudo mkdir -p "$CC_DIR"
sudo tee "$CC_DIR/managed-settings.json" >/dev/null <<JSON
{{ "env": {{ "ANTHROPIC_BASE_URL": "$WARDEN_URL", "WARDEN_URL": "$WARDEN_URL", "WARDEN_TOKEN": "$KEY", "WARDEN_ENROLL_TOKEN": "$ENROLL_TOKEN" }}, "apiKeyHelper": "/usr/local/bin/warden-reenroll" }}
JSON
echo "  Claude Code -> $CC_DIR/managed-settings.json (gateway auth via apiKeyHelper)"

# Browser extension (Chrome/Chromium/Edge): system-wide managed policy delivers this org's
# config to extension id $EXT_ID via Chromium's 3rdparty managed-storage schema. It carries
# the ENROLLMENT token — the extension self-enrolls its own per-device key (no static key).
echo "Configuring browser extension managed policy ..."
POLICY_JSON=$(cat <<JSON
{{ "3rdparty": {{ "extensions": {{ "$EXT_ID": {{ "backendUrl": "$WARDEN_URL", "enrollToken": "$ENROLL_TOKEN", "enforce": true }} }} }} }}
JSON
)
for DIR in /etc/opt/chrome/policies/managed /etc/chromium/policies/managed /etc/opt/edge/policies/managed; do
  # Only configure browsers that are actually installed (their policy root exists).
  root="${{DIR%/policies/managed}}"
  [ -d "$root" ] || continue
  sudo mkdir -p "$DIR"
  printf '%s\\n' "$POLICY_JSON" | sudo tee "$DIR/warden.json" >/dev/null
  echo "  policy -> $DIR/warden.json"
done

# Desktop app (egress proxy) — optional; needs the Warden CA + admin. See docs.
echo "Done. Restart Claude Code and your browser to apply."
'''


def render(platform: str, base_url: str, enroll_token: str,
           extension_id: str = "", proxy_host: str = "") -> str:
    if platform == "macos":
        return render_macos(base_url, enroll_token, extension_id, proxy_host)
    if platform == "windows":
        return render_windows(base_url, enroll_token, extension_id, proxy_host)
    if platform in ("linux", "arch"):
        return render_linux(base_url, enroll_token, extension_id, proxy_host)
    raise ValueError(f"unknown platform: {platform!r}")
