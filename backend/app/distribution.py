"""Public distribution of the onboarding CLI + egress-proxy addon.

Serves a one-line installer (`GET /install.sh`) and the allowlisted script files
(`GET /cli/<name>`) so a user can set up Claude Code/Cursor governance — and, with
`--desktop`, the desktop-app egress proxy — without cloning the repo:

    curl -fsSL https://warden.tachtech.net/install.sh | bash
    curl -fsSL https://warden.tachtech.net/install.sh | bash -s -- --desktop

Public by design (same posture as the published browser extension): the scripts carry no
secrets, and `warden connect` mints a per-user token via browser sign-in at runtime. Only
files on the allowlist are served, resolved from a fixed base dir — no path traversal.
"""

from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from .config import settings

router = APIRouter(tags=["distribution"])

# public name -> path relative to the repo/app root (cli/ and proxy/ are copied into the
# image alongside the backend). warden_addon.py keeps its .py name; the CLI tools don't.
_ALLOW = {
    "warden-connect": "cli/warden-connect",
    "warden-reenroll": "cli/warden-reenroll",
    "warden-reenroll.ps1": "cli/warden-reenroll.ps1",
    "warden-hook": "cli/warden-hook",
    "warden-cursor-hook": "cli/warden-cursor-hook",
    "warden-gemini-hook": "cli/warden-gemini-hook",
    "warden-codex-hook": "cli/warden-codex-hook",
    "warden-mcp": "cli/warden-mcp",
    "warden-posture": "cli/warden-posture",
    "warden-secrets": "cli/warden-secrets",
    "warden-otel": "cli/warden-otel",
    "warden-desktop": "cli/warden-desktop",
    "warden_addon.py": "proxy/warden_addon.py",
}

# The POSIX CLI tools install under these names via install.sh. Excluded: warden_addon.py
# (the proxy addon, fetched separately by warden-desktop) and warden-reenroll.ps1 (the
# Windows-native apiKeyHelper, fetched by the Windows installer).
_CLI_TOOLS = [n for n in _ALLOW if n not in ("warden_addon.py", "warden-reenroll.ps1")]

# Candidate roots: /app in the container (backend copied to /app, cli/ to /app/cli), and
# the repo root in dev (backend/app/distribution.py -> parents[2]).
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOTS = [os.path.dirname(os.path.dirname(_HERE)), os.path.dirname(_HERE)]


def _resolve(rel: str) -> str | None:
    for root in _ROOTS:
        cand = os.path.join(root, rel)
        if os.path.isfile(cand):
            return cand
    return None


def _base_url() -> str:
    return (settings.public_base_url or "https://warden.tachtech.net").rstrip("/")


@router.get("/cli/{name}")
def get_script(name: str):
    rel = _ALLOW.get(name)
    if rel is None:
        raise HTTPException(status_code=404, detail="unknown script")
    path = _resolve(rel)
    if path is None:
        raise HTTPException(status_code=404, detail="script not available in this deployment")
    with open(path, "r", encoding="utf-8") as f:
        body = f.read()
    return PlainTextResponse(body, media_type="text/x-shellscript")


@router.get("/install.sh")
def install_sh():
    base = _base_url()
    tools = " ".join(_CLI_TOOLS)
    script = f"""#!/usr/bin/env bash
# Warden onboarding installer. Installs the governance CLI into ~/.warden/bin and runs
# `warden connect` (browser sign-in -> Claude Code + local hooks + Cursor), then stands
# up the local egress proxy so traffic those tools make directly is inspected too.
#
# By default it governs AI CLIs (Claude Code, Codex, Gemini) via per-tool shims — no sudo:
#   curl -fsSL {base}/install.sh | bash
#
#   --desktop    also govern desktop AI apps + browsers system-wide (system proxy + CA; needs sudo)
#   --cli-only   the default; kept as an explicit opt-in for clarity
#   --no-proxy   CLI + hooks only; skip the egress proxy entirely
set -euo pipefail

WARDEN_URL="{base}"
BIN="$HOME/.warden/bin"
TOOLS="{tools}"
PROXY_MODE="cli-only"   # cli-only (default) | desktop | none
for a in "$@"; do
  [ "$a" = "--desktop" ] && PROXY_MODE="desktop"
  [ "$a" = "--cli-only" ] && PROXY_MODE="cli-only"
  [ "$a" = "--no-proxy" ] && PROXY_MODE="none"
done

echo "Installing Warden CLI into $BIN ..."
mkdir -p "$BIN"
for t in $TOOLS; do
  curl -fsSL "$WARDEN_URL/cli/$t" -o "$BIN/$t"
  chmod +x "$BIN/$t"
done
echo "  installed: $TOOLS"

# Put ~/.warden/bin on PATH for future shells (bash, zsh, fish), and this one.
add_path() {{
  local rc="$1"
  [ -f "$rc" ] || return 0
  grep -qs '.warden/bin' "$rc" || printf '\\nexport PATH="$HOME/.warden/bin:$PATH"\\n' >> "$rc"
}}
add_path "$HOME/.bashrc"; add_path "$HOME/.zshrc"; add_path "$HOME/.profile"
# fish doesn't read POSIX rc files; drop a conf.d snippet (fish sources every *.fish there).
if [ -d "$HOME/.config/fish" ] || command -v fish >/dev/null 2>&1; then
  mkdir -p "$HOME/.config/fish/conf.d"
  printf 'fish_add_path -g "$HOME/.warden/bin"\\n' > "$HOME/.config/fish/conf.d/warden.fish"
fi
export PATH="$BIN:$PATH"

echo "Connecting Claude Code (a browser window will open to sign in) ..."
"$BIN/warden-connect" "$WARDEN_URL" || echo "  (run 'warden-connect' later to finish sign-in)"

case "$PROXY_MODE" in
  cli-only)
    echo "Setting up CLI governance (egress proxy + shims; no sudo) ..."
    WARDEN_URL="$WARDEN_URL" "$BIN/warden-desktop" install --cli-only \\
      || echo "  (proxy setup skipped/failed — run 'warden-desktop install --cli-only' to retry)"
    ;;
  desktop)
    echo "Setting up desktop-app governance (egress proxy; will ask for sudo) ..."
    WARDEN_URL="$WARDEN_URL" "$BIN/warden-desktop" install \\
      || echo "  (proxy setup skipped/failed — run 'warden-desktop install' to retry)"
    ;;
esac

echo ""
echo "Done. Open a new terminal (or 'source ~/.zshrc') so 'warden-connect' is on PATH."
[ "$PROXY_MODE" = "desktop" ] && echo "Desktop apps + browsers are governed system-wide."
[ "$PROXY_MODE" = "none" ] && echo "To also govern AI CLIs:  warden-desktop install --cli-only   (or --desktop for system-wide)"
"""
    return PlainTextResponse(script, media_type="text/x-shellscript")
