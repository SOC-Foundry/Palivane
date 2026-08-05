"""Public distribution of the onboarding CLI + egress-proxy addon.

Serves a one-line installer (`GET /install.sh`) and the allowlisted script files
(`GET /cli/<name>`) so a user can set up Claude Code/Cursor governance — and, with
`--desktop`, the desktop-app egress proxy — without cloning the repo:

    curl -fsSL https://palivane.tachtech.net/install.sh | bash
    curl -fsSL https://palivane.tachtech.net/install.sh | bash -s -- --desktop

Public by design (same posture as the published browser extension): the scripts carry no
secrets, and `palivane connect` mints a per-user token via browser sign-in at runtime. Only
files on the allowlist are served, resolved from a fixed base dir — no path traversal.
"""

from __future__ import annotations

import hashlib
import os
import re

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse

from .config import settings

router = APIRouter(tags=["distribution"])

# public name -> path relative to the repo/app root (cli/ and proxy/ are copied into the
# image alongside the backend). palivane_addon.py keeps its .py name; the CLI tools don't.
_ALLOW = {
    "palivane-connect": "cli/palivane-connect",
    "palivane-reenroll": "cli/palivane-reenroll",
    "palivane-reenroll.ps1": "cli/palivane-reenroll.ps1",
    "palivane-desktop.ps1": "cli/palivane-desktop.ps1",
    "palivane-hook": "cli/palivane-hook",
    "palivane-cursor-hook": "cli/palivane-cursor-hook",
    "palivane-gemini-hook": "cli/palivane-gemini-hook",
    "palivane-codex-hook": "cli/palivane-codex-hook",
    "palivane-copilot-hook": "cli/palivane-copilot-hook",
    "palivane-mcp": "cli/palivane-mcp",
    "palivane-posture": "cli/palivane-posture",
    "palivane-secrets": "cli/palivane-secrets",
    "palivane-s3-scan": "cli/palivane-s3-scan",
    "palivane-github-scan": "cli/palivane-github-scan",
    "palivane-ci-scan": "cli/palivane-ci-scan",
    "palivane-otel": "cli/palivane-otel",
    "palivane-desktop": "cli/palivane-desktop",
    "palivane_addon.py": "proxy/palivane_addon.py",
}

# The POSIX CLI tools install under these names via install.sh. Excluded: palivane_addon.py
# (the proxy addon, fetched separately by palivane-desktop); palivane-reenroll.ps1 /
# palivane-desktop.ps1 (the Windows-native apiKeyHelper and desktop installer, fetched
# directly on Windows — install.sh is bash); and palivane-s3-scan / palivane-github-scan —
# ops/admin scanners run on demand (CI / a security box), not planes installed on every
# developer machine, so they're downloadable but not auto-installed.
_INSTALLER_SKIP = {"palivane_addon.py", "palivane-reenroll.ps1", "palivane-desktop.ps1",
                   "palivane-s3-scan", "palivane-github-scan", "palivane-ci-scan"}
_CLI_TOOLS = [n for n in _ALLOW if n not in _INSTALLER_SKIP]

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
    return (settings.public_base_url or "https://palivane.tachtech.net").rstrip("/")


def _manifest() -> dict:
    """Version + per-file sha256 of every script this deployment serves.

    Clients (palivane-posture's self-update) compare these hashes against their local copies
    and re-download only what changed — so a backend deploy propagates new hook/addon/
    scanner code without anyone re-running the installer. Hashes, not the version string,
    are the source of truth: a client that already matches never downloads anything.
    Computed once per process (the files are baked into the image)."""
    global _MANIFEST_CACHE
    if _MANIFEST_CACHE is None:
        files: dict[str, dict] = {}
        for name, rel in _ALLOW.items():
            path = _resolve(rel)
            if path is None:
                continue          # not shipped in this deployment — omit, don't fake it
            with open(path, "rb") as f:
                blob = f.read()
            files[name] = {"sha256": hashlib.sha256(blob).hexdigest(), "size": len(blob)}
        _MANIFEST_CACHE = {"version": settings.version,
                           "self_update": settings.self_update_enabled,
                           "base_url": _base_url(), "files": files}
    return _MANIFEST_CACHE


_MANIFEST_CACHE: dict | None = None

# User-Agent client name -> the served script that carries its VERSION constant. The proxy
# addon reports as "palivane-proxy"; every other client's UA name matches its filename.
_UA_SOURCE = {
    "palivane-hook": "palivane-hook",
    "palivane-posture": "palivane-posture",
    "palivane-cursor-hook": "palivane-cursor-hook",
    "palivane-gemini-hook": "palivane-gemini-hook",
    "palivane-codex-hook": "palivane-codex-hook",
    "palivane-copilot-hook": "palivane-copilot-hook",
    "palivane-proxy": "palivane_addon.py",
}
_VERSIONS_CACHE: dict[str, str] | None = None
_VERSION_RE = re.compile(r'^VERSION\s*=\s*["\']([^"\']+)["\']', re.MULTILINE)


def client_versions() -> dict[str, str]:
    """The client build each script declares, keyed by its User-Agent name — what a
    device SHOULD be running. The console compares reported versions against this to flag
    stale plumbing. Read from the shipped files so there's one source of truth (the
    scripts themselves), cached per process."""
    global _VERSIONS_CACHE
    if _VERSIONS_CACHE is None:
        out: dict[str, str] = {}
        for ua_name, served in _UA_SOURCE.items():
            path = _resolve(_ALLOW.get(served, ""))
            if path is None:
                continue
            try:
                with open(path, "r", encoding="utf-8") as f:
                    m = _VERSION_RE.search(f.read())
            except OSError:
                continue
            if m:
                out[ua_name] = m.group(1)
        _VERSIONS_CACHE = out
    return _VERSIONS_CACHE


@router.get("/cli/manifest.json")
def cli_manifest():
    """Public manifest of the served scripts (same posture as the scripts themselves —
    no secrets). Cache-busting is the client's job: it fetches this, not the files."""
    return JSONResponse(_manifest(), headers={"Cache-Control": "no-cache"})


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
# Palivane onboarding installer. Installs the governance CLI into ~/.palivane/bin and runs
# `palivane connect` (browser sign-in -> Claude Code + local hooks + Cursor), then stands
# up the local egress proxy so traffic those tools make directly is inspected too.
#
# By default it governs AI CLIs (Claude Code, Codex, Gemini) via per-tool shims — no sudo:
#   curl -fsSL {base}/install.sh | bash
#
#   --desktop    also govern desktop AI apps + browsers system-wide (system proxy + CA; needs sudo)
#   --cli-only   the default; kept as an explicit opt-in for clarity
#   --no-proxy   CLI + hooks only; skip the egress proxy entirely
#
# Windows (PowerShell, no admin needed):
#   iwr {base}/cli/palivane-desktop.ps1 -OutFile palivane-desktop.ps1
#   powershell -ExecutionPolicy Bypass -File palivane-desktop.ps1 install
set -euo pipefail

PALIVANE_URL="{base}"
BIN="$HOME/.palivane/bin"
TOOLS="{tools}"
PROXY_MODE="cli-only"   # cli-only (default) | desktop | none
for a in "$@"; do
  [ "$a" = "--desktop" ] && PROXY_MODE="desktop"
  [ "$a" = "--cli-only" ] && PROXY_MODE="cli-only"
  [ "$a" = "--no-proxy" ] && PROXY_MODE="none"
done

echo "Installing Palivane CLI into $BIN ..."
mkdir -p "$BIN"
for t in $TOOLS; do
  curl -fsSL "$PALIVANE_URL/cli/$t" -o "$BIN/$t"
  chmod +x "$BIN/$t"
done
echo "  installed: $TOOLS"

# Put ~/.palivane/bin on PATH for future shells (bash, zsh, fish), and this one.
add_path() {{
  local rc="$1"
  [ -f "$rc" ] || return 0
  grep -qs '.palivane/bin' "$rc" || printf '\\nexport PATH="$HOME/.palivane/bin:$PATH"\\n' >> "$rc"
}}
add_path "$HOME/.bashrc"; add_path "$HOME/.zshrc"; add_path "$HOME/.profile"
# fish doesn't read POSIX rc files; drop a conf.d snippet (fish sources every *.fish there).
if [ -d "$HOME/.config/fish" ] || command -v fish >/dev/null 2>&1; then
  mkdir -p "$HOME/.config/fish/conf.d"
  printf 'fish_add_path -g "$HOME/.palivane/bin"\\n' > "$HOME/.config/fish/conf.d/warden.fish"
fi
export PATH="$BIN:$PATH"

echo "Connecting Claude Code (a browser window will open to sign in) ..."
"$BIN/palivane-connect" "$PALIVANE_URL" || echo "  (run 'palivane-connect' later to finish sign-in)"

case "$PROXY_MODE" in
  cli-only)
    echo "Setting up CLI governance (egress proxy + shims; no sudo) ..."
    PALIVANE_URL="$PALIVANE_URL" "$BIN/palivane-desktop" install --cli-only \\
      || echo "  (proxy setup skipped/failed — run 'palivane-desktop install --cli-only' to retry)"
    ;;
  desktop)
    echo "Setting up desktop-app governance (egress proxy; will ask for sudo) ..."
    PALIVANE_URL="$PALIVANE_URL" "$BIN/palivane-desktop" install \\
      || echo "  (proxy setup skipped/failed — run 'palivane-desktop install' to retry)"
    ;;
esac

echo ""
echo "Done. Open a new terminal (or 'source ~/.zshrc') so 'palivane-connect' is on PATH."
[ "$PROXY_MODE" = "desktop" ] && echo "Desktop apps + browsers are governed system-wide."
[ "$PROXY_MODE" = "none" ] && echo "To also govern AI CLIs:  palivane-desktop install --cli-only   (or --desktop for system-wide)"
"""
    return PlainTextResponse(script, media_type="text/x-shellscript")
