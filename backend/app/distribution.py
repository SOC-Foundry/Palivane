"""Public distribution of the onboarding CLI + egress-proxy addon.

Serves a one-line installer (`GET /install.sh`) and the allowlisted script files
(`GET /cli/<name>`) so a user can set up Claude Code/Cursor governance — and, with
`--desktop`, the desktop-app egress proxy — without cloning the repo:

    curl -fsSL https://app.palivane.io/install.sh | bash
    curl -fsSL https://app.palivane.io/install.sh | bash -s -- --desktop

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
    # Same script, clearer name. "palivane-mcp" is the GUARD that wraps somebody else's MCP
    # server; "the Palivane MCP server" is the thing that exposes Palivane's own tools, and
    # for months those two have shared a name in the one part of the product a launch
    # visitor touches first. Installing both spellings fixes the confusion without breaking
    # a single config in the field, which a rename would.
    "palivane-mcp-guard": "cli/palivane-mcp",
    "palivane-posture": "cli/palivane-posture",
    "palivane-secrets": "cli/palivane-secrets",
    "palivane-s3-scan": "cli/palivane-s3-scan",
    "palivane-github-scan": "cli/palivane-github-scan",
    "palivane-ci-scan": "cli/palivane-ci-scan",
    "palivane-otel": "cli/palivane-otel",
    "palivane-desktop": "cli/palivane-desktop",
    "palivane_addon.py": "proxy/palivane_addon.py",
    # Shared local-detection module; palivane-secrets and palivane-s3-scan both
    # import it, and fetch it from here when it is not already beside them.
    "palivane_detect.py": "cli/palivane_detect.py",
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
    return (settings.public_base_url or "https://app.palivane.io").rstrip("/")


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


@router.get("/cli/manifest.sig")
def cli_manifest_sig():
    """Ed25519 signature over the manifest's canonical {name: sha256} digest, base64 in a
    text/plain body. 404 when this deployment has no signing key set — the installer then
    treats the release as unsigned (warns, proceeds). See release_signing.py."""
    from . import release_signing
    sig = release_signing.sign_files(_manifest()["files"])
    if sig is None:
        raise HTTPException(status_code=404, detail="release signing not configured")
    return PlainTextResponse(sig, media_type="text/plain",
                             headers={"Cache-Control": "no-cache"})


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
    from . import release_signing
    base = _base_url()
    # Only offer the extension step when this deployment knows which item to point at.
    ext_url = (f"https://chromewebstore.google.com/detail/{settings.extension_id}"
               if settings.extension_id else "")
    tools = " ".join(_CLI_TOOLS)
    pubkey = release_signing.release_pubkey_pem().strip()
    # When this deployment signs releases, the generated installer REQUIRES a valid
    # signature (fail closed). Until the key is provisioned it serves require_sig=0, so the
    # verify step warns-but-proceeds instead of blocking every install.
    require_sig = "1" if release_signing.signing_enabled() else "0"
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
REQUIRE_SIG="{require_sig}"   # 1 when this deployment signs releases (fail closed)
# Empty unless PALIVANE_EXTENSION_ID is configured. Deliberately not defaulted in code: a
# Web Store id belongs to the account that published the item, and a stale default once
# landed a third party's extension in the MDM forcelist (see config.extension_id).
PALIVANE_EXT_URL="{ext_url}"
PROXY_MODE="cli-only"   # cli-only (default) | desktop | none
for a in "$@"; do
  [ "$a" = "--desktop" ] && PROXY_MODE="desktop"
  [ "$a" = "--cli-only" ] && PROXY_MODE="cli-only"
  [ "$a" = "--no-proxy" ] && PROXY_MODE="none"
  [ "$a" = "--no-verify" ] && REQUIRE_SIG="skip"   # opt out of integrity checks (not advised)
done

# The release-signing public key this installer pins. A signature that doesn't verify
# against THIS key is rejected — so a network attacker who can rewrite the served scripts
# still can't forge a release.
PALIVANE_RELEASE_PUBKEY="{pubkey}"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
sha256_of() {{ if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d" " -f1;
  else shasum -a 256 "$1" | cut -d" " -f1; fi; }}

# --- Integrity: verify the signed manifest, then check every file against it -----------
verify_release() {{
  [ "$REQUIRE_SIG" = "skip" ] && {{ echo "  ! integrity check skipped (--no-verify)"; return 0; }}
  curl -fsSL "$PALIVANE_URL/cli/manifest.json" -o "$TMP/manifest.json" || {{
    echo "  ! could not fetch manifest"; [ "$REQUIRE_SIG" = "1" ] && return 1 || return 0; }}
  local sig_http
  sig_http="$(curl -fsS -o "$TMP/manifest.sig" -w '%{{http_code}}' "$PALIVANE_URL/cli/manifest.sig" || echo 000)"
  if [ "$sig_http" != "200" ]; then
    if [ "$REQUIRE_SIG" = "1" ]; then echo "  ! release signature required but not served"; return 1; fi
    echo "  ! this release is unsigned — proceeding (set up release signing to enforce)"; return 0
  fi
  # Canonical digest = the {{name: sha256}} map as compact sorted JSON — must match
  # release_signing.canonical_files_digest on the server.
  if ! command -v python3 >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    echo "  ! python3+openssl needed to verify the signature"; [ "$REQUIRE_SIG" = "1" ] && return 1 || return 0
  fi
  python3 - "$TMP/manifest.json" > "$TMP/digest" <<'PY'
import json, sys
files = json.load(open(sys.argv[1]))["files"]
sys.stdout.write(json.dumps({{k: v["sha256"] for k, v in files.items()}},
                            separators=(",", ":"), sort_keys=True))
PY
  printf '%s' "$PALIVANE_RELEASE_PUBKEY" > "$TMP/pub.pem"
  openssl base64 -d -A -in "$TMP/manifest.sig" -out "$TMP/sig.der" 2>/dev/null || {{ echo "  ! bad signature encoding"; return 1; }}
  # ECDSA P-256 / SHA-256 — verifiable by the stock openssl dgst CLI on any machine.
  if openssl dgst -sha256 -verify "$TMP/pub.pem" -signature "$TMP/sig.der" "$TMP/digest" >/dev/null 2>&1; then
    echo "  ✓ release signature verified"
  else
    echo "  ✗ release signature INVALID — refusing to install (possible tampering)"; return 1
  fi
  return 0
}}

file_matches_manifest() {{  # $1=name $2=path ; needs $TMP/manifest.json
  [ -f "$TMP/manifest.json" ] || return 0   # no manifest fetched (unsigned/offline path)
  command -v python3 >/dev/null 2>&1 || return 0
  local want got
  want="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["files"].get(sys.argv[2],{{}}).get("sha256",""))' "$TMP/manifest.json" "$1")"
  [ -n "$want" ] || return 0
  got="$(sha256_of "$2")"
  [ "$want" = "$got" ]
}}

echo "Verifying release integrity ..."
verify_release || {{ echo "Aborting install."; exit 1; }}

echo "Installing Palivane CLI into $BIN ..."
# Stage + verify EVERYTHING before touching $BIN: a hash mismatch on any file must leave
# no partial install behind, not just block the one tampered file.
for t in $TOOLS; do
  curl -fsSL "$PALIVANE_URL/cli/$t" -o "$TMP/$t"
  if ! file_matches_manifest "$t" "$TMP/$t"; then
    echo "  ✗ $t failed its SHA-256 check — refusing to install (possible tampering)"; exit 1
  fi
done
mkdir -p "$BIN"
for t in $TOOLS; do install -m 0755 "$TMP/$t" "$BIN/$t"; done
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
  printf 'fish_add_path -g "$HOME/.palivane/bin"\\n' > "$HOME/.config/fish/conf.d/palivane.fish"
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
# In-tab browser capture is the one plane this script cannot install. Chrome requires a
# user gesture to add a Web Store item — there is no supported headless path short of an
# enterprise managed policy, which is a system-wide change and belongs to MDM (see
# docs/mdm-policy-pack.md), not to a piped shell script. So: say so, and make it one click.
if [ -n "$PALIVANE_EXT_URL" ]; then
  echo ""
  echo "One more surface — the browser extension (what people paste into ChatGPT et al):"
  echo "  $PALIVANE_EXT_URL"
  # `curl … | bash` leaves stdin pointing at the script, so a bare `read` returns EOF
  # immediately and would silently answer for the user. Read the answer from the terminal
  # instead, and only when there is one and a desktop to open a browser on.
  if [ -e /dev/tty ] && {{ [ -n "${{DISPLAY:-}}" ] || [ -n "${{WAYLAND_DISPLAY:-}}" ] || [ "$(uname)" = "Darwin" ]; }}; then
    printf "Open the store page now? [y/N] "
    if read -r _ans < /dev/tty 2>/dev/null; then
      case "$_ans" in
        y|Y|yes|YES)
          if [ "$(uname)" = "Darwin" ]; then open "$PALIVANE_EXT_URL" >/dev/null 2>&1 || true
          else xdg-open "$PALIVANE_EXT_URL" >/dev/null 2>&1 || true
          fi ;;
      esac
    fi
  fi
fi
echo ""
echo "Done. Open a new terminal (or 'source ~/.zshrc') so 'palivane-connect' is on PATH."
[ "$PROXY_MODE" = "desktop" ] && echo "Desktop apps + browsers are governed system-wide."
[ "$PROXY_MODE" = "none" ] && echo "To also govern AI CLIs:  palivane-desktop install --cli-only   (or --desktop for system-wide)"
"""
    return PlainTextResponse(script, media_type="text/x-shellscript")
