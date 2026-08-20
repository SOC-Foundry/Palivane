#!/usr/bin/env bash
# Smoke test for the Palivane device installer, across BOTH Linux trust-store families.
#
# Answers "does the endpoint installer actually work on this distro?" by exercising the REAL
# installer functions from cli/palivane-desktop (sourced with its command dispatcher
# stripped) against the OS-integration paths that are the actual portability risk:
#   * system CA trust — update-ca-certificates (Debian/Ubuntu) OR update-ca-trust (the
#     p11-kit distros: Fedora/RHEL, Arch, openSUSE); proven by signing a leaf with the test
#     CA and `openssl verify`ing it against the DEFAULT trust store (family-agnostic)
#   * NSS trust via certutil (nss-tools / libnss3-tools) — how Chromium/Electron desktop apps trust it
#   * session proxy env drop (~/.config/environment.d)
#   * CLI-capture PATH shims (fail-open)
# plus prerequisite presence and a `bash -n` parse of every shipped CLI tool.
#
# Each real function runs in a sandboxed $HOME with a throwaway self-signed test CA, so it
# needs no enrollment, backend, desktop session, or real mitmproxy. Parts that genuinely
# need a logged-in desktop (systemd --user proxy service, `palivane connect` sign-in, live
# desktop-app capture) are reported SKIP with the reason — this proves the mechanisms.
#
# Run inside the target distro (or use installer-smoke-docker.sh to spin up a matrix):
#   sudo ./deploy/native/installer-smoke.sh
#   PALIVANE_URL=https://app.palivane.io sudo ./deploy/native/installer-smoke.sh
#
# Exit non-zero if any check FAILs (SKIPs don't fail). Root is required for system CA trust.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
DESKTOP="$REPO/cli/palivane-desktop"
PALIVANE_URL="${PALIVANE_URL:-}"

pass=0 fail=0 skip=0
c() { printf '\033[36m%s\033[0m\n' "$*"; }
ok()  { printf '  \033[32m[PASS]\033[0m %s\n' "$*"; pass=$((pass+1)); }
bad() { printf '  \033[31m[FAIL]\033[0m %s\n' "$*"; fail=$((fail+1)); }
skp() { printf '  \033[33m[SKIP]\033[0m %s\n' "$*"; skip=$((skip+1)); }

[ -f "$DESKTOP" ] || { echo "cannot find cli/palivane-desktop under $REPO" >&2; exit 2; }

# --- 0) distro + trust-store family -----------------------------------------------------
c "== Palivane installer smoke test =="
[ -r /etc/os-release ] && . /etc/os-release
echo "  target: ${PRETTY_NAME:-unknown}  (kernel $(uname -r), arch $(uname -m))"
ROOT=0; [ "$(id -u)" = 0 ] && ROOT=1

# Mirror cli/palivane-desktop's own family detection so we assert the right anchor path.
P11KIT_ANCHOR_DIRS="/etc/ca-certificates/trust-source/anchors /etc/pki/ca-trust/source/anchors /etc/pki/trust/anchors"
detect_family() {
  if command -v update-ca-certificates >/dev/null 2>&1 && [ -d /usr/local/share/ca-certificates ]; then
    echo "debian"
  elif command -v update-ca-trust >/dev/null 2>&1; then
    echo "p11kit"
  else
    echo "none"
  fi
}
p11kit_dir() { local d; for d in $P11KIT_ANCHOR_DIRS; do [ -d "$d" ] && { echo "$d"; return; }; done; echo "/etc/ca-certificates/trust-source/anchors"; }
FAMILY="$(detect_family)"
echo "  trust-store family: $FAMILY"

# --- 1) prerequisites -------------------------------------------------------------------
c "1) prerequisites"
have() { command -v "$1" >/dev/null 2>&1; }
ver() { case "$1" in openssl) openssl version 2>&1 ;; *) "$1" --version 2>&1 ;; esac; }
for tool in curl openssl python3; do
  if have "$tool"; then ok "$tool present ($(ver "$tool" | head -1 | cut -c1-48))"
  else bad "$tool MISSING — required for the installer"; fi
done
case "$FAMILY" in
  debian) ok "system-CA tool: update-ca-certificates (Debian/Ubuntu)" ;;
  p11kit) ok "system-CA tool: update-ca-trust (p11-kit; anchors $(p11kit_dir))" ;;
  none)   bad "no system-CA tool (update-ca-certificates / update-ca-trust) — CLIs won't trust the proxy CA" ;;
esac
if have certutil; then ok "certutil present — desktop-app (Chromium/Electron) CA trust supported"
else skp "certutil MISSING — install nss-tools/libnss3-tools, else Claude/ChatGPT-desktop capture won't work (CLI governance still does)"; fi
have sudo || { [ "$ROOT" = 1 ] && ok "sudo absent but running as root — system-trust checks can proceed" \
                                || skp "sudo absent and not root — system-CA-trust checks will SKIP"; }

# --- 2) shipped-script syntax (bash -n) -------------------------------------------------
c "2) shipped CLI scripts parse under this distro's bash"
for f in "$DESKTOP" "$REPO"/cli/palivane-connect "$REPO"/cli/palivane-hook \
         "$REPO"/cli/palivane-reenroll "$REPO"/cli/palivane-mcp "$REPO"/deploy/native/install.sh; do
  [ -f "$f" ] || continue
  head -1 "$f" | grep -q 'bash' || continue
  if bash -n "$f" 2>/dev/null; then ok "bash -n $(basename "$f")"; else bad "PARSE ERROR: $(basename "$f")"; fi
done

# --- source the REAL installer functions (strip the trailing command dispatcher) --------
SANDBOX="$(mktemp -d)"; export HOME="$SANDBOX/home"; mkdir -p "$HOME"
trap 'rm -rf "$SANDBOX"' EXIT
FUNCS="$SANDBOX/palivane-desktop.funcs"
sed '/^case "\${1:-install}"/,$d' "$DESKTOP" > "$FUNCS"
# shellcheck disable=SC1090
source "$FUNCS" 2>/dev/null || echo "  could not source installer functions" >&2
set +eu
c "loaded real installer functions from cli/palivane-desktop"

# Throwaway CA (at the exact path bootstrap_ca produces) + a leaf signed by it. Trust is
# proven by verifying the leaf against the DEFAULT store — works for every family/bundle.
mkdir -p "$(dirname "$CA")"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$SANDBOX/ca.key" -out "$CA" -days 1 \
  -subj "/CN=palivane-smoke-test-CA" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
LEAF="$SANDBOX/leaf.crt"
openssl req -newkey rsa:2048 -nodes -keyout "$SANDBOX/leaf.key" -out "$SANDBOX/leaf.csr" \
  -subj "/CN=leaf.palivane-smoke.test" >/dev/null 2>&1
openssl x509 -req -in "$SANDBOX/leaf.csr" -CA "$CA" -CAkey "$SANDBOX/ca.key" \
  -CAcreateserial -out "$LEAF" -days 1 >/dev/null 2>&1
[ -f "$CA" ] && [ -f "$LEAF" ] && c "generated throwaway test CA + leaf" || bad "could not generate test CA/leaf (openssl)"
verify_leaf() { openssl verify "$LEAF" >/dev/null 2>&1; }   # default store = system trust

# --- 3) system CA trust (family-aware; proven by openssl verify) ------------------------
c "3) system CA trust — $FAMILY (installer trust_ca_system)"
if [ "$ROOT" != 1 ] && ! have sudo; then
  skp "need root/sudo — system CA trust not exercised"
elif [ "$FAMILY" = "none" ]; then
  bad "no supported system-CA tool on this distro — installer can't establish system trust"
else
  verify_leaf && skp "leaf already verifies before trust (unexpected) — skipping trust assertion" || {
    ( trust_ca_system ) >/dev/null 2>&1
    # a) the anchor file landed in the family's directory
    case "$FAMILY" in
      debian) anchor="/usr/local/share/ca-certificates/palivane-mitmproxy.crt" ;;
      p11kit) anchor="$(p11kit_dir)/palivane-mitmproxy.crt" ;;
    esac
    [ -f "$anchor" ] && ok "installer placed the CA anchor at $anchor" || bad "CA anchor not found at $anchor"
    # b) the real proof: a cert signed by our CA now verifies against the DEFAULT trust store
    if verify_leaf; then ok "CA is trusted system-wide (openssl verify of a CA-signed leaf succeeds)"
    else bad "CA NOT trusted after $([ "$FAMILY" = debian ] && echo update-ca-certificates || echo 'update-ca-trust extract') — system-trust clients would reject the proxy"; fi
    # c) uninstall reverses it
    ( untrust_ca_system ) >/dev/null 2>&1
    [ ! -f "$anchor" ] && ok "uninstall removed the CA anchor" || bad "untrust left the anchor behind ($anchor)"
    verify_leaf && bad "CA still trusted after untrust — uninstall did not clean the trust store" \
                || ok "CA no longer trusted after uninstall (verify fails, as expected)"
  }
fi

# --- 4) NSS trust via certutil (Chromium/Electron desktop apps) -------------------------
c "4) NSS trust — certutil (desktop-app CA trust)"
if ! have certutil; then
  skp "certutil absent — desktop-app CA trust path not exercised"
else
  ( nss_trust_ca ) >/dev/null 2>&1
  certutil -d "$NSS_DB" -L 2>/dev/null | grep -q "$CA_NICK" \
    && ok "installer added the CA to the per-user NSS store as '$CA_NICK'" \
    || bad "CA not in the NSS store after nss_trust_ca"
  ( nss_untrust_ca ) >/dev/null 2>&1
  certutil -d "$NSS_DB" -L 2>/dev/null | grep -q "$CA_NICK" \
    && bad "CA still in NSS store after nss_untrust_ca" \
    || ok "uninstall removed the CA from the NSS store"
fi

# --- 5) session proxy env drop ----------------------------------------------------------
c "5) session proxy env (~/.config/environment.d)"
( set_session_proxy_env ) >/dev/null 2>&1
ENVCONF="$HOME/.config/environment.d/palivane-proxy.conf"
[ -f "$ENVCONF" ] && grep -q '^https_proxy=http://127.0.0.1:' "$ENVCONF" \
  && ok "installer wrote the session proxy env file GUI apps inherit at login" \
  || bad "session proxy env file missing or malformed ($ENVCONF)"
( unset_session_proxy_env ) >/dev/null 2>&1
[ ! -f "$ENVCONF" ] && ok "uninstall removed the session proxy env file" || bad "session proxy env file left behind"

# --- 6) CLI-capture PATH shims ----------------------------------------------------------
c "6) CLI-capture PATH shims"
FAKEBIN="$SANDBOX/fakebin"; mkdir -p "$FAKEBIN"
printf '#!/usr/bin/env bash\necho real-claude\n' > "$FAKEBIN/claude"; chmod +x "$FAKEBIN/claude"
( PATH="$FAKEBIN:$PATH" CLI_SHIM_TOOLS="claude" wire_cli_capture ) >/dev/null 2>&1
if [ -f "$SHIM_DIR/claude" ] && grep -q 'palivane-desktop CLI capture shim' "$SHIM_DIR/claude"; then
  ok "installer wired a capture shim for 'claude'"
  grep -q 'fail-open' "$SHIM_DIR/claude" && ok "shim is fail-open (dead proxy -> tool still runs)" || bad "shim missing fail-open guard"
else bad "no CLI capture shim created in $SHIM_DIR"; fi

# --- 7) served install.sh (optional; needs a reachable backend) -------------------------
c "7) served bootstrap installer (install.sh)"
if [ -z "$PALIVANE_URL" ]; then
  skp "PALIVANE_URL unset — not probing the served /install.sh"
elif ! curl -fsS --max-time 10 "$PALIVANE_URL/install.sh" -o "$SANDBOX/install.sh" 2>/dev/null; then
  skp "could not fetch $PALIVANE_URL/install.sh (backend unreachable)"
else
  bash -n "$SANDBOX/install.sh" 2>/dev/null && ok "served install.sh parses" || bad "served install.sh has a parse error"
  grep -q 'palivane/bin' "$SANDBOX/install.sh" && ok "served install.sh targets ~/.palivane/bin" || bad "served install.sh does not reference ~/.palivane/bin"
  skp "full 'curl install.sh | bash' not run — needs 'palivane connect' enrollment"
fi

# --- needs a real logged-in desktop -----------------------------------------------------
c "not exercised here (need a logged-in desktop / backend):"
skp "systemd --user proxy service (start_service) — needs a user session + D-Bus"
skp "'palivane connect' enrollment — interactive browser sign-in"
skp "live desktop-app (Claude/ChatGPT desktop) capture — needs the GUI apps + a session"

printf '\n\033[36m== summary (%s / %s) ==\033[0m  \033[32m%d passed\033[0m, \033[31m%d failed\033[0m, \033[33m%d skipped\033[0m\n' \
  "${ID:-?}" "$FAMILY" "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ] && { echo "RESULT: PASS — the installer mechanisms work on this distro."; exit 0; } \
                  || { echo "RESULT: FAIL — $fail installer check(s) failed."; exit 1; }
