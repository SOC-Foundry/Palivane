#!/usr/bin/env bash
# Debian smoke test for the Palivane device installer.
#
# Answers "does the endpoint installer actually work on Debian?" by exercising the REAL
# installer functions from cli/palivane-desktop — sourced with its command dispatcher
# stripped — against the Debian-specific OS-integration paths that are the actual
# portability risk:
#   * system CA trust via update-ca-certificates (/usr/local/share/ca-certificates)
#   * NSS trust via certutil (libnss3-tools) — how Chromium/Electron desktop apps trust it
#   * session proxy env drop (~/.config/environment.d)
#   * CLI-capture PATH shims
# plus prerequisite presence and a `bash -n` parse of every shipped CLI tool.
#
# It runs each real function in a sandboxed $HOME with a throwaway self-signed test CA, so
# it never needs enrollment, a running backend, a desktop session, or the real mitmproxy.
# Things that genuinely need a logged-in Debian desktop (the systemd --user proxy service,
# `palivane connect` sign-in, live desktop-app capture) are reported as SKIP with the reason
# — this harness proves the mechanisms, not a full end-to-end capture.
#
# Run it inside a Debian box (or use debian-smoke-docker.sh to spin one up from any host):
#   sudo ./deploy/native/debian-smoke.sh
#   PALIVANE_URL=https://palivane.tachtech.net sudo ./deploy/native/debian-smoke.sh   # also probe the served install.sh
#
# Exit status is non-zero if any check FAILs (SKIPs don't fail). Root is required for the
# system-CA-trust checks; without it those SKIP.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
DESKTOP="$REPO/cli/palivane-desktop"
PALIVANE_URL="${PALIVANE_URL:-}"

pass=0 fail=0 skip=0
c() { printf '\033[36m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m[PASS]\033[0m %s\n' "$*"; pass=$((pass+1)); }
bad()  { printf '  \033[31m[FAIL]\033[0m %s\n' "$*"; fail=$((fail+1)); }
skp()  { printf '  \033[33m[SKIP]\033[0m %s\n' "$*"; skip=$((skip+1)); }

[ -f "$DESKTOP" ] || { echo "cannot find cli/palivane-desktop under $REPO" >&2; exit 2; }

# --- 0) distro identity -----------------------------------------------------------------
c "== Debian installer smoke test =="
if [ -r /etc/os-release ]; then
  . /etc/os-release
  echo "  target: ${PRETTY_NAME:-unknown}  (kernel $(uname -r), arch $(uname -m))"
  case "${ID:-}${ID_LIKE:-}" in
    *debian*|*ubuntu*) : ;;
    *) printf '  \033[33mnote: not a Debian-family distro; the update-ca-certificates checks may not apply.\033[0m\n' ;;
  esac
fi
ROOT=0; [ "$(id -u)" = 0 ] && ROOT=1

# --- 1) prerequisites -------------------------------------------------------------------
c "1) prerequisites"
have() { command -v "$1" >/dev/null 2>&1; }
ver() { case "$1" in openssl) openssl version 2>&1 ;; *) "$1" --version 2>&1 ;; esac; }
for tool in curl openssl python3 update-ca-certificates; do
  if have "$tool"; then ok "$tool present ($(ver "$tool" | head -1 | cut -c1-48))"
  else bad "$tool MISSING — required on Debian for the installer"; fi
done
if have certutil; then ok "certutil present (libnss3-tools) — desktop-app (Chromium/Electron) CA trust supported"
else skp "certutil MISSING — install libnss3-tools, else Claude/ChatGPT-desktop capture won't work (CLI governance still does)"; fi
have sudo || { [ "$ROOT" = 1 ] && ok "sudo absent but running as root — system-trust checks can proceed" \
                                || skp "sudo absent and not root — system-CA-trust checks will SKIP"; }

# --- 2) shipped-script syntax (bash -n) -------------------------------------------------
c "2) shipped CLI scripts parse under Debian bash"
syntax_fail=0
for f in "$DESKTOP" "$REPO"/cli/palivane-connect "$REPO"/cli/palivane-hook \
         "$REPO"/cli/palivane-reenroll "$REPO"/cli/palivane-mcp "$REPO"/deploy/native/install.sh; do
  [ -f "$f" ] || continue
  head -1 "$f" | grep -q 'bash' || continue     # only bash scripts (skip .ps1 / python)
  if bash -n "$f" 2>/dev/null; then ok "bash -n $(basename "$f")"; else bad "PARSE ERROR: $(basename "$f")"; syntax_fail=1; fi
done

# --- source the REAL installer functions (strip the trailing command dispatcher) --------
SANDBOX="$(mktemp -d)"; export HOME="$SANDBOX/home"; mkdir -p "$HOME"
trap 'rm -rf "$SANDBOX"' EXIT
FUNCS="$SANDBOX/palivane-desktop.funcs"
sed '/^case "\${1:-install}"/,$d' "$DESKTOP" > "$FUNCS"
# shellcheck disable=SC1090
if source "$FUNCS" 2>/dev/null; then set +eu; c "loaded real installer functions from cli/palivane-desktop"
else set +eu; echo "  could not source installer functions" >&2; fi

# A throwaway self-signed CA at the exact path bootstrap_ca would produce.
mkdir -p "$(dirname "$CA")"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$SANDBOX/ca.key" -out "$CA" \
  -days 1 -subj "/CN=palivane-smoke-test-CA" >/dev/null 2>&1
[ -f "$CA" ] && c "generated throwaway test CA at \$CA" || { bad "could not generate test CA (openssl)"; }
CA_FPR="$(openssl x509 -in "$CA" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"

# --- 3) system CA trust via update-ca-certificates (THE Debian path) --------------------
c "3) system CA trust — update-ca-certificates (Debian trust store)"
if [ "$ROOT" != 1 ] && ! have sudo; then
  skp "need root/sudo — system CA trust not exercised"
elif ! have update-ca-certificates; then
  skp "update-ca-certificates absent — not a Debian-family trust store"
else
  ( trust_ca_system ) >/dev/null 2>&1
  if [ -f /usr/local/share/ca-certificates/palivane-mitmproxy.crt ]; then
    ok "installer dropped the CA into /usr/local/share/ca-certificates"
  else bad "CA not placed in /usr/local/share/ca-certificates"; fi
  # The real proof: the cert now lives in the system bundle curl/git read.
  if openssl x509 -in "$CA" -noout -fingerprint -sha256 2>/dev/null | grep -qf <(printf '%s' "$CA_FPR") \
     && grep -qs "palivane-smoke-test-CA" <(openssl storeutl -noout -text -certs /etc/ssl/certs/ca-certificates.crt 2>/dev/null || \
        awk 'BEGIN{c=""} /BEGIN CERT/{c=""} {c=c$0"\n"} /END CERT/{print c | "openssl x509 -noout -subject 2>/dev/null"}' /etc/ssl/certs/ca-certificates.crt 2>/dev/null); then
    ok "CA is now in the system bundle (/etc/ssl/certs/ca-certificates.crt) — system-trust clients accept it"
  else
    # Fallback proof: openssl verify a leaf-less check by trusting the bundle dir.
    if awk '/BEGIN CERT/{f=1} f{print} /END CERT/{f=0}' /etc/ssl/certs/ca-certificates.crt 2>/dev/null \
         | grep -qF "$(openssl x509 -in "$CA" -outform pem 2>/dev/null | sed -n '2p')"; then
      ok "CA present in the system bundle (matched by PEM body)"
    else bad "CA did NOT make it into /etc/ssl/certs/ca-certificates.crt after update-ca-certificates"; fi
  fi
  # Reverse it — uninstall must clean the system store.
  ( untrust_ca_system ) >/dev/null 2>&1
  if [ ! -f /usr/local/share/ca-certificates/palivane-mitmproxy.crt ]; then
    ok "uninstall path removed the CA from the Debian trust store"
  else bad "untrust left the CA behind in /usr/local/share/ca-certificates"; fi
fi

# --- 4) NSS trust via certutil (Chromium/Electron desktop apps) -------------------------
c "4) NSS trust — certutil (how desktop apps trust the proxy CA)"
if ! have certutil; then
  skp "certutil absent (libnss3-tools) — desktop-app CA trust path not exercised"
else
  ( nss_trust_ca ) >/dev/null 2>&1
  if certutil -d "$NSS_DB" -L 2>/dev/null | grep -q "$CA_NICK"; then
    ok "installer added the CA to the per-user NSS store as '$CA_NICK'"
  else bad "CA not found in the NSS store after nss_trust_ca"; fi
  ( nss_untrust_ca ) >/dev/null 2>&1
  if ! certutil -d "$NSS_DB" -L 2>/dev/null | grep -q "$CA_NICK"; then
    ok "uninstall path removed the CA from the NSS store"
  else bad "CA still in the NSS store after nss_untrust_ca"; fi
fi

# --- 5) session proxy env drop ----------------------------------------------------------
c "5) session proxy env (~/.config/environment.d)"
( set_session_proxy_env ) >/dev/null 2>&1
ENVCONF="$HOME/.config/environment.d/palivane-proxy.conf"
if [ -f "$ENVCONF" ] && grep -q '^https_proxy=http://127.0.0.1:' "$ENVCONF"; then
  ok "installer wrote the session proxy env file GUI apps inherit at login"
else bad "session proxy env file missing or malformed ($ENVCONF)"; fi
( unset_session_proxy_env ) >/dev/null 2>&1
[ ! -f "$ENVCONF" ] && ok "uninstall path removed the session proxy env file" \
                    || bad "session proxy env file left behind after unset"

# --- 6) CLI-capture PATH shims ----------------------------------------------------------
c "6) CLI-capture PATH shims"
FAKEBIN="$SANDBOX/fakebin"; mkdir -p "$FAKEBIN"
printf '#!/usr/bin/env bash\necho real-claude\n' > "$FAKEBIN/claude"; chmod +x "$FAKEBIN/claude"
( PATH="$FAKEBIN:$PATH" CLI_SHIM_TOOLS="claude" wire_cli_capture ) >/dev/null 2>&1
if [ -f "$SHIM_DIR/claude" ] && grep -q 'palivane-desktop CLI capture shim' "$SHIM_DIR/claude"; then
  ok "installer wired a fail-open capture shim for 'claude'"
  grep -q 'fail-open' "$SHIM_DIR/claude" && ok "shim is fail-open (dead proxy -> tool still runs)" \
                                         || bad "shim missing fail-open guard"
else bad "no CLI capture shim created in $SHIM_DIR"; fi

# --- 7) served install.sh (optional; needs a reachable backend) -------------------------
c "7) served bootstrap installer (install.sh)"
if [ -z "$PALIVANE_URL" ]; then
  skp "PALIVANE_URL unset — not probing the served /install.sh (set it to a reachable backend)"
elif ! curl -fsS --max-time 10 "$PALIVANE_URL/install.sh" -o "$SANDBOX/install.sh" 2>/dev/null; then
  skp "could not fetch $PALIVANE_URL/install.sh (backend unreachable)"
else
  if bash -n "$SANDBOX/install.sh" 2>/dev/null; then ok "served install.sh parses under Debian bash"; else bad "served install.sh has a parse error"; fi
  grep -q 'palivane/bin' "$SANDBOX/install.sh" && ok "served install.sh targets ~/.palivane/bin as expected" \
                                               || bad "served install.sh does not reference ~/.palivane/bin"
  skp "full 'curl install.sh | bash' not run — it needs 'palivane connect' enrollment (sign-in)"
fi

# --- things that genuinely need a real Debian desktop -----------------------------------
c "not exercised here (need a logged-in Debian desktop / backend):"
skp "systemd --user proxy service (start_service) — needs a user session + D-Bus"
skp "'palivane connect' enrollment — interactive browser sign-in"
skp "live desktop-app (Claude/ChatGPT desktop) capture — needs the GUI apps + a session"

# --- summary ----------------------------------------------------------------------------
printf '\n\033[36m== summary ==\033[0m  \033[32m%d passed\033[0m, \033[31m%d failed\033[0m, \033[33m%d skipped\033[0m\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ] && { echo "RESULT: PASS — the Debian installer mechanisms work on this box."; exit 0; } \
                  || { echo "RESULT: FAIL — $fail installer check(s) failed on this Debian box."; exit 1; }
