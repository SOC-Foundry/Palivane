# Deploying Warden for Claude (browser, Claude Code, desktop)

This guide covers governing the three ways your org uses Claude:

| Surface | How it reaches Claude | Capture plane | Section |
| --- | --- | --- | --- |
| **claude.ai in a browser** | Chrome/Edge tab | Browser extension | [1](#1-claudeai-in-the-browser) |
| **Claude Code (CLI/IDE)** | `api.anthropic.com` via the CLI | LLM gateway (or proxy) | [2](#2-claude-code) |
| **Claude desktop app** | its own HTTPS to Anthropic | Egress proxy | [3](#3-claude-desktop-app) |

All three feed the same Warden engine, tenant, and dashboard. Each call is scored for
**prompt injection / jailbreak / exfiltration** (attacks on the model) and **PII /
secrets** (data leaving), and either recorded (monitor) or blocked inline (enforce).

---

## Prerequisites (once)

1. **Run Warden.** From the repo root:
   ```bash
   cp .env.docker.example .env       # set WARDEN_SECRET_KEY (openssl rand -hex 32)
   docker compose up --build         # API+UI at http://<host>:8080 (8090 in our dev setup)
   ```
   Put it on an internal host behind your SSO/reverse proxy. Use Postgres (the compose
   default), not SQLite.

2. **Create a tenant + admin** (if not using the seeded demo):
   ```bash
   docker compose exec backend python -m app.users create-tenant --slug acme --name "Acme"
   docker compose exec backend python -m app.users create-user --tenant acme --email soc@acme.com --role admin
   ```

3. **Set the shared ingest token** (used by the extension and the proxy) and the tenant
   in `.env`, then restart the backend:
   ```bash
   EXTENSION_INGEST_TOKEN=$(openssl rand -hex 24)
   INGEST_TENANT=acme
   ```

4. **Decide monitor vs enforce.** Start in monitor mode (`GATEWAY_ENFORCE=false`), watch
   findings for a week, tune, then flip to enforce. See [Rollout](#rollout).

Log in at the UI as the admin to get a token (`POST /api/auth/login`) for the admin
calls below, or use the dashboard.

---

## 1. claude.ai in the browser

**Plane:** the Manifest V3 extension in [`extension/`](../extension/). It intercepts the
prompt *before send*, scores it, and warns/blocks. Covers managed browsers.

### Backend
Already done in prerequisites — `EXTENSION_INGEST_TOKEN` + `INGEST_TENANT` are what the
extension authenticates with.

### Install (pilot / single machine)
1. `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select the
   `extension/` folder.
2. Open the extension's **Options** and set:
   - **Backend URL**: `https://warden.corp.example.com`
   - **Ingest token**: the `EXTENSION_INGEST_TOKEN` value
   - **Enforce**: on to block, off to warn only
3. Visit `https://claude.ai`, submit a prompt with a fake SSN `123-45-6789` and an
   `AKIA…` key — it should be blocked with a red banner.

### Roll out fleet-wide (Chrome/Edge enterprise) — zero-touch
1. Build the package: `extension/build.sh` → a zip for the Chrome Web Store / Edge
   Add-ons (private/unlisted) or a self-hosted CRX.
2. **Force-install** via policy `ExtensionInstallForcelist` (Intune/Workspace/GPO) — it
   installs automatically, no user action.
3. **Configure centrally** via managed storage (`3rdparty/extensions/<id>/policy`); the
   extension's `managed_schema.json` applies these and they **override** user settings:
   ```json
   {
     "backendUrl": { "Value": "https://warden.corp.example.com" },
     "token":      { "Value": "<EXTENSION_INGEST_TOKEN>" },
     "enforce":    { "Value": true }
   }
   ```
   Result: managed devices install **and** configure the extension with zero interaction.

**Covers:** managed browsers. Personal/unmanaged browsers are caught only by the network
proxy (Section 3) or surfaced by [coverage reconciliation](#verify-coverage).

---

## 2. Claude Code

Two routes. The **gateway** is recommended (no certificates, one config block); the
**proxy** is the fallback when you can't repoint the base URL.

### Route A — gateway (recommended)

**Backend** `.env`:
```bash
GATEWAY_ENFORCE=true                 # or false to start in monitor mode
GATEWAY_BLOCK_SEVERITY=high
GATEWAY_ANTHROPIC_KEY=sk-ant-...      # the REAL Anthropic key, server-side only
# GATEWAY_ANTHROPIC_BASE defaults to https://api.anthropic.com
```

**Mint an API key per developer** (so findings attribute to them):
```bash
curl -X POST https://warden.corp.example.com/api/apikeys \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"label":"alice-laptop","actor":"alice@acme.com"}'   # token shown once: ak_...
```

**Deploy to developer machines** via Claude Code's enterprise `managed-settings.json`
(highest precedence — users can't override). Paths:
- macOS: `/Library/Application Support/ClaudeCode/managed-settings.json`
- Linux/WSL: `/etc/claude-code/managed-settings.json`
- Windows: `C:\Program Files\ClaudeCode\managed-settings.json`

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "https://warden.corp.example.com/v1",
    "ANTHROPIC_AUTH_TOKEN": "ak_<the developer's Warden key>"
  }
}
```
- `ANTHROPIC_AUTH_TOKEN` is sent as `Authorization: Bearer`; `ANTHROPIC_API_KEY` would be
  sent as `x-api-key` — the gateway accepts either. For per-user keys without baking them
  into the file, use Claude Code's `apiKeyHelper` to fetch the key dynamically.
- The gateway implements `/v1/messages`, `/v1/messages/count_tokens`, and forwards the
  `anthropic-version`/`anthropic-beta` headers, so Claude Code works fully.
- Per-tool policy auto-suppresses `source_code_leak` for `claude-code` (code is its job),
  while **secrets and PII are still blocked**.

> Setting a custom `ANTHROPIC_BASE_URL` disables MCP tool-search by default — set
> `ENABLE_TOOL_SEARCH=true` in the same `env` block if you rely on it.

### Route B — egress proxy (no base-URL change)
Use the proxy (Section 3) and set, in the same `managed-settings.json`:
```json
{ "env": {
  "HTTPS_PROXY": "http://warden-proxy.corp:8081",
  "NODE_EXTRA_CA_CERTS": "/etc/ssl/certs/corp-ca.pem"
} }
```
Claude Code honors both. This catches Claude Code *and* everything else on the device.

---

## 3. Claude Desktop app (macOS & Windows)

The desktop app makes its own HTTPS calls to `api.anthropic.com` and has **no
custom-base-URL setting**, so it can't use the gateway (Section 2) — it's captured at the
**network egress** with the [`proxy/`](../proxy/) mitmproxy addon. This section is for the
**official macOS/Windows** app (it's Electron, and on those OSes it uses the **system
proxy** and the **OS certificate store** natively — which is what makes this work cleanly
and MDM-deployable). Linux community builds are out of scope.

> Scope note: this is the awkward surface. Prefer governing Claude via the **gateway**
> (Claude Code / SDKs) and the **browser extension** — those cooperate at the app layer.
> Use the desktop proxy only where you must, and lean on your **existing corporate
> proxy/SWG** if you already run one rather than standing up a per-device Warden proxy.

### Run the proxy (once, near your egress)
```bash
pip install mitmproxy
WARDEN_URL=https://warden.corp.example.com \
WARDEN_TOKEN=$EXTENSION_INGEST_TOKEN \
WARDEN_PROXY_ENFORCE=true \
mitmdump -s proxy/warden_addon.py --listen-port 8081
```
(`WARDEN_TOKEN` is the `EXTENSION_INGEST_TOKEN` from prerequisites, or a per-tenant
`ak_…` key. Run it as a service and scale horizontally — the addon is stateless.)

### Single machine (pilot / testing)

**macOS**
1. Copy `~/.mitmproxy/mitmproxy-ca-cert.pem` from the proxy host to the Mac, then trust it:
   ```bash
   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain mitmproxy-ca-cert.pem
   ```
2. Point the system HTTPS proxy at the proxy host: **System Settings → Network → (interface)
   → Details → Proxies → Secure Web Proxy (HTTPS)** = `PROXY_HOST:8081`.
3. Fully quit and reopen Claude Desktop → send a fake secret (`SSN 123-45-6789
   AKIAABCDEFGHIJKLMNOP`) → it should be blocked; the request shows in the proxy log and a
   finding appears in Warden.

**Windows**
1. Import the CA to Trusted Root:
   ```powershell
   Import-Certificate -FilePath mitmproxy-ca-cert.pem -CertStoreLocation Cert:\LocalMachine\Root
   ```
2. **Settings → Network & internet → Proxy → Manual proxy** = `PROXY_HOST:8081` (HTTPS).
3. Restart Claude Desktop and test as above.

### Fleet rollout (MDM — the real deployment)
Don't configure machines by hand; push both via MDM (Intune / Jamf / GPO):
1. **CA** — deploy the mitmproxy/corporate root CA to the device **system trust store**
   (Intune *Trusted Certificate* profile; Jamf *Certificate* payload; GPO *Trusted Root*).
2. **Proxy** — push a system proxy or **PAC file** scoped to AI domains
   (Intune/Jamf network-proxy profile; GPO WinHTTP/WinINET). Claude Desktop inherits it.

On managed devices this is transparent — the app already trusts the CA and uses the system
proxy, so no per-app config.

### Caveats (read these)
- **Certificate pinning is the wildcard.** The proxy needs TLS inspection; if Claude
  Desktop pins `api.anthropic.com`, it refuses the inspected cert and either errors or
  bypasses — unfixable at the network layer. **Confirm with the single-machine test before
  committing to a fleet rollout.** If a chat *works but Warden sees nothing*, the app is
  bypassing the proxy (routing/config); if it *fails to connect after the CA is trusted*,
  it's pinning.
- **Fail-open:** if Warden is unreachable the proxy lets traffic through, so an outage
  never blocks the company's AI access.
- **Hard-deny posture:** the proxy scans the full transcript, so a secret can't slip
  through on a later replayed turn; the user starts a new chat to clear it (blocks return
  `400` with a "start a new chat" message).

---

## Verify coverage

You can't monitor a device you don't manage — find the gap by what's missing. Export
your IdP/CASB list of who accessed Claude/AI domains and reconcile it against captured
findings:

```bash
curl -X POST https://warden.corp.example.com/api/coverage/reconcile \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"events":[{"actor":"alice@acme.com","tool":"claude.ai"},{"actor":"mallory@acme.com","tool":"claude.ai"}]}'
# -> {"covered":1,"uncovered_count":1,"uncovered":[{"actor":"mallory@acme.com",...}]}
```
The uncovered actors are using Claude on an unmanaged device or bypassing the planes —
your follow-up list (enroll the device, or block it via conditional access).

---

## Rollout

1. **Monitor first** — `GATEWAY_ENFORCE=false`, extension/proxy in warn mode. Let
   findings accumulate.
2. **Tune** — triage findings in the dashboard; export the labels and re-run the eval to
   pick the right block threshold (`python -m app.eval --corpus ...`). Adjust
   `GATEWAY_TOOL_SUPPRESS` if a sanctioned tool is noisy.
3. **Enforce** — flip `GATEWAY_ENFORCE=true` and the extension/proxy to enforce. Blocks
   are inline; everything is recorded and attributed per user.

---

## Notes & limitations

- **Attribution:** set `actor` on each API key (gateway), pass `user` from the extension
  Options, and `WARDEN_PROXY_USER` on the proxy — so findings and coverage are per-person.
- **Managed browser config:** the extension supports Chrome `storage.managed`, so
  enterprise policy configures it automatically and overrides user settings (zero-touch).
  On a single pilot machine, set the Options page instead.
- **Cert pinning:** the proxy plane depends on TLS inspection; pinned clients bypass it —
  rely on the gateway route where you control the client, and on coverage reconciliation
  to catch the rest.
- **Fail-open everywhere:** capture failures never block legitimate AI use.
