# MDM policy pack — agentless enforcement

Warden's `/api/scan/*` endpoints *detect* risky MCP servers, dependencies, and IDE
extensions. This runbook covers the **enforcement** side: the config your MDM pushes to
managed devices so policy is applied **with no Warden agent on the box**. The OS, editor,
and browser do the enforcing; Warden only generates the config.

> Everything here is applied by your MDM (Jamf / Intune / Group Policy). If you can't use
> an MDM, the same files can be applied by hand for a pilot.

## 1. Get the pack

An admin calls the generator (the token is a console session or admin API key):

```bash
curl -s "https://warden.example.com/api/policy-pack\
?base_url=https://warden.example.com&proxy_host=proxy.corp.example.com&proxy_port=8081" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.artifacts | keys[]'
```

It returns these artifacts (write each to a file):

| File | Purpose |
| --- | --- |
| `README.txt` | Summary of the pack + your backend/proxy values |
| `vscode-extensions.json` | VS Code `extensions.allowed` — allow approved, block known-bad |
| `macos-proxy.mobileconfig` | macOS system proxy → the Warden egress proxy |
| `windows-proxy.reg` | Windows system proxy → the Warden egress proxy |
| `chrome-edge-forcelist.txt` | `ExtensionInstallForcelist` value for the browser extension. Defaults to the **Chrome Web Store** (extension published there — Unlisted is fine). Pass `?ext_update_url=…` (+ `?ext_crx_url=…`) to `/api/policy-pack` for a **self-hosted CRX** with no Web Store submission (managed devices only) — that also emits `extension-updates.xml` below. |
| `chrome-extension-settings.json` | Chrome/Edge **`ExtensionSettings`** to govern *third-party* browser extensions — including agentic AI ones (e.g. Claude for Chrome) that Warden's own extension can't inspect. Blocks unsanctioned AI extensions by ID and/or keeps permitted ones off sensitive origins (`runtime_blocked_hosts`); Warden's extension is always force-installed. Query params: `?browser_ext_lockdown=true` (deny-all + allowlist), `?browser_ext_blocklist=`/`?browser_ext_allowlist=` (comma-sep IDs), `?browser_ext_blocked_hosts=`. |
| `extension-updates.xml` | *(self-hosted only)* Omaha update manifest to host next to your signed `.crx`; the forcelist points at its URL. |
| `claude-managed-settings.json` | Claude Code `managed-settings.json`: Route C hooks (warden-hook, warden-posture); subscription sign-in by default (`forceLoginMethod`), gateway routing with `route_gateway=true` |
| `openai.env` | Environment vars (`OPENAI_BASE_URL`) routing OpenAI SDK/CLI clients through the gateway — agentless, no CA needed |
| `gemini.txt` | Gemini routing: SDK `http_options` snippet + note (Gemini has no base-URL env var, so the system proxy is its primary capture path) |
| `cursor-hooks.json` | Cursor `hooks.json` registering `warden-cursor-hook` on the security events — local, pinning-proof capture of Cursor prompts + tool calls |
| `cursor.txt` | The full Cursor story: why chat is proxy-opaque, and how the hooks + MCP wrap + git/gateway close it |
| `warden-secrets.plist` / `.cron` / `-task.xml` | Schedule the endpoint credential scan (`warden-secrets --engine trufflehog`) daily via launchd (macOS) / cron (Linux) / Task Scheduler (Windows) — finds SSH/RSA keys, tokens, `.env` secrets **at rest** before an infostealer does (metadata-only). Drives **TruffleHog** by default (falls back to the built-in regex scan if not installed); set `?secrets_engine=gitleaks` or `?secrets_engine=` on `/api/policy-pack` to change it. |
| `ca-note.txt` | Where to deploy your root CA (required for TLS inspection) |

The extension allow/deny lists come from this tenant's IDE-vetting config (its
`ide_ext_allowed` / `ide_ext_denylist`, else the global `IDE_EXT_ALLOWED` /
`IDE_EXT_DENYLIST`); the browser extension id from `WARDEN_EXTENSION_ID`. The hook script
paths default to `/usr/local/bin/warden-hook` and `/usr/local/bin/warden-posture` —
override with `&hook_path=…&posture_path=…`.

Pull one artifact to a file:

```bash
curl -s "https://warden.example.com/api/policy-pack?..." -H "Authorization: Bearer $ADMIN_TOKEN" \
  | jq -r '.artifacts["vscode-extensions.json"]' > vscode-extensions.json
```

## 2. Deploy the CA first (required)

TLS inspection — and therefore MCP/AI-traffic inspection through the egress proxy — needs
your corporate/egress-proxy **root CA** trusted on the device. Warden doesn't generate the
cert (it's yours); deploy it to the **system** trust store:

- **Jamf / Intune (macOS):** a *Certificate* payload in a configuration profile.
- **Intune (Windows):** a *Trusted Certificate* profile targeting the Root store.
- **Group Policy (Windows):** Computer Config → Policies → Windows Settings → Security
  Settings → Public Key Policies → *Trusted Root Certification Authorities*.

Without the CA the proxy **fails open** (traffic flows uninspected). Cert-pinned clients
(e.g. Cursor's chat endpoint) bypass inspection regardless — that's expected.

## 3. System proxy → the Warden egress proxy

Routes egress through the proxy so MCP + AI traffic is inspected (and enforced).

- **macOS (Jamf/Intune):** upload `macos-proxy.mobileconfig` as a custom configuration
  profile. It sets a global manual HTTP/HTTPS proxy to `proxy_host:proxy_port`.
- **Windows (Intune):** deploy `windows-proxy.reg` values via a *Settings catalog* / custom
  OMA-URI, or import as a GPO **Registry** preference
  (`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` → `ProxyEnable`,
  `ProxyServer`). For system-wide/WinHTTP use `netsh winhttp set proxy proxy_host:port`
  pushed as a startup script.

## 4. VS Code extension allowlist

`vscode-extensions.json` contains `extensions.allowed` — in allowlist mode it denies all
(`"*": false`) except approved ids and explicitly blocks known-bad ones. Deploy it as
**machine-level** VS Code settings so users can't override:

- **macOS:** push the JSON to `/Library/Application Support/Code/User/settings.json` via an
  MDM file deployment (Jamf *Files and Processes* / Intune shell script), or merge it into
  a managed `com.microsoft.VSCode` preferences profile.
- **Windows:** push to `%ProgramData%\Microsoft\VS Code\...` machine settings, or set the
  VS Code **AllowedExtensions** policy via the registry under
  `HKLM\Software\Policies\Microsoft\VSCode`.

Pair with `/api/scan/ide-extensions` in CI (scanning `.vscode/extensions.json`) so a repo
can't *recommend* a banned extension either.

## 5. Browser extension force-install

`chrome-edge-forcelist.txt` is the `ExtensionInstallForcelist` value
(`<id>;https://clients2.google.com/service/update2/crx`). Deploy via:

- **Chrome:** policy `ExtensionInstallForcelist` (Google Admin, Intune ADMX, or GPO).
- **Edge:** same policy name under the Edge ADMX, with the Edge Add-ons update URL.

This force-installs the Warden extension; combine with the per-tenant config via managed
storage (the `/api/provision` installer emits that block prefilled — see
[`extension/README.md`](../extension/README.md)). Push an **`enrollToken`** (`et_…`) rather
than a static ingest `token` and the extension self-enrolls its own per-device key,
re-enrolling automatically if that key is revoked — per-device attribution and revocation,
no re-push.

## 6. Verify

- **Proxy:** on a managed device, an AI/MCP request should appear as a finding in the
  console; a blocked one returns the Warden error.
- **CA:** `curl https://api.anthropic.com` through the proxy succeeds (no cert error).
- **VS Code:** installing a non-approved extension is refused by the editor.
- **Browser:** the Warden extension appears as *installed by your organization*.

## Claude Code hooks (MDM-pushable, same model)

The pack now generates this for you: **`claude-managed-settings.json`** carries Warden's
**local planes** — a `PreToolUse` hook (`warden-hook` — pre-execution tool-call inspection)
and a `SessionStart` hook (`warden-posture` — device drift). By default Claude Code keeps
its own sign-in and `forceLoginMethod: "claudeai"` locks login to claude.ai (Pro/Max
subscriptions) — devs' prompts bill their plans, not an org API key. Generate the pack with
`route_gateway=true` (console checkbox or query param) to instead route prompts through the
Warden gateway (`ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN`), billing the org's provider
key. Deploy it to Claude Code's managed-settings path (macOS `/Library/Application
Support/ClaudeCode/`, Linux `/etc/claude-code/`, Windows `C:\Program Files\ClaudeCode\`),
push the two scripts to the referenced paths with your MDM's file-deployment, and — in
gateway mode — replace the `ak_` placeholder with each developer's key (or wire
`apiKeyHelper` — the `/api/provision` installer wires it to `warden-reenroll` for a
self-healing per-device key). See
[`docs/claude-deployment.md`](claude-deployment.md) (Route C) for the field-by-field
breakdown. Same philosophy as the rest of the pack: config the app enforces, no resident
Warden agent.

## OpenAI & Gemini clients (gateway redirect)

The proxy profile already inspects `api.openai.com` and `generativelanguage.googleapis.com`
(with the CA trusted), and the extension covers `chatgpt.com` / `gemini.google.com`. For
API clients that pin certs or otherwise skip the proxy, the pack also ships an explicit
gateway redirect:

- **`openai.env`** — `OPENAI_BASE_URL` (and the legacy `OPENAI_API_BASE`) pointed at the
  gateway's OpenAI-compatible `/v1/chat/completions`. Push as machine/user env via MDM;
  agentless, no CA required. Set `OPENAI_API_KEY` to each user's `ak_` Warden key.
- **`gemini.txt`** — Gemini's SDKs don't honor a standard base-URL env var, so the **system
  proxy is Gemini's primary agentless capture**. Where a client is code-configurable, the
  file gives the google-genai `http_options(base_url=…)` snippet pointing at the gateway's
  `/v1beta/models/{model}:generateContent`.

## What this does and doesn't cover

- ✅ Enforces the proxy, the extension install, the editor allowlist, and CA trust — all by
  config, no Warden agent.
- ⚠️ **Gathering** a live per-device inventory (what's installed/running right now) needs
  your MDM's inventory feed — Warden can *vet* that list (`/api/scan/ide-extensions`) but
  doesn't collect it (on developer machines, [`warden-posture`](claude-deployment.md)
  closes most of this gap by reporting installed IDE extensions and MCP configs).
  Cert-pinned clients bypass TLS inspection — inherent to the network plane; the Claude
  Code hooks above see local tool activity regardless of pinning.
