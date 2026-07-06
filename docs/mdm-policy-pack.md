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
| `chrome-edge-forcelist.txt` | `ExtensionInstallForcelist` value for the browser extension |
| `ca-note.txt` | Where to deploy your root CA (required for TLS inspection) |

The extension allow/deny lists come from your org's IDE-vetting config
(`IDE_EXT_ALLOWED` / `IDE_EXT_DENYLIST`); the browser extension id from
`WARDEN_EXTENSION_ID`.

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

This force-installs the Warden extension; combine with the per-tenant token via managed
config (the `/api/provision` installer emits that block prefilled — see
[`extension/README.md`](../extension/README.md)).

## 6. Verify

- **Proxy:** on a managed device, an AI/MCP request should appear as a finding in the
  console; a blocked one returns the Warden error.
- **CA:** `curl https://api.anthropic.com` through the proxy succeeds (no cert error).
- **VS Code:** installing a non-approved extension is refused by the editor.
- **Browser:** the Warden extension appears as *installed by your organization*.

## What this does and doesn't cover

- ✅ Enforces the proxy, the extension install, the editor allowlist, and CA trust — all by
  config, no Warden agent.
- ⚠️ **Gathering** a live per-device inventory (what's installed/running right now) needs
  your MDM's inventory feed — Warden can *vet* that list (`/api/scan/ide-extensions`) but
  doesn't collect it. Cert-pinned clients bypass TLS inspection. Both are inherent to the
  agentless model.
