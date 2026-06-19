# Warden — Shadow-AI Guard (browser extension)

A Manifest V3 extension that catches **secrets, PII, and proprietary data being pasted
into external AI tools** (ChatGPT, Claude, Gemini) — and warns or blocks **before the
prompt is sent**. It's the Module C (`ai_usage`) capture client; all detection happens
in the Warden backend (`POST /api/ingest/ai-usage`).

## How it works

`content.js` injects `injected.js` into the page, which wraps `window.fetch`. When the
page submits a prompt, the interceptor extracts the prompt text, asks the background
worker for a verdict (which calls Warden), and:

- **allow** → sends normally,
- **warn** → sends, but shows an amber banner,
- **block** → the request is **not sent**; a red banner explains why.

It **fails open**: if the backend is slow, unreachable, or unconfigured, prompts go
through untouched — the extension never breaks the user's tool.

## Backend setup

Set a shared token and the tenant on the Warden backend, then restart it:

```
EXTENSION_INGEST_TOKEN=<a long random string>
INGEST_TENANT=<tenant slug, e.g. acme>
```

## Build a package

```bash
./build.sh            # -> warden-shadow-ai-guard-<version>.zip
```

## Install — pilot (one machine)

1. `chrome://extensions` → **Developer mode** → **Load unpacked** → pick this folder.
2. Open **Options** and set **Backend URL**, **Ingest token** (`EXTENSION_INGEST_TOKEN`),
   and **Enforce**.
3. Visit `https://claude.ai`, submit a prompt with a fake SSN `123-45-6789` + an `AKIA…`
   key — it should be blocked.

## Install — so users can just install it

Publish the `build.sh` zip to the **Chrome Web Store** (or **Edge Add-ons**) as a
**private/unlisted** item, or self-host the CRX with an `update_url`. Then either:
- users click **Add to Chrome** (one click), or
- you **force-install** it so it appears automatically — no user action.

## Enterprise rollout — zero-touch (force-install + managed config)

Push via your MDM / Google Admin / group policy:

1. **Force-install** by extension ID — Chrome `ExtensionInstallForcelist`
   (Edge: `ExtensionInstallForcelist`; with a self-hosted CRX, include the `update_url`).
2. **Configure centrally** via managed storage (`3rdparty/extensions/<id>/policy`) — the
   extension declares a `managed_schema.json`, so policy values are applied automatically
   and **override** user settings (users can't repoint it):

   ```json
   {
     "backendUrl": { "Value": "https://warden.corp.example.com" },
     "token":      { "Value": "<EXTENSION_INGEST_TOKEN>" },
     "enforce":    { "Value": true }
   }
   ```

With this, a managed device installs and configures the extension with **zero user
interaction**. Set `user` from SSO if your management layer can template it.

## Scope & limits (honest)

- Covers **managed browsers/devices** where the extension is installed; personal
  devices bypass it (use a network proxy plane for those).
- The fetch-interception parsing is tuned for current ChatGPT/Claude/Gemini request
  shapes; their internal APIs change, so the `SEND_PATTERNS` / `extractPrompt` logic in
  `injected.js` needs occasional maintenance. Unknown shapes fall back to scanning the
  raw request body, so detection degrades gracefully rather than failing silently.
