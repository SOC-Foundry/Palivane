# Publishing the Warden extension to the Chrome Web Store / Edge Add-ons

This is the listing copy, the review answers (permissions + privacy), and the
step-by-step submission. The repo ships everything a reviewer needs; what's left is
account-bound and must be done from your own developer account.

## What's already done (in the repo)

- **Icons** — `icons/icon-{16,32,48,128}.png`, wired into `manifest.json` (`icons` +
  `action.default_icon`). The 128px icon is what the store requires.
- **Manifest V3**, single-purpose, no remote code — `injected.js` is packaged and loaded
  via `web_accessible_resources` (reviewers reject extensions that fetch remote JS).
- **Packaging** — `./build.sh` produces `warden-shadow-ai-guard-<version>.zip` with the
  icons included (and fails if the 128px icon is missing).

## What only you can do (account-bound)

1. **Register a developer account** — [Chrome Web Store dev dashboard](https://chrome.google.com/webstore/devconsole)
   (one-time **$5** fee) and/or [Edge Partner Center](https://partner.microsoft.com/dashboard/microsoftedge)
   (free).
2. **Host a privacy policy** at a public URL (use [`PRIVACY.md`](./PRIVACY.md) — paste it
   on your site or a public Gist) and put that URL in the listing.
3. **Provide screenshots** — at least one **1280×800** (or 640×400) PNG. Good shots: the
   amber "warn" banner and the red "block" banner on a prompt containing a fake secret.
4. **Upload the zip, fill the listing, and submit for review.**

## Distribution choice

| Mode | Who can install | Use when |
| --- | --- | --- |
| **Public** | Anyone | You want a public security tool. |
| **Unlisted** | Anyone with the link | Internal rollout without a public listing. |
| **Private** (Workspace) | Only your Google Workspace domain | Single-org deployment. |
| **Force-install** (no store review) | Managed devices via MDM / `ExtensionInstallForcelist` | Zero-touch fleet rollout — see [README](./README.md#enterprise-rollout--zero-touch-force-install--managed-config). |

You don't *need* the store for a managed fleet (force-install + self-hosted CRX works),
but a private/unlisted store item is the easiest install path.

---

## Listing copy (paste into the dashboard)

**Name:** Warden — Shadow-AI Guard

**Summary (≤132 chars):** Stops secrets, PII, and proprietary data from being pasted into
AI tools — scans prompts and warns or blocks before they're sent.

**Category:** Productivity (or Developer Tools)

**Detailed description:**
> Warden — Shadow-AI Guard inspects prompts you send to external AI tools (ChatGPT,
> Claude, Gemini, Microsoft Copilot) for secrets, credentials, PII, and proprietary
> source code, and warns or blocks **before the prompt leaves your browser**.
>
> Detection runs on your organization's self-hosted Warden backend; the extension is the
> capture client. It fails open — if the backend is unreachable, your AI tools keep
> working untouched. Configuration (backend URL, token, enforce mode) is set by your
> administrator via Options or managed enterprise policy.
>
> This is an organizational security tool. It is intended to be deployed by an
> administrator against a Warden backend you operate.

---

## Review answers

**Single purpose:**
> Inspect prompts being sent to external AI services for sensitive data (secrets, PII,
> proprietary code) and warn or block before the prompt is transmitted.

**Permission justifications:**

| Permission | Why it's needed |
| --- | --- |
| `storage` | Store the admin's configuration (backend URL, ingest token, enforce flag) and read enterprise **managed** policy. |
| `host_permissions` — `claude.ai`, `chatgpt.com`, `chat.openai.com`, `gemini.google.com`, `copilot.microsoft.com` | Run the content/injected script on these AI tools to read the prompt text before submission so it can be scanned. The extension acts **only** on these AI hosts. |
| `host_permissions` — `localhost` / `127.0.0.1` | Allow talking to a Warden backend running locally during evaluation. Remove these two from `manifest.json` before a public listing if you only use a hosted backend. |

**Data use disclosures (Chrome "Privacy practices" tab):**
- **What's collected:** the text of prompts the user submits to the supported AI tools
  (so it can be scanned), plus an optional user identifier set by the admin.
- **Where it goes:** **only** to the Warden backend your organization operates
  (`POST /api/ingest/ai-usage`). It is **not** sent to the extension's developer or any
  third party.
- Check: *not sold to third parties*, *not used for purposes unrelated to the single
  purpose*, *not used for creditworthiness/lending*.
- **Privacy policy URL:** the public URL where you host [`PRIVACY.md`](./PRIVACY.md).

> Because the extension transmits prompt content, expect Chrome to flag it for a closer
> review of the data-use disclosures. The honest framing above — *data goes only to the
> customer's own backend, never to us* — is what reviewers look for.

---

## Submit — Chrome Web Store

```bash
cd extension && ./build.sh          # -> warden-shadow-ai-guard-<version>.zip
```

1. [Dev dashboard](https://chrome.google.com/webstore/devconsole) → **Add new item** →
   upload the zip.
2. Fill **Store listing** (copy above), **Privacy practices** (answers above + policy
   URL), and add screenshots + the 128px icon (auto-read from the zip).
3. Choose visibility (Public / Unlisted / Private) → **Submit for review**.
4. On later updates: bump `"version"` in `manifest.json`, re-run `./build.sh`, upload.

### Optional — automated upload (CI)

The Chrome Web Store has a [publish API](https://developer.chrome.com/docs/webstore/using-api).
Once you have an OAuth client + refresh token and the item ID:

```bash
TOKEN=$(curl -s -X POST https://oauth2.googleapis.com/token \
  -d client_id=$CWS_CLIENT_ID -d client_secret=$CWS_SECRET \
  -d refresh_token=$CWS_REFRESH -d grant_type=refresh_token | jq -r .access_token)
curl -X PUT -H "Authorization: Bearer $TOKEN" -H "x-goog-api-version: 2" \
  -T warden-shadow-ai-guard-<version>.zip \
  "https://www.googleapis.com/upload/chromewebstore/v1.1/items/$CWS_ITEM_ID"
curl -X POST -H "Authorization: Bearer $TOKEN" -H "x-goog-api-version: 2" \
  "https://www.googleapis.com/chromewebstore/v1.1/items/$CWS_ITEM_ID/publish"
```

## Submit — Edge Add-ons

Same zip. [Edge Partner Center](https://partner.microsoft.com/dashboard/microsoftedge) →
**New extension** → upload → fill listing + privacy → submit. Edge also has a
[publish API](https://learn.microsoft.com/microsoft-edge/extensions-chromium/publish/api/using-addons-api).

## After upload: wire the extension ID into your fleet

The store assigns a **permanent extension ID** on first upload (visible in the dashboard
item URL — you don't have to publish to see it). That ID connects publishing to the rest
of the deploy pipeline:

1. **Tell Warden the ID** so generated installers write the browser managed policy under
   the right key. Set it once on the backend and every `/api/provision` installer + the
   Connect page uses it automatically:
   ```
   WARDEN_EXTENSION_ID=<the store item id>
   ```
   (env var; passed through `docker-compose.yml`). Restart the backend.

2. **Force-install policy** (MDM / Google Admin / GPO) — Chrome `ExtensionInstallForcelist`:
   ```
   <extension-id>;https://clients2.google.com/service/update2/crx
   ```
   Edge uses the same policy name with the Edge Add-ons update URL. Installs the extension
   automatically on managed devices.

3. **Managed config** is keyed by the ID — push to
   `3rdparty/extensions/<extension-id>/policy` (backendUrl + token + enforce). The
   provisioner emits exactly this block, prefilled.

### Alternative: self-hosted CRX (you control the ID)
To fix the ID *before* any store upload (e.g. to pre-stage all policy), pack a CRX with
your own signing key — the ID is derived deterministically from that key — and
force-install with **your** `update_url`. No store account needed, but you host the CRX +
`update.xml` and manage updates; Chrome also requires the extension be allow-listed by
enterprise policy to load off-store.
