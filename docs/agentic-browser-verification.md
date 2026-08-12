# Agentic-browser verification runbook (Comet / ChatGPT desktop / Dia)

**Status: parsing shipped, verification pending.** The egress proxy
(`proxy/palivane_addon.py` ≥ 1.3.0) now parses Perplexity Comet's assistant SSE and flags
its agent WebSocket, and the ChatGPT desktop app rides the existing `chatgpt.com`
handling. All of it was built on Linux against synthetic fixtures — **none of these
browsers ships a Linux build**, so every check below needs a real macOS or Windows
machine. This runbook is the checklist for that pass. Background/decisions:
[roadmap-frontier.md — Agentic browsers](roadmap-frontier.md#agentic-browsers-comet--dia--chatgpt-desktop).

Record results in the table at the bottom and update the roadmap + `/coverage` copy when
a row flips to verified.

## Common setup (both platforms)

1. On the test machine, install mitmproxy and fetch the repo (only `proxy/` is needed):

   ```bash
   pip install mitmproxy
   ```

2. Start the addon against a reachable Palivane backend (or a dev one):

   ```bash
   PALIVANE_URL=https://palivane.tachtech.net PALIVANE_TOKEN=<capture-key> \
   mitmdump -s proxy/palivane_addon.py --listen-port 8081
   ```

   Leave enforce off for the first pass (`PALIVANE_PROXY_ENFORCE` unset) — you want to
   observe, not fight blocks while checking plumbing.

3. Trust the mitmproxy CA and point the system proxy at the addon.

   macOS:

   ```bash
   sudo security add-trusted-cert -d -r trustRoot \
     -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem
   networksetup -setwebproxy   "Wi-Fi" 127.0.0.1 8081
   networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8081
   ```

   Windows (admin PowerShell):

   ```powershell
   certutil -addstore root "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.cer"
   # Settings > Network & internet > Proxy > Manual: 127.0.0.1:8081
   ```

   (On a managed fleet this is exactly what the MDM policy pack pushes — the manual steps
   above just reproduce it on a bench machine.)

4. Sanity check the plumbing before touching a browser: `curl -x http://127.0.0.1:8081
   https://chatgpt.com -sk -o /dev/null -v` should show mitmdump logging the CONNECT.

**Reading pass/fail in mitmdump:** a *pinned* client shows up as the TLS handshake dying
— `Client TLS handshake failed. The client does not trust the proxy's certificate`
or `tlsv1 alert unknown ca` — immediately after the CONNECT. That is the same signature
we measured for Cursor's `api2.cursor.sh` (see `proxy/README.md`, "Cursor caveat").

## 1. Perplexity Comet (priority)

Three checks: managed rollout, sidecar invisibility (expected), and proxy
inspectability of the agent protocol.

### 1a. Managed-storage / forced-install flow

Comet supports the Chromium enterprise policy suite. Target is the macOS bundle id /
Windows policy hive for Comet (`ai.perplexity.comet`):

macOS:

```bash
sudo defaults write /Library/Managed\ Preferences/ai.perplexity.comet \
  ExtensionInstallForcelist -array \
  "<palivane-extension-id>;https://clients2.google.com/service/update2/crx"
```

Windows: the same `ExtensionInstallForcelist` value under Comet's policy registry path
(mirror of `HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist` — confirm the
exact vendor path in `comet://policy` once on the machine).

- **Pass:** `comet://policy` (or the equivalent internal page) lists the policy as set;
  the Palivane extension appears pinned/non-removable; managed storage delivers the org
  config (extension shows "managed by your organization" state).
- **Fail:** policy page ignores the key → record which Chromium policies Comet actually
  honors; managed rollout needs a different channel.

### 1b. Sidecar invisibility (expected result)

With the extension installed, use the Comet **sidecar assistant** on any page and give it
a prompt containing a synthetic marker (e.g. the fake card `4111 1111 1111 1111`).

- **Expected pass:** NO extension finding is produced (the sidecar originates prompts in
  an extension/WebUI context the MAIN-world fetch wrap can't see) — while the *proxy*
  finding from 1c does appear. This confirms the division of labor; it is not a bug.
- Ordinary in-tab AI use (visiting chatgpt.com in a Comet tab) must still produce
  extension findings — check one to confirm the extension itself works in Comet.

### 1c. SSE inspectability / pinning check

With the system proxy up and the addon running, submit an assistant prompt with a
synthetic marker.

- **Pass:**
  - mitmdump shows `POST https://www.perplexity.ai/rest/sse/perplexity_ask`;
  - a finding lands in the console with `tool=comet`, destination
    `https://www.perplexity.ai/rest/sse/perplexity_ask`, containing your marker;
  - a second finding for the SSE *response* (destination suffix `#sse-response`) carries
    the agent's streamed answer;
  - answers still stream live in Comet (the addon tees, it must not buffer/stall).
- **Fail — pinning:** TLS alert in mitmdump (see "Reading pass/fail" above). Record it
  like the Cursor caveat; inline coverage for Comet then needs a local plane, not the proxy.
- **Fail — parse-miss:** findings appear but prefixed `[comet parse-miss]`, and mitmdump
  logs a parse-miss warning. The protocol shape drifted from the Zenity teardown. Capture
  the real bodies and iterate:

  ```bash
  mitmdump -s proxy/palivane_addon.py --listen-port 8081 -w comet.flows
  # reproduce, then export bodies:
  mitmdump -nr comet.flows --filter "~u perplexity_ask & ~q" --set dumper_default_contentview=raw
  # save the request body as <dir>/ask_request.json and the SSE response as <dir>/ask_response.sse, then:
  python3 proxy/palivane_addon.py --selftest-comet <dir>
  ```

  Fix the parser until the self-test passes on the *real* capture, and replace/extend the
  synthetic fixtures in `proxy/fixtures/comet/`.

### 1d. Agent WebSocket

Give the assistant an agentic task ("open my cart and check out", anything that drives
the page).

- **Pass:** mitmdump/addon logs `Comet agent WebSocket opened: wss://www.perplexity.ai/agent`,
  a channel-open finding lands (`tool=comet`, `wss://` destination), and text frames
  produce scannable findings. Note frame volume — if the channel is chatty, we may need
  batching before enforcing.
- **Partial pass:** channel-open finding only, frames binary/opaque — still useful
  (device-level "agent automation is running" signal). Record the framing so a decoder
  can be scoped.

### Self-test (no browser, no network)

Anyone can validate the parser end-to-end offline:

```bash
python3 proxy/palivane_addon.py --selftest-comet
# [PASS] perplexity_ask_request.json ...
# [PASS] perplexity_ask_response.sse ...
# selftest-comet: 2/2 fixtures parsed
```

The bundled fixtures are **synthetic** (Zenity-teardown shape, clearly marked). Point the
flag at a directory of real captured bodies (`*.json` request bodies, `*.sse` response
streams) to validate against a live capture.

## 2. ChatGPT desktop app (Atlas's successor)

The app (Chat/Work/Codex modes, built-in browser) talks to the `chatgpt.com` backend the
proxy already parses (`{author:{role}}, content.parts` shape). What's unverified is the
app's *client* behavior, not our parsing.

1. Install the desktop app; set system proxy + trusted CA as in Common setup.
2. **System-proxy check:** send any prompt. Pass: mitmdump shows
   `CONNECT chatgpt.com:443` (or a subdomain — the suffix match covers them all) coming
   from the app, not just from browsers.
   Fail: no CONNECT → the app bypasses the system proxy (record whether
   `HTTPS_PROXY`/Electron flags change that).
3. **Trust-store check:** no TLS failure in mitmdump. Fail signature = pinning, as above.
4. **Parsing check:** prompt with a synthetic marker in each mode (Chat, Work, Codex, and
   a page-question in the built-in browser). Pass: findings with the marker; note which
   host each mode used — if Codex or the built-in browser hits a host outside
   `AI_HOST_SUFFIXES`, add it (with a test) and re-run.
5. **Enforce check:** re-run with `PALIVANE_PROXY_ENFORCE=true` and a prompt containing a
   real-shaped fake secret (e.g. `AKIA` + 16 chars). Pass: the app surfaces the Palivane
   400 block message cleanly.

## 3. Dia (The Browser Company / Atlassian) — discovery capture only

macOS-only (Apple Silicon; Windows "fall 2026"). The sidebar talks to **Dia's hosted
backend**, which relays to model partners — so egress only ever sees Dia's hosts, and we
don't know what those are: the `diabrowser.com` catalog row is flagged **provisional**
(`PROVISIONAL` in `backend/app/ai_catalog.py`). Per the roadmap, **do not write parsing
code** until real hosts are captured. This is a capture session, not an integration:

```bash
# Wide-open capture (interception NOT scoped to the AI list — we don't know Dia's hosts):
PALIVANE_PROXY_INTERCEPT_ALL=true mitmdump -s proxy/palivane_addon.py \
  --listen-port 8081 -w dia.flows
```

Use the Dia sidebar for a few varied prompts, then enumerate hosts:

```bash
mitmdump -nr dia.flows | awk '{print $2}' | sort | uniq -c | sort -rn | head -30
```

Deliverables from the session:

- the real sidebar API hostnames → promote/replace the `diabrowser.com` catalog row(s),
  drop the provisional flag, and only then consider proxy parsing;
- pinning verdict per host (TLS-failure signature above);
- whether any documented enterprise-policy surface exists yet (none known as of Aug 2026).

## Results

| Check | Platform | Date | Result | Notes |
|---|---|---|---|---|
| Comet 1a forced-install | macOS | | | |
| Comet 1a forced-install | Windows | | | |
| Comet 1b sidecar invisibility | macOS | | | |
| Comet 1c SSE inspect/pinning | macOS | | | |
| Comet 1c SSE inspect/pinning | Windows | | | |
| Comet 1d agent WebSocket | macOS | | | |
| ChatGPT desktop proxy/trust | macOS | | | |
| ChatGPT desktop proxy/trust | Windows | | | |
| ChatGPT desktop parsing/enforce | either | | | |
| Dia host capture | macOS (Apple Silicon) | | | |
