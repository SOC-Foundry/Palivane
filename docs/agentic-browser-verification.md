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
   observe, not fight blocks while checking plumbing. For the actual verification pass,
   swap in the evidence collector (`-s proxy/verify_browsers.py`, next section) — same
   env vars and port, runs the addon unchanged, and fills the Results table for you.

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

## Automated evidence collector (use this for the pass)

You don't have to eyeball mitmdump output and hand-fill the Results table:
`proxy/verify_browsers.py` runs the normal addon **plus** an evidence recorder that
classifies each proxy-observable check below while you perform the browser actions. Be
clear about what it automates: **evidence capture and classification only** — the
browser actions themselves (prompts, agentic tasks, policy installs) are still manual,
and the extension/policy-side checks (Comet 1a forced-install, 1b sidecar invisibility)
happen outside the proxy's view, so those two are always hand-recorded.

Flow (in place of step 2's bare-addon command; same env vars, same port):

```bash
# 1. Start the collector (add PALIVANE_PROXY_INTERCEPT_ALL=true for the Dia session):
PALIVANE_URL=https://palivane.tachtech.net PALIVANE_TOKEN=<capture-key> \
mitmdump -s proxy/verify_browsers.py --listen-port 8081

# 2. Perform the browser actions for the checks you're exercising (1c, 1d, 2, 3 below).

# 3. Ctrl-C. The collector writes, to the current directory ($PALIVANE_VERIFY_DIR to
#    override):
#      verification-report.md    PASS / PARTIAL / FAIL / NOT-EXERCISED per check, plus
#                                paste-ready rows for the Results table at the bottom
#                                of this runbook (verbatim column format)
#      verification-report.json  the raw evidence (per-host CONNECT/TLS tallies with
#                                handshake-failure signatures, parse counts, WS frames)
```

What it records, per check: per-host TLS success vs. client-handshake failure (the
pinning signature above), whether `perplexity_ask` request/SSE bodies parsed via the
addon's own extractors or parse-missed, whether the `/agent` WebSocket opened and
produced readable text frames, whether `chatgpt.com` POSTs parsed via `extract_prompt`
(and any enforce-mode blocks), and every host that traversed the proxy (the Dia
discovery list). A check you didn't exercise reports NOT-EXERCISED — the collector
never guesses.

Do the checks one browser at a time (quit other browsers/apps between sections) so the
evidence attributes cleanly — the proxy sees traffic, not which app sent it.

The **manual fallback** readings are kept in each section below in case you need to
debug the collector itself or work from a raw `-w` capture.

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

With the system proxy up and the **collector** running (`mitmdump -s
proxy/verify_browsers.py`, see above), submit an assistant prompt with a synthetic
marker, wait for the streamed answer to finish, then stop the collector. The report
classifies this check as three rows: `comet_1c_request` (request body parsed via
`extract_comet_ask`), `comet_1c_sse_response` (SSE stream parsed via
`extract_comet_sse`), and `comet_1c_pinning` (TLS interception vs. the
handshake-failure pinning signature). Also confirm by hand that a finding with your
marker landed in the console (`tool=comet`) and that answers still streamed live in
Comet (the addon tees, it must not buffer/stall) — the collector can't see the console
or the browser UI.

Manual fallback readings:

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

With the collector running, give the assistant an agentic task ("open my cart and check
out", anything that drives the page). The report's `comet_1d_agent_ws` row lands PASS
(channel opened, readable text frames), PARTIAL (channel opened but frames
binary/opaque or absent — the runbook's "partial pass"), or NOT-EXERCISED, with frame
counts in the evidence. Note frame volume from the JSON — if the channel is chatty, we
may need batching before enforcing.

Manual fallback readings:

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

Collector flow: install the desktop app, set system proxy + trusted CA as in Common
setup, start the collector, send a marker prompt in **each** mode (Chat, Work, Codex,
and a page-question in the built-in browser), stop. The report's `chatgpt_proxy_trust`
row covers steps 2–3 below (traffic observed + no handshake failure = PASS; the pinning
signature = FAIL; nothing = NOT-EXERCISED — i.e. the app bypassed the system proxy), and
`chatgpt_parsing` covers step 4 (any POST body parsed via `extract_prompt` = PASS;
bodies seen but none parsed = FAIL — capture them and check for an `AI_HOST_SUFFIXES`
gap). Check the host inventory for any host a mode used outside the AI list. Step 5
(enforce) is a **manual re-run** — the collector notes any observed block in the row but
can't submit the prompt for you.

Manual fallback steps:

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
PALIVANE_PROXY_INTERCEPT_ALL=true mitmdump -s proxy/verify_browsers.py \
  --listen-port 8081 -w dia.flows
```

Use the Dia sidebar for a few varied prompts, then stop the collector. The report's
host inventory is the deliverable: every host that traversed the proxy with per-host
CONNECT/request counts and TLS success vs. handshake-failure (the pinning verdict per
host), with any `*.diabrowser.com` host called out in the `dia_host_capture` row. Keep
`-w dia.flows` so the raw bodies are preserved for the catalog follow-up.

Manual fallback — enumerate hosts from the raw capture:

```bash
mitmdump -nr dia.flows | awk '{print $2}' | sort | uniq -c | sort -rn | head -30
```

Deliverables from the session:

- the real sidebar API hostnames → promote/replace the `diabrowser.com` catalog row(s),
  drop the provisional flag, and only then consider proxy parsing;
- pinning verdict per host (TLS-failure signature above);
- whether any documented enterprise-policy surface exists yet (none known as of Aug 2026).

## Results

The collector's `verification-report.md` emits rows in exactly this column format —
paste them in verbatim (1a/1b rows stay hand-filled; a NOT-EXERCISED row means that
check still hasn't been performed, don't paste it as a result).

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
