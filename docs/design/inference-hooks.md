# Design draft. Palivane as an Anthropic Inference hooks server

> Status: **v1 built** (`backend/app/inference_hooks.py`, `POST /api/inference-hooks`,
> Settings → Integrations). Not yet run against a real Claude Enterprise org. Spec followed:
> [Inference hooks](https://platform.claude.com/docs/en/manage-claude/inference-hooks) and
> [Develop an Inference hooks integration](https://platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint)
> (read 2026-10-23).

## 1. Why

Inference hooks make Anthropic call an org's "AI security server" before each governed
inference request and before each set of tool calls, and wait for allow or deny. They are
generally available to Claude Enterprise as of 2026-10-20. One configuration covers
claude.ai (web, desktop, mobile), Cowork local *and cloud*, Claude Code, Claude in Chrome,
Claude for Microsoft 365 and Claude Tag, with nothing installed on devices.

That closes the gaps device-side Palivane can't:

- **Cowork cloud sessions** never touch the device. The proxy, the hooks and the extension
  see nothing from them.
- **Local Cowork** ignores `~/.claude/settings.json` hooks, so palivane-hook doesn't run there.
- **Unmanaged devices and mobile**: no sensor at all.

It is Enterprise-only and not on Bedrock/Vertex, so the device sensors stay for everyone
else. A tenant can run both; findings dedupe by recurrence-folding as they already do.

## 2. The contract in brief

- `POST` to the URL the org's admin configures (any path). Public HTTPS on 443, valid public
  certificate, no redirects. Sent from `160.79.106.0/24`.
- Headers: `User-Agent: anthropic-dlp/1`, any **custom headers the admin configures**, and
  Standard Webhooks signing: `webhook-id`, `webhook-timestamp`,
  `webhook-signature: v1,<base64 HMAC-SHA256 of "{id}.{ts}.{raw body}">`. The secret is
  `whsec_<standard base64>`. Reject timestamps more than 5 minutes off. During rotation
  accept the old and the new secret.
- Body `type` is `prompt` or `tool_call`; an unknown type must get **allow**, not an error.
  Also: `request_id` (= `webhook-id`), `tenant_id`, `actor {type:"user", id, email_address}`,
  `source.application` (`claude-ai` | `claude-code` | `cowork` | `config-test` | future),
  `session_id`, `model`, `messages` (blocks: `text`, `tool_use`, `tool_result`,
  `attachment` with extracted `text`; unknown block types are skipped), `metadata`.
- `prompt` carries the **whole transcript, every time**. `tool_call` carries only the latest
  assistant message: text plus one `tool_use` per call, each with `tool_info`
  (`platform` | `application` | `third_party` (+`origin`, `verified_origin`) | `client`).
- Verdict: HTTP 200 + `{"action":"allow"}` or
  `{"action":"deny","deny_reason":"<=500 chars, shown to the user","reference_id":"<=50 chars"}`.
  Anything else (non-200, timeout, bad JSON) is a *webhook failure* and the org's failure
  handling (block or allow) applies. Sustained failures trip Anthropic's circuit breaker.
- Budget: 1–10,000 ms, default 5,000 ms, for the whole exchange. Bodies up to 64 MiB
  (typically under 10 MB).

## 3. Design

### 3.1 Endpoint and tenant routing

`POST /api/inference-hooks`. The tenant is found the way every capture endpoint finds it: the
admin adds a custom request header `X-Palivane-Token: ak_…` in the Anthropic console. Then the
**signature is verified with that tenant's signing secret**. Both are required: the key routes
the request, the signature proves it came from Anthropic for that org. A key alone could be
replayed by anyone holding it. A signature alone can't say which tenant's secret to use.

- Signing secrets: stored per tenant, sealed at rest (`crypto.seal`, like `siem_s3_secret`),
  write-only through the API. Two slots, `current` and `previous`, so a rotation doesn't
  reject Anthropic's stragglers.
- Unsigned requests: rejected (401) once a secret is stored. With no secret stored at all,
  answer 401 too. Anthropic now requires a secret before hooks can be enabled.
- No idempotency cache: Anthropic retries only when the *connection* fails, so the first
  attempt never reached Palivane and nothing is scored twice.
- The key is checked before the body is read, so nothing without a valid key gets Palivane to
  read a multi-megabyte transcript.

### 3.2 What a prompt frame scans

Same rule as the gateway (`gateway._scan_messages`): **the latest user turn**, meaning its
`text` blocks and the extracted `text` of its `attachment` blocks. Not the whole transcript
every time: Claude Code resends history and large tool results on every request, so scanning
everything makes one secret anywhere poison every later turn and refile the same finding.

That rule has one hole that only exists here. Anthropic resends a **denied** message with
every later request, because it stays in the transcript until the user edits it out. Scanning
only the latest turn would let it through on the next message. So Palivane **remembers what
it denied**: a small table of `(tenant, session_id, sha256 of the denied block)` with a TTL.
Every prompt frame hashes its earlier user blocks and denies again on a match, with a reason
that says an earlier blocked message is still in the conversation and how to remove it (edit
it, `/rewind` in Claude Code, a new task in Cowork). No rescanning, and nothing outside
Palivane's own past denials is affected.

`tool_result` blocks are scanned **for confirmed secrets only** (since 2026-10-29, QA H5),
on their own, outside the prompt score: what a tool just returned is on its way to the model,
so a live credential in it is denied like one in a prompt, in monitor mode too. Ordinary tool
output (code, file contents) never stops a frame. Only the latest turn's results are read, so
a result is checked once. The gateway applies the same rule to the latest tool_result. Orgs
whose repositories keep fake vendor keys in test fixtures can turn it off
(`block_tool_result_secrets`, Settings); results are then recorded but not stopped.
See open question 1.

### 3.3 What a tool-call frame scans

Each `tool_use` maps to Palivane's MCP-activity shape (the same mapping `palivane-hook`'s
`build_activity` does: tool name, input as args text, `tool_info.origin` as the server) and is
scored on the MCP surface: dangerous commands, sensitive paths, secrets in arguments,
untrusted servers. One verdict covers the frame, so a block on any call denies them all, with
the reason naming which call.

### 3.4 The verdict rule

The same rule every client plane uses (`should_block`):

- a **confirmed** secret/PII leak (`force_block`) is denied in any mode;
- an ordinary `block` is denied when the tenant enforces (Settings → Enforcement, the same
  per-actor stance `_client_enforce_for` gives the CLI hooks, tool name `cowork`/`claude-code`/
  `claude-ai`);
- a **coached** verdict is denied under enforcement. The hook protocol can't redact, so the
  `deny_reason` says what to remove instead of carrying the cleaned copy (500-char cap).
- everything else is allowed and, as now, still recorded as a finding when it scores.

Rollout safety comes from Anthropic's side (shadow mode, rollout percentage, role
exclusions), so Palivane needs no separate shadow mode.

`deny_reason` is written for the user: what was found, from the masked evidence (no secret
text, as in palivane-hook 1.3.3), and what to do. `reference_id` is the finding id, so a
denial in Anthropic's Activity Feed joins to the Palivane finding.

### 3.5 Speed and failure

- **Rules only inline.** `run_analysis(..., use_judge=False)`. The LLM judge's timeout is
  45 s, far past a 5 s budget. The regex and ML detectors are milliseconds.
- **Own meter.** Hook traffic is counted under a new `inference_hook` kind, not `ingest`. A
  429 is a webhook failure: under fail-closed, an exhausted ingest quota would block every
  prompt in the org.
- **Errors are honest.** A bad signature is a 401; an internal error is a 500. Both are
  webhook failures, so the org's own failure-handling choice decides, which is what the
  protocol intends. Unknown frame types and `config-test` get allow.
- **Size.** Cloud Run caps HTTP/1 request bodies at 32 MiB. The 64 MiB protocol maximum
  would fail there; real transcripts sit well under it. Scored content is capped the way
  the ai-usage endpoint caps it.

### 3.6 Console

Settings → Integrations → **Anthropic Inference hooks**:

- the endpoint URL to paste into Anthropic (`https://app.palivane.io/api/inference-hooks`);
- "Create header key": mints an `ak_` key labelled *Inference hooks* and shows the exact
  custom header to add;
- the signing secret field (paste `whsec_…`, write-only), with "rotate" moving the current
  one to `previous`;
- last request received, last verdict, and count of signature failures, so a misconfigured
  secret is visible before an admin turns on blocking.

### 3.7 Findings

Recorded like any ai-usage or MCP capture: actor = `actor.email_address` (else `actor.id`),
tool = `source.application`, destination `anthropic`, agent label `inference-hooks`. Shows up
in Findings, Fleet (as a capture plane), alerts and SIEM unchanged.

Prompt frames are scored with **no destination**: the org governs Claude through Anthropic
itself, and `claude.ai` as a destination would raise "Unsanctioned AI tool: Claude" for any
org that hasn't listed it. Content signals fire as on every other plane.

## 4. Open questions

1. **Scan tool results?** Decided 2026-10-23: not in v1. Revised 2026-10-29 (QA H5): scanned
   for confirmed secrets, which deny; on by default with a per-org off switch for fixture-heavy
   repos. Other findings in tool output are recorded, never denied.
2. **Image-only content** is never sent by Anthropic, so screenshots aren't inspected. Nothing
   Palivane can do on this path.
3. **The titling request.** The overview says hooks govern inference requests; whether
   Cowork's title-generation call is governed is unconfirmed.

## 5. Plan

1. Tenant columns for the two sealed secrets + the denied-block table (one migration).
2. `backend/app/inference_hooks.py`: signature verification, frame parsing, latest-turn and
   tool-call extraction, verdict building. Pure functions, unit-tested against the spec's own
   examples.
3. The endpoint in `main.py` and the `inference_hook` meter.
4. Settings UI.
5. A signed end-to-end test that posts spec-shaped frames (prompt with a secret, resent
   denied turn, tool call with `rm -rf /`, unknown type, `config-test`).
