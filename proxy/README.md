# Palivane egress proxy (desktop / network capture plane)

Catches AI usage the browser extension can't: **desktop apps** (Claude/ChatGPT
desktop), **IDE assistants** (Cursor, GitHub Copilot), **CLIs**, and anything else that
makes its own HTTPS calls to an AI provider. It's a [mitmproxy](https://mitmproxy.org/)
addon that inspects outbound POSTs to AI domains, scores the prompt through Palivane,
records a finding, and blocks (HTTP 400, provider-error shape) on a block verdict.

Inspected destinations include OpenAI (incl. the `openai` CLI and Codex CLI via
`api.openai.com`), Anthropic, and Gemini. The **Gemini CLI** is covered in all three of
its modes: API-key (`generativelanguage.googleapis.com`), the default OAuth "log in with
Google" / Code Assist (`cloudcode-pa.googleapis.com`), and Vertex
(`aiplatform.googleapis.com`). Also Cohere/Mistral/Perplexity, **GitHub Copilot**
(`*.githubcopilot.com`, `copilot-proxy.githubusercontent.com`), **Microsoft Copilot**
(`copilot.microsoft.com`), and **Cursor** (`*.cursor.sh`, `cursor.com`) — see
`AI_HOST_SUFFIXES` in `palivane_addon.py`. The tool is identified from the User-Agent
(`detect_tool`), so the backend's per-tool policy suppresses routine `source_code_leak`
for coding tools (`claude-code`, `cursor`, `copilot`, `gemini-cli`) while still catching
secrets and PII.

## MCP inspection (agentic tool-use)

Beyond prompt capture, the addon inspects **MCP** (Model Context Protocol) — the JSON-RPC
an AI coding agent uses to call tools and read resources. It's **content-sniffed** (any
POST whose body is JSON-RPC 2.0), so it works for MCP servers on any host, and posts a
normalized activity to `POST /api/ingest/mcp` on the **`mcp`** surface. A block verdict
returns a **JSON-RPC error** so the agent surfaces it cleanly. It flags:

- **sensitive resource access** (tool/resource touching `.env`, private keys, cloud creds…)
- **dangerous commands** (`curl … | sh`, `rm -rf /`, reverse shells…)
- **tool poisoning** (injected instructions in a server's advertised tool descriptions —
  caught in the `tools/list` response *and* in the tool defs the agent sends to the LLM API)
- **untrusted servers** (not on `MCP_ALLOWED_SERVERS`)
- **secrets/PII** in tool-call arguments

> **Transport boundary (agentless).** Remote / Streamable-HTTP MCP servers flow through
> the proxy and are fully inspected + blockable. **Local stdio** MCP servers never touch
> the network — agentlessly they're governed by *policy* (`MCP_ALLOWED_SERVERS`) and
> surfaced via the tool definitions the agent sends to the model (so tool-poisoning is
> still caught). For **inline** inspection of local stdio, wrap the server command with
> [`cli/palivane-mcp`](../cli/README.md) — an app-scoped shim, not an endpoint agent.

MCP env vars are read by the **backend** (`MCP_ENFORCE`, `MCP_BLOCK_SEVERITY`,
`MCP_ALLOWED_SERVERS`), not the proxy — the proxy just relays; the backend decides.

> **Cursor caveat (measured).** Cursor's model/chat endpoint (`api2.cursor.sh`) **pins
> its certificate** — a TLS-inspecting proxy is rejected (`tlsv1 alert unknown ca`) even
> with a trusted CA, so **chat prompts can't be intercepted** this way. The proxy can
> still see Cursor's codebase-index uploads (`aiserver.v1.CodebaseSnapshotService`,
> protobuf) and telemetry, but those aren't the prompt. **The fix isn't the proxy —
> it's the local plane:** [`palivane-cursor-hook`](../cli/README.md) uses Cursor's Hooks
> API to inspect the prompt (`beforeSubmitPrompt`), shell/MCP calls, and file reads/edits
> before they run, immune to the pinning. Pair with the **git plane** and the **gateway**
> for first-party AI.

## Run

```bash
pip install mitmproxy
PALIVANE_URL=http://localhost:8090 \
PALIVANE_TOKEN=<EXTENSION_INGEST_TOKEN> \
PALIVANE_PROXY_ENFORCE=true \
PALIVANE_PROXY_USER=alice@company.com \
mitmdump -s proxy/palivane_addon.py --listen-port 8081
```

Point a client at it and watch a sensitive prompt get blocked:

```bash
curl -x http://localhost:8081 https://api.openai.com/v1/chat/completions \
  -H "authorization: Bearer $OPENAI_KEY" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"SSN 123-45-6789, AWS key AKIA..."}]}'
# -> 400 {"error":{"type":"invalid_request_error", "message":"Blocked by Palivane: sensitive data (...)"}}
```

| Env | Purpose |
| --- | --- |
| `PALIVANE_URL` | Palivane backend base URL |
| `PALIVANE_TOKEN` | the backend's `EXTENSION_INGEST_TOKEN` |
| `PALIVANE_PROXY_ENFORCE` | `true` blocks; otherwise observe + record only. Either way the org's console stance (Settings → *Device enforcement*) rides along on each verdict and blocks when on |
| `PALIVANE_PROXY_USER` | end-user identity to attribute findings to |

**Attribution:** on a per-device install (`palivane-desktop`), leave `PALIVANE_PROXY_USER`
unset — the proxy authenticates with the device's per-user `ak_…` key (from
`palivane connect`), and the backend attributes findings to that key's owner
automatically. `PALIVANE_PROXY_USER` matters only for a *central* egress proxy running
with the shared `EXTENSION_INGEST_TOKEN`, where one process serves many people: it can
only carry a single static identity, so per-user attribution needs either per-device
proxies or per-user keys. Prefer per-device installs when attribution matters.

## Deploying to managed devices

1. **System proxy** — push the proxy address via MDM (or a PAC file) so all traffic
   routes through it.
2. **TLS inspection** — install mitmproxy's CA (or your corporate root CA, with
   mitmproxy configured to use it) on managed devices so HTTPS bodies are inspectable.
   On a managed fleet this cert is already trusted.
3. Run `mitmdump` as a service (systemd) near the egress point; scale horizontally —
   the addon is stateless (it calls the Palivane API).

### Scoped TLS interception (recommended)

Decrypting *all* TLS is a bigger ask — operationally (more cert-pinning breakage) and
politically (privacy review, works councils) — than the proxy actually needs. Scope
interception to the AI domains with mitmproxy's `--allow-hosts`: matching hosts are
decrypted and inspected; **everything else is tunneled untouched, end-to-end encrypted**.

```bash
mitmdump -s proxy/palivane_addon.py --listen-port 8081 --allow-hosts \
  '(^|\.)(api\.openai\.com|chatgpt\.com|chat\.openai\.com|api\.anthropic\.com|claude\.ai|generativelanguage\.googleapis\.com|gemini\.google\.com|api\.cohere\.ai|api\.mistral\.ai|api\.perplexity\.ai|githubcopilot\.com|copilot-proxy\.githubusercontent\.com|copilot\.microsoft\.com|cursor\.sh|cursor\.com)(:443)?$'
```

Keep the regex in sync with `AI_HOST_SUFFIXES` in `palivane_addon.py` (append your own
MCP-server domains — content-sniffed MCP detection only sees hosts that are decrypted).
Full interception remains the fallback when you need MCP inspection on arbitrary,
unpredictable hosts; scoped is the right default everywhere else — the objection it
answers changes from "you decrypt everything" to "we inspect a short list of AI domains".

## Honest limits

- **TLS inspection required** to read request bodies. Apps that **certificate-pin**
  (some native clients) will refuse the inspected cert — they break or bypass rather
  than being inspected. Most major AI desktop/web clients don't hard-pin, but verify
  per app.
- Covers traffic that **routes through the proxy** — i.e. managed/on-network devices.
  Off-network personal devices need an endpoint agent (out of scope here).
- **Fails open**: if Palivane is unreachable the request is allowed through, so the
  proxy never becomes a single point of failure for the company's AI access.
- Prompt extraction recognizes OpenAI / Anthropic / Gemini shapes; for **any other JSON
  body** it harvests all string values so secrets/PII are still scanned without a
  per-vendor parser, and falls back to the raw text for non-JSON (e.g. protobuf/binary)
  bodies. GitHub Copilot Chat uses a `messages` body (covered) and inline completion uses
  a `prompt` field (covered). Note Cursor uses **protobuf** (`application/proto`), not
  JSON — and its chat endpoint pins certs anyway (see the Cursor caveat above).
- **Verify TLS interception per IDE before relying on enforcement.** Some builds pin
  certs (Cursor's chat endpoint does — measured); where they do, the client bypasses or
  fails rather than being inspected.
