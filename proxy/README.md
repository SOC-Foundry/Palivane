# Warden egress proxy (desktop / network capture plane)

Catches AI usage the browser extension can't: **desktop apps** (Claude/ChatGPT
desktop), **IDE assistants** (Cursor, GitHub Copilot), **CLIs**, and anything else that
makes its own HTTPS calls to an AI provider. It's a [mitmproxy](https://mitmproxy.org/)
addon that inspects outbound POSTs to AI domains, scores the prompt through Warden,
records a finding, and blocks (HTTP 403) on a block verdict.

Inspected destinations include OpenAI, Anthropic, Gemini, Cohere/Mistral/Perplexity,
**GitHub Copilot** (`*.githubcopilot.com`, `copilot-proxy.githubusercontent.com`), and
**Microsoft Copilot** (`copilot.microsoft.com`) — see `AI_HOST_SUFFIXES` in
`warden_addon.py`. The tool is identified from the User-Agent (`detect_tool`), so the
backend's per-tool policy suppresses routine `source_code_leak` for `copilot` while
still catching secrets and PII.

## Run

```bash
pip install mitmproxy
WARDEN_URL=http://localhost:8090 \
WARDEN_TOKEN=<EXTENSION_INGEST_TOKEN> \
WARDEN_PROXY_ENFORCE=true \
WARDEN_PROXY_USER=alice@company.com \
mitmdump -s proxy/warden_addon.py --listen-port 8081
```

Point a client at it and watch a sensitive prompt get blocked:

```bash
curl -x http://localhost:8081 https://api.openai.com/v1/chat/completions \
  -H "authorization: Bearer $OPENAI_KEY" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"SSN 123-45-6789, AWS key AKIA..."}]}'
# -> 403 {"error":{"type":"warden_blocked", "message":"Blocked by Warden: sensitive data (...)"}}
```

| Env | Purpose |
| --- | --- |
| `WARDEN_URL` | Warden backend base URL |
| `WARDEN_TOKEN` | the backend's `EXTENSION_INGEST_TOKEN` |
| `WARDEN_PROXY_ENFORCE` | `true` blocks; otherwise observe + record only |
| `WARDEN_PROXY_USER` | end-user identity to attribute findings to |

## Deploying to managed devices

1. **System proxy** — push the proxy address via MDM (or a PAC file) so all traffic
   routes through it.
2. **TLS inspection** — install mitmproxy's CA (or your corporate root CA, with
   mitmproxy configured to use it) on managed devices so HTTPS bodies are inspectable.
   On a managed fleet this cert is already trusted.
3. Run `mitmdump` as a service (systemd) near the egress point; scale horizontally —
   the addon is stateless (it calls the Warden API).

## Honest limits

- **TLS inspection required** to read request bodies. Apps that **certificate-pin**
  (some native clients) will refuse the inspected cert — they break or bypass rather
  than being inspected. Most major AI desktop/web clients don't hard-pin, but verify
  per app.
- Covers traffic that **routes through the proxy** — i.e. managed/on-network devices.
  Off-network personal devices need an endpoint agent (out of scope here).
- **Fails open**: if Warden is unreachable the request is allowed through, so the
  proxy never becomes a single point of failure for the company's AI access.
- Prompt extraction handles OpenAI / Anthropic / Gemini request shapes and falls back
  to the raw body; new providers may need a parser tweak in `extract_prompt`. GitHub
  Copilot Chat uses a `messages` body (covered) and inline completion uses a `prompt`
  field (covered by the fallback).
- **Verify Copilot TLS interception on your fleet** before relying on enforcement — some
  IDE Copilot builds pin certs; where they do, they bypass rather than being inspected.
