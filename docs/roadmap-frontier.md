# Frontier roadmap — scoped, not yet shipped

Competitive tracks that are genuine investments or decisions rather than code we can land
now. Recorded honestly so they're tracked, not implied as shipped. The other competitive
tracks (framework mapping, coaching, A2A, red-team self-test, PII locales, benchmarks,
personal-vs-corporate accounts, catalog pipeline, MCP reputation feed) are shipped; these
four are the remainder.

## Local ML classifiers — the biggest bet

**Status: greenfield. Not started in code, deliberately.** There is zero ML in the
detection path today (no numpy/sklearn/onnx/torch); detection is regex/heuristic plus the
optional API-based LLM judge. Competitors ship trained classifiers (Lakera, Nightfall,
Harmonic, PANW). Shipping our own is a real investment, not a sprint:

- a labeled **training** corpus far larger than the ~100-item eval corpus (which is sized
  to *measure*, not train);
- a lightweight offline inference path (ONNX/quantized) that preserves the no-API-key
  promise and a per-request latency budget (the gateway is inline);
- retraining + drift monitoring as an ongoing cost.

Do not scaffold a no-op ML hook to look done — that's cargo-cult. Start it as a scoped
project with a corpus and a latency target, or not at all.

## MCP Enterprise-Managed Authorization (EMA)

**Status: decision made — see [mcp-ema-integration.md](mcp-ema-integration.md).** The IdP
is the PDP for *connections*; Palivane is the decision + enforcement point for *actions*
and the audit plane for both. Key fact from the spec's own text: EMA's visibility "does
not extend to the actual MCP traffic" — the per-call gap is stated normatively, and it is
exactly where Palivane sits. Build list (small, ordered) is in the doc: accept EMA-minted
tokens as actor identity, audit the ID-JAG issuance leg, document role precedence, Okta
partnership motion. Workload/agent identity stays Palivane's — EMA only covers humans.

## Agentic browsers (Comet / Dia / ChatGPT desktop)

**Status: per-browser plan, researched Aug 2026.** These products run the agent
themselves, so the model call doesn't come through a page fetch the extension wraps. The
cross-cutting conclusion: **the egress proxy, not the extension, is the realistic inline
path for all of them** — every one is Chromium/Electron-derived and should honor system
proxy + OS trust store, the mechanism we already deploy for desktop apps. The per-browser
work is protocol parsing, and none of it is verifiable on Linux (no Linux builds exist).

- **Perplexity Comet — the priority.** macOS/Windows/mobile. Agent prompts flow as SSE to
  `www.perplexity.ai/rest/sse/perplexity_ask` and automation over
  `wss://www.perplexity.ai/agent` (Zenity Labs teardown) — hosts the catalog already
  covers, so discovery works today. The sidecar originates prompts from an extension/WebUI
  context our MAIN-world fetch wrap can't see, so the extension won't capture assistant
  prompts even though it installs fine — but Comet supports the full Chromium enterprise
  policy suite incl. `ExtensionInstallForcelist` (MDM target `ai.perplexity.comet`), so
  the managed rollout ports directly and still covers ordinary in-tab AI use. **Verify on
  macOS/Windows:** managed-storage flow, sidecar invisibility (expected), and whether the
  SSE body is plaintext-inspectable through the proxy with no pinning — if yes, Comet
  inline enforcement ships via the egress proxy alone.
- **ChatGPT desktop (Atlas's successor).** OpenAI discontinued Atlas as a standalone
  browser on 2026-07-09 and folded it into the ChatGPT desktop app (Chat/Work/Codex modes
  with built-in browser; Mac + Windows). Not an extension host — the egress proxy is the
  only path; traffic is the `chatgpt.com` backend the catalog and proxy already know.
  **Verify on macOS/Windows:** system-proxy + trust-store behavior of the desktop app.
- **Dia (The Browser Company / Atlassian) — least visible, least urgent.** macOS-only
  (Windows "fall 2026", no Linux signal). The AI sidebar talks to Dia's hosted backend,
  which relays to model partners — egress never sees model-provider hosts, only Dia's, and
  the actual API hostnames are unverified (our `diabrowser.com` catalog row is
  provisional). No documented enterprise-policy surface. **Verify on Apple-Silicon macOS:**
  mitmproxy capture of the sidebar's real API hosts, add catalog rows, check pinning.

Listed as a known gap on /coverage (copy updated for the Atlas sunset).

## SaaS-AI OAuth discovery — live pulls shipping, per-platform buildout

The OAuth-grant ingest (`POST /api/discovery/oauth-grants`) covers the mechanism, and the
connector framework (`backend/app/saas_connectors.py` + `/api/discovery/connectors`) now
does **live pulls**: store a platform admin credential (encrypted at rest), sync on demand
or from an operator cron, grants land through the same ingest path as a manual export.
First connector: **Google Workspace** (service account with domain-wide delegation).
Remaining work is per-platform fetchers in the PLATFORMS registry — M365 (Graph
`servicePrincipals`/`oauth2PermissionGrants`), Slack, Salesforce, Notion, … — each an
admin-API client that normalizes to the same grant shape.
