# Frontier roadmap, scoped, not yet shipped

Competitive tracks that are genuine investments or decisions rather than code we can land
now. Recorded honestly so they're tracked, not implied as shipped. The other competitive
tracks (framework mapping, coaching, A2A, red-team self-test, PII locales, benchmarks,
personal-vs-corporate accounts, catalog pipeline, MCP reputation feed) are shipped; these
four are the remainder.

## Local ML classifiers, the biggest bet

**Status: model machinery AND the data pipeline are built; the gate is NOT cleared, see
[ml-classifier-baseline.md](ml-classifier-baseline.md).** The track has a *working* offline
classifier (`backend/app/ml/`: stdlib feature-hashing + logistic regression, no
numpy/onnx/torch, ~0.07 ms/example, well under the inline budget), a training-corpus
builder, and an honest held-out benchmark against the regex baseline.

The measured result: on synthetic paraphrase data the linear model catches injection
phrasings the regex list misses (regex recall 0.34 → the competitive gap is real), but the
numbers are inflated by train/test sharing one synthetic distribution. **Go/no-go
(unchanged): do not wire it into the live path or commit weights until a real labeled
corpus (consented captures, analyst-labeled, held-out by time window) shows it beats regex
with a low FP rate.**

The path to that corpus now exists end-to-end: a consented capture pipeline (per-tenant
`ml_capture` opt-in, off by default; sampled prompts staged with the regex verdict as a
weak label), an analyst labeling API (`/api/ml/corpus*`, attributed ground truth + training
export), a public-dataset importer (deepset/prompt-injections and friends, operator-
downloaded, as an interim real-distribution eval set), and a time-windowed holdout in the
benchmark that prints an explicit `GATE: PASS/FAIL` against the documented criteria (beats
regex F1, FP rate ≤ 2%, no synthetic rows in the holdout). What remains is not code: opt
pilot tenants in, accumulate and label captures, and let the gate decide.

## MCP Enterprise-Managed Authorization (EMA)

**Status: decision made; build items 1-3 shipped, see
[mcp-ema-integration.md](mcp-ema-integration.md).** The IdP is the PDP for *connections*;
Palivane is the decision + enforcement point for *actions* and the audit plane for both.
Key fact from the spec's own text: EMA's visibility "does not extend to the actual MCP
traffic", the per-call gap is stated normatively, and it is exactly where Palivane sits.
Shipped: EMA-minted tokens (ID-JAG / JWT access tokens) attribute the session actor on the
MCP capture path with honest opaque-token fallback; the ID-JAG issuance/redemption legs
are recorded as session events where the proxy sees the token endpoints; role
`allow_servers` precedence (tightening overlay under EMA) is documented in `authz.py` and
the doc. Remaining: the partnership motion (Okta XAA validation, MCP-AS vendor
compatibility stories), not code. Workload/agent identity stays Palivane's, EMA only
covers humans.

## Agentic browsers (Comet / Dia / ChatGPT desktop)

**Status: parsing shipped in the egress proxy (addon ≥ 1.3.0); pending the macOS/Windows
verification pass, [agentic-browser-verification.md](agentic-browser-verification.md).**
These products run the agent themselves, so the model call doesn't come through a page
fetch the extension wraps. The cross-cutting conclusion held: **the egress proxy, not the
extension, is the realistic inline path for all of them**, every one is
Chromium/Electron-derived and should honor system proxy + OS trust store, the mechanism
we already deploy for desktop apps. The protocol parsing is now built; what remains is
verifying it against real builds, and none of that is possible on Linux (no Linux builds
exist).

- **Perplexity Comet, the priority. Parsing shipped, unverified.** macOS/Windows/mobile.
  Agent prompts flow as SSE to `www.perplexity.ai/rest/sse/perplexity_ask` and automation
  over `wss://www.perplexity.ai/agent` (Zenity Labs teardown). The proxy now parses both:
  the ask request/response (dedicated parser, blockable on the request side, tee-and-scan
  on the streamed SSE response, parse-miss findings on shape drift) and the agent
  WebSocket (channel-open flag + per-frame scanning). Synthetic Zenity-shape fixtures +
  an offline self-test (`python3 proxy/palivane_addon.py --selftest-comet`) let a field
  engineer validate against a real capture. The sidecar originates prompts from an
  extension/WebUI context our MAIN-world fetch wrap can't see, so the extension won't
  capture assistant prompts even though it installs fine, but Comet supports the full
  Chromium enterprise policy suite incl. `ExtensionInstallForcelist` (MDM target
  `ai.perplexity.comet`), so the managed rollout ports directly and still covers ordinary
  in-tab AI use. **Verify on macOS/Windows** (runbook §1): managed-storage flow, sidecar
  invisibility (expected), SSE plaintext-inspectability/pinning, if the pinning check
  passes, Comet inline enforcement ships via the egress proxy alone.
- **ChatGPT desktop (Atlas's successor). Covered by existing parsing, client behavior
  unverified.** OpenAI discontinued Atlas as a standalone browser on 2026-07-09 and folded
  it into the ChatGPT desktop app (Chat/Work/Codex modes with built-in browser; Mac +
  Windows). Not an extension host, the egress proxy is the only path; traffic is the
  `chatgpt.com` backend the catalog and proxy already know, and the suffix match covers
  every subdomain the app uses. **Verify on macOS/Windows** (runbook §2): system-proxy +
  trust-store behavior of the desktop app, and per-mode host inventory.
- **Dia (The Browser Company / Atlassian), least visible, least urgent. Discovery only,
  deliberately no parsing.** macOS-only (Windows "fall 2026", no Linux signal). The AI
  sidebar talks to Dia's hosted backend, which relays to model partners, egress never
  sees model-provider hosts, only Dia's, and the actual API hostnames are unverified: the
  `diabrowser.com` catalog row is now explicitly flagged (`PROVISIONAL` in
  `backend/app/ai_catalog.py`, surfaced on classify hits) and the proxy does not intercept
  it. No documented enterprise-policy surface. **Verify on Apple-Silicon macOS** (runbook
  §3): mitmproxy capture of the sidebar's real API hosts, then add catalog rows, drop the
  provisional flag, check pinning, parsing only after that.

Listed as a known gap on /coverage (copy reflects: parsing shipped, verification pending).

## SaaS-AI OAuth discovery, fetchers + smoke harness built, real-tenant runs pending

The OAuth-grant ingest (`POST /api/discovery/oauth-grants`) covers the mechanism, and the
connector framework (`backend/app/saas_connectors.py` + `/api/discovery/connectors`) now
does **live pulls**: store a platform admin credential (encrypted at rest), sync on demand
or from an operator cron, grants land through the same ingest path as a manual export.
Live fetchers in the PLATFORMS registry:

- **Google Workspace**, service account with domain-wide delegation; per-user token
  inventory from the Admin SDK. Validated against a real tenant.
- **Microsoft 365 / Entra ID**. Graph client-credentials app; `servicePrincipals` +
  `oauth2PermissionGrants` (delegated consents, principal resolved to UPN) +
  `appRoleAssignments` (app-only grants, role GUIDs resolved to names).
- **Slack**, org-admin token (Enterprise Grid, `admin.apps:read`);
  `admin.apps.approved.list` gives org-approved apps + scopes (approval-level, no
  per-granting-user attribution, that's all Slack exposes).
- **Salesforce**, connected-app client-credentials flow; `OauthToken` sObject gives
  (app, user) grants. Salesforce exposes no per-token scopes, so broad-scope flagging
  is unavailable there.
- **Notion**, registered **manual-export-only**: Notion's public API has no endpoint to
  enumerate a workspace's installed integrations or their grants (integration-scoped API,
  SCIM is users/groups only, audit log is a UI/SIEM export, verified Aug 2026). Sync
  returns an actionable error pointing at the manual ingest.

M365/Slack/Salesforce fetchers are built against the documented API shapes with mocked-
HTTP tests, and the real-tenant smoke harness is shipped: `scripts/connector_smoke.py`
runs one live fetch per platform, auth leg, grant count, truncation-sentinel presence,
redacted row sample, ingest-shape validation, final `SMOKE: PASS/FAIL`, with the
per-platform tenant-setup runbook (app registrations, tokens, permissions, gotchas) in
`docs/connector-smoke-tests.md`. What's still pending is the actual runs: each of
M365/Slack/Salesforce stays unvalidated until its smoke passes against a real admin
tenant. Grant timestamps are not carried, the ingest grant shape has no time field.
