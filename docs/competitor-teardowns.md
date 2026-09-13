# Competitor teardowns

The feature-by-feature detail [competitive-position.md](competitive-position.md) says it
lacks: *"what to say when a prospect has Harmonic in the other tab."* Five teardowns here —
Prompt Security, Nightfall, Knostic, Harmonic, and Lakera — in the same honest register:
verified claims are sourced to the vendor's own site; anything secondhand is labelled and
treated as adversarial.

**Read the caveats.** These were assembled from public web sources in **September 2026**.
Vendor sites change; acquisitions happen (one already did — see Prompt Security). Verify any
specific number against a primary source before repeating it to a prospect. Comparison sites
and vendor competitor-blogs were deliberately excluded or flagged.

**The uncomfortable cross-cutting finding, up front:** the "capture-surface breadth" moat is
*narrower than the pitch implies*. Nightfall already ships a browser plugin, SaaS
integrations, endpoint agents, and an MCP gateway; Prompt Security ships a browser/endpoint
sensor and shadow-MCP discovery. The surfaces that are still genuinely differentiating are
the **egress proxy**, **SaaS OAuth _discovery_** (as opposed to per-app integrations), and
**local _stdio_ MCP inspection** — plus the **free self-hosted edition**, **published
per-seat pricing**, and the specific **agent primitives** (identity attestation, A2A graph)
that none of the three evidence. Lead with those, not with a generic "we cover more surfaces."

---

## Prompt Security — now "Prompt Security | From SentinelOne"

**Landscape change:** founded 2023 (Tel Aviv), **acquired by SentinelOne in 2025** and now
marketed as part of the SentinelOne platform. Treat it as an incumbent-backed offering, not a
startup, in any deal.

- **What they are** — enterprise GenAI-security platform: "discover, govern, and protect AI
  usage across every employee and developer," plus protection for homegrown AI apps and
  agents. Primary surface is employee/shadow-AI usage (browser + endpoint), extending to a
  gateway/"AI firewall" for homegrown apps. SaaS confirmed; on-prem edition claimed only by
  secondary sources (unverified).
- **Surfaces** — browser extension / endpoint sensor with DOM-level inspection and shadow-AI
  discovery (confirmed); gateway/reverse-proxy for homegrown apps (confirmed, mechanics not
  detailed); **shadow MCP + unsanctioned-agent discovery** (confirmed). SaaS OAuth app
  discovery: not found on primary pages. Self-host: unconfirmed.
- **Detection** — both DLP (redaction/scrubbing) and adversarial (prompt injection,
  jailbreak, data poisoning). Methodology (ML vs rules) not disclosed.
- **Pricing** — not published; demo-gated. Azure Marketplace listing exists (terms not
  retrievable).
- **Agent story** — real and marketed: "map every agent and MCP server, then govern what
  they can do"; endpoint sensor claims to detect new agents and restrict risky capabilities.
  **Agent identity attestation and A2A governance are not mentioned on primary pages.**
- **Palivane wins:** SaaS OAuth *discovery* and local *stdio* MCP inspection (neither shown);
  the specific agent primitives (attestation that *blocks* unattested tool calls, A2A graph,
  read-only analyst) vs their higher-level "governance"; free self-host; published $12/seat;
  fail-open commitment.
- **Palivane loses:** SentinelOne's detection heritage, reference customers, MSSP GTM, and
  broad service coverage. Our low injection recall and no cited production tenant are exactly
  where an incumbent out-positions us in enterprise deals.

Sources: sentinelone.com/platform/securing-ai-prompt/, prompt.security/ (+ browser/endpoint
sensor blog), SentinelOne acquisition press release. Acquisition price conflicts across
secondary sources ($250M vs $300M) — unverified.

---

## Nightfall AI — "the AI-native DLP platform"

- **What they are** — a DLP company repositioned around AI: "AI Moves Your Data. Nightfall
  Controls It." SaaS only ("no agents to install" for SaaS integrations; deploy in <1 hour).
  Primary surface is sensitive-data control across SaaS apps, GenAI apps, browsers, endpoints.
- **Surfaces** — browser plugins; lightweight macOS/Windows endpoint agents (via MDM);
  API-based SaaS integrations (Slack, Drive, Gmail, Salesforce, Teams, OneDrive, SharePoint,
  Jira, Confluence, Notion, Zendesk); and an **MCP Gateway** to govern AI agents. **No
  on-prem/self-host** (SaaS only). Messaging points to *remote* MCP; local stdio not
  confirmed. They explicitly disclaim "invasive proxies."
- **Detection** — strongly **ML-based**, their moat: "replace regexes and rules with… high
  accuracy detectors trained with machine learning," ~95% precision claimed, 100+ models,
  across PII/PHI/PCI/secrets. Prompt injection covered on the developer platform.
- **Pricing** — enterprise demo-gated (plan names shown, dollar figures blanked: "$ per
  user/year"). A genuine **free developer tier** exists but is usage-capped SaaS (3 GB
  scanned/month). AWS Marketplace listings exist (contract pricing).
- **Agent story** — real: MCP Gateway, an "MCP & AI Agent Security" category, and **Nyx**, an
  "autonomous DLP analyst… that sees, reasons, and acts." Data-classification-centric.
  **Agent identity attestation, A2A flow graphs, and blocking unattested tool calls are not
  evidenced.**
- **Palivane wins:** free self-host (they're SaaS-only); published per-seat pricing; the agent
  *primitives* (attestation/A2A) vs their data-classification agent story; local stdio MCP;
  egress proxy; SaaS OAuth *discovery*; fail-open.
- **Palivane loses:** detection quality — their ML detectors almost certainly beat our regex
  on recall and phrasing (this is their whole moat). Real customers, named investors,
  marketplace listings. And note **surface parity is closer than assumed** — they already
  have browser + SaaS + endpoint + MCP gateway.

Sources: nightfall.ai (+ /platform, /pricing, /firewall-for-ai), help.nightfall.ai developer
pricing, AWS Marketplace. Nightfall's own competitor-comparison blogs excluded as adversarial.
Some /products/* paths 404'd; the platform page was used instead.

---

## Knostic — "need-to-know access controls for enterprise AI"

**This is an adjacent category, not a head-to-head.** Knostic answers "what can this LLM
reveal from the corpus" (data-access / entitlements / oversharing). Palivane answers
shadow-AI capture + prompt/tool-call inspection + inline agent governance. When they overlap
it's at the edges.

- **What they are** — "GenAI Knowledge Security Platform" / "IAM for LLMs"; core problem is
  **LLM oversharing** via enterprise assistants (Copilot for M365, Glean). SaaS,
  per-client-isolated (explicitly not multitenant). Tagline has broadened to "Security Across
  the Agentic Lifecycle" with a coding-agent/MCP line (Kirin).
- **Surfaces** — enterprise LLM assistants (Copilot, Glean confirmed; Gemini/Einstein
  future); coding agents / IDEs / MCP servers (via Kirin); a "Shadow AI Spotlight" (scope
  unclear — no confirmed browser extension or egress proxy). SaaS OAuth discovery: not found.
- **Mechanism** — knowledge-layer, need-to-know oversharing detection via **simulated
  prompts** (red-team-style simulations against actual user entitlements, 20+ prompt patterns
  per persona), with file-level remediation and auto-labeling. Primarily monitor/scan +
  role-based access, **not inline proxy blocking**. Not DLP-first, not injection-first.
- **Pricing** — unusually, publishes per-seat tiers for AgentMesh: free tiers, Premium
  $15/user/mo, Pro $850/user/mo, Enterprise custom (10+). Core Copilot-readiness platform is
  demo-gated. AWS Marketplace listing exists (a ~$50k/yr figure is secondary/unverified).
- **Agent story** — AgentMesh (right-knowledge scoping for agents), Kirin (coding-agent/MCP
  safety), and OpenAnt (open-source, self-hostable LLM vuln-discovery tool). **No agent
  identity attestation, A2A graph, or inline tool-call blocking** as Palivane frames it.
- **Palivane wins:** capture-surface breadth (browser, egress proxy, OAuth discovery, local
  stdio MCP — none confirmed at Knostic); inline agent governance (attestation/A2A/analyst vs
  their scan+label); free self-host (only their narrow OpenAnt tool is self-hostable);
  transparent $12/seat vs their $15 floor / $850 Pro; fail-open.
- **Palivane loses / doesn't address:** need-to-know oversharing for Copilot/Glean — deep
  entitlement simulation and file-level remediation Palivane's prompt model doesn't do.
  Gartner Cool Vendor recognition, named funding, published AgentMesh catalog, AWS private
  offers. If the buyer's problem is "Copilot exposes salary data," Knostic owns that framing;
  Palivane must reframe toward capture + inline control.

Sources: knostic.ai (+ /what-we-do, /the-genai-knowledge-security-platform, AgentMesh tiers
blog, OpenAnt blog). AWS Marketplace seller profile and funding/about pages are secondary.

---

## Harmonic Security — "AI Governance & Control Platform"

**Independent** (Series A ~$17.5M, Apr 2025; ~$26M total — no acquisition found). Browser-
and desktop-first, and the closest surface overlap to Palivane of anyone here.

- **What they are** — governance platform built on understanding *how* AI is used, so
  "security decisions follow the work instead of blocking it." Multi-surface SaaS, rolled out
  via Intune/JAMF/Kandji/Group Policy. Three tiers: Explore (discovery), Guide (real-time
  browser/desktop control), Command (governance for humans + agents). No self-host advertised.
- **Surfaces** — browser extension across 10+ browsers (Chrome, Edge, Firefox, Safari, Arc,
  Brave, Comet, Dia…); desktop AI apps (Claude Desktop, ChatGPT Desktop, Cursor, Windsurf);
  embedded AI (Canva, Grammarly, Google AI mode); and an **MCP gateway on Windows/macOS/
  Linux** for agentic workflows. Egress proxy, SaaS OAuth *discovery*, dedicated endpoint DLP:
  not confirmed on primary pages (discovery reads as browser/desktop telemetry, not OAuth-graph).
- **Detection** — explicitly anti-regex: "classify the meaning of the work, not the shape of
  the string," via small language models reading the full interaction in <200 ms. No prominent
  prompt-injection claim.
- **Pricing** — demo-gated on their own site, but their **AWS Marketplace listing publishes
  ~$163/user/year** (12-month, 200-user minimum). That's ≈ $13.60/user/mo — **comparable to
  our $12**, so pricing is *not* a clean win against Harmonic; say so.
- **Agent story** — real and specific: govern "at the MCP layer and the tool surface,"
  granular per-MCP-server read/write/act permissions, "least agency" + human oversight for
  high-risk tasks. **No agent identity attestation, unattested-tool-call blocking, or A2A flow
  modeling found.**
- **Palivane wins:** free self-host (Harmonic has none); the specific agent primitives
  (attestation + *blocking* unattested tool calls + A2A graph) vs their MCP permissions;
  egress proxy, OAuth discovery, local stdio MCP; fail-open.
- **Palivane loses / caveats:** **browser-surface overlap is real and Harmonic's is likely
  broader** (10+ browsers, desktop apps, embedded AI) — do not out-claim browser breadth. Their
  ML/SLM data detection beats our regex; they have funding, a marketplace listing, and implied
  customers; we have no cited tenant. And pricing is a wash, not a win.

Sources: harmonic.security (+ /products/harmonic-protect, /pricing, /solutions/ai-agent-
security-mcp-gateway), Harmonic's own AWS Marketplace listing. Funding figures secondary.

---

## Lakera — "Lakera Guard," now a Check Point company

**Acquired by Check Point Software (announced Sept 16, 2025)**; now the foundation of Check
Point's "Global Center of Excellence for AI Security," folded into the Infinity platform.

**This is a different category — an API guardrail you embed in an app you build**, the same
distinction Palivane's own docs draw for LLM Guard / NeMo. Lakera is *not* a capture plane.

- **What they are** — AI-native runtime protection for GenAI/agents/MCP, API-first SaaS.
  Flagship **Lakera Guard**: a low-latency detection API (`POST api.lakera.ai/v2/guard`),
  called from your own app via any HTTP client.
- **Surfaces** — inline in the app's LLM path only. **No browser extension, egress proxy, or
  SaaS OAuth discovery** in Guard's own docs. Self-host exists (Docker / Helm / air-gapped) but
  is **Enterprise-license-only**. MCP/agent: "AI Agent Security" protects prompts, RAG, and
  MCP-connected tools incl. indirect injection, plus action governance. (Parent Check Point
  markets shadow-AI/browser discovery separately — not Guard's path.)
- **Detection (their strength)** — real-time ML across prompt attacks (injection/jailbreak),
  data leakage/PII, content violations, malicious links; trained on the largest prompt-injection
  corpus, sourced from their **Gandalf** game (Check Point cites 80M+ adversarial patterns),
  sub-50 ms latency claimed.
- **Pricing** — a free developer tier exists (~10k requests/mo — JS-gated page, treat the exact
  cap as lightly verified); Pro/Enterprise are quote-gated. No published per-seat pricing.
- **Agent story** — strong and current (MCP tool discovery, indirect-injection protection,
  action governance). Agent-to-agent and *identity attestation* not explicitly claimed —
  governance is framed as guardrails/policy, not identity.
- **Palivane wins:** capture breadth — browser, egress proxy, OAuth discovery, local stdio MCP
  — none of which Lakera Guard sits in front of (it only sees paths the app author wires it
  into); inline agent governance with *identity* (attestation/A2A/analyst); free self-host
  (Lakera gates self-host behind Enterprise); published per-seat pricing; fail-open.
- **Palivane loses — decisively — on prompt-injection detection.** Lakera is best-in-class,
  ML-trained on the largest real attack corpus. This is exactly our stated weakness (regex,
  ~0.22 recall on real injections). **Do not compete on detection accuracy here** — compete on
  placement, breadth, and identity-aware governance.

Sources: lakera.ai (+ /ai-agent-security), Check Point acquisition press release, docs.lakera.ai
(quickstart, selfhosting), Lakera Gandalf datasets on Hugging Face. Pricing page JS-gated
(secondary).

---

## What to actually say in the room

1. **"Prompt firewall" framing** → pivot to identity + action: "attestation and the A2A graph
   are about *which agent, attested how, called which tool, and fed which downstream agent* —
   not just whether a string looks malicious." None of the five evidence attestation or A2A.
2. **"We already have a browser extension / MCP" (Nightfall, Prompt Security, Harmonic)** →
   concede the surface — Harmonic's browser coverage is probably *broader* than ours, don't
   pretend otherwise — and move to the *differentiated* ones: egress proxy, OAuth discovery,
   local stdio MCP, and **free self-host** (Nightfall and Harmonic are SaaS-only).
3. **"Your detection is worse" — especially vs Lakera/Check Point** → true on injection recall;
   **do not argue it, and never argue it against Lakera** (they're the best-in-class injection
   detector, trained on the Gandalf corpus — this is their whole moat). Say: "For secrets and
   PII, deterministic precision is the product — we don't cry wolf, which is what makes
   enforcement survivable. For injection phrasing, a specialist out-detects us today." Then move
   back to breadth + agent governance + self-host. Note Lakera is a *library you embed*, not a
   capture plane — often complementary to us, not competing.
4. **Knostic in the tab** → "different problem." They do need-to-know oversharing for Copilot;
   we do shadow-AI capture and inline agent control. Often complementary, not competing.
5. **Price** → we publish $12/seat. Prompt Security, Nightfall, and Lakera are demo-/quote-
   gated above any free tier. The two that publish are *not* a clean loss to argue: Knostic
   floors at $15 (and jumps to $850 for Pro), and Harmonic's marketplace price (~$13.60/mo) is
   roughly ours — so lead with *transparency* ("here's the number, on the page"), not "cheaper."

**The standing weakness across all five:** no cited production tenant. Every teardown ends at
the same place competitive-position.md does — one referenceable pilot resolves the maturity
gap that these incumbents win on.
