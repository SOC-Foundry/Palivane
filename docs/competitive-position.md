# Competitive position

What Palivane can defensibly claim, what it cannot claim yet, and where the evidence for
each lives. Written in the same register as [the coverage matrix](../frontend/src/components/CoverageMatrix.jsx):
the gaps are here on purpose, because a positioning doc that only lists strengths is a
brochure, and sales improvising the weak answers in a live call is worse than sales
reading a prepared honest one.

Companion docs: [roadmap-frontier.md](roadmap-frontier.md) (what is genuinely not shipped),
[ml-classifier-baseline.md](ml-classifier-baseline.md) (the detection numbers below, with
their methodology).

---

## The one-line version

**The moat is capture breadth, not detection IP.** Palivane sees prompts on more surfaces
than anyone asking about it expects, and each surface is real integration work with its own
OS, browser and enterprise-policy grief. That is the durable asset. Detection quality is
deliberately deterministic today, which is the right call for secrets and the honest
weakness for injection.

State it that way round. Leading with detection quality invites a comparison Palivane does
not currently win.

---

## 1. What is the moat?

### The defensible claim: surface coverage

A competitor does not out-feature this; they have to rebuild every plane:

| Plane | Covers | Why it is hard to copy |
|---|---|---|
| Browser extension | In-tab AI use (ChatGPT, Claude, Gemini, …) | MV3, per-site DOM/fetch interception, managed-policy rollout |
| Gateway (`llm_io`) | Claude Code, Cursor, Codex, Copilot, Gemini CLI | Per-tool hook formats, and a base-URL override path per SDK |
| Egress proxy | Desktop apps, agentic browsers, anything without a base-URL knob | mitmproxy + a CA + system proxy per OS, plus TLS-inspecting-VPN coexistence |
| SaaS OAuth discovery | Third-party AI apps granted access to Workspace/M365/Slack/Salesforce | Four different admin APIs, four different consent models |
| MCP wrapper (`cli/palivane-mcp`) | Local stdio MCP servers | Nobody else is inspecting this surface inline |
| MCP server (`mcp-server/`) | Palivane itself, from the assistant | Product surface, not just capture |

The MCP planes are the sharpest wedge: local stdio MCP servers never touch the network, so
an egress-based competitor structurally cannot see them.

### The second claim: fail-open as a stated commitment

*"A down security control must never take engineering down with it."* It is enforced in the
clients, not just asserted in copy. Security tools that wedge developer workflow get removed,
and every buyer who has been burned by one knows it. This is a real differentiator and costs
nothing to say.

### The third claim: inline agent governance (the agent-era wedge)

Newer than the surface-coverage argument, and increasingly the reason a prospect is shopping
at all. Palivane governs what agents *do*, inline, not just what prompts contain:

| Capability | What it does | Where the evidence lives |
|---|---|---|
| Agent identity attestation | Binds a tool call to a workload-identity (OIDC) agent; an unattested call (`ag_` bearer or none) is flagged, and with enforcement on, hard-blocked | `app/main.py` `_agent_attestation` / the `agent_attestation` signal; `test_agent_attestation.py` |
| A2A flow graph | A directed graph of which agent fed which, carrying the message count and the worst risk that crossed each hop | `app/agent_graph.py`; the Agents tab |
| The analyst | A read-only investigator that gathers a finding's context + the actor's recent activity and recommends dismiss / triage / keep-open with a rationale and calibrated confidence — never acts on its own | `app/analyst.py`; `POST /api/findings/{id}/investigate` |
| Least-privilege agent roles | Per-agent authz (an `AgentRole` allowlist of tools) so an agent token can only do what its role permits, enforced on the gateway and tool-call paths | `app/authz.py`, the `AgentRole` model, `_agent_authz_probe` / `_gw_authz` |
| Local MCP inspection | Sees tool calls on local stdio MCP servers that never touch the network | `mcp-server/` wrapper (also the moat table below) |

Why this is a distinct axis from the scanner vendors: attestation and the A2A graph are about
*identity and action*, not *prompt content*. An injection-focused competitor can out-detect a
malicious string and still have nothing to say about "which agent, attested how, called which
tool, and fed which downstream agent." That is the sentence to use when a prospect frames the
category as "prompt firewall."

**The honest counterweight** (same register as everything else here): this axis is the
*least* tenant-proven of the three moat claims. Attestation requires the tenant to wire
workload-identity OIDC (real config burden), the analyst's quality rides the optional LLM
judge tier, and none of it has run against real agent traffic yet — the same one-pilot
constraint as the rest of the doc. Claim the *architecture* (inline, identity-aware, on
surfaces a scanner isn't in); do not yet claim a measured outcome.

### What is NOT the moat, and must not be claimed as one

Detection quality. The shipping engine is regex + heuristics; the ML classifier exists but
**is not wired into the live path** and has not cleared its gate.

Measured, on our own benchmark:

| | precision | recall | corpus |
|---|---|---|---|
| regex (shipping) | 1.00 | **0.34** | synthetic injection paraphrases |
| regex (shipping) | — | **0.22** | human-written real injections |

Read that correctly before repeating it:

- **For secrets and PII, regex is the right tool and precision is the product.** A leaked
  `AKIA…` key is a deterministic match, not a judgment call. 1.00 precision means Palivane
  does not cry wolf, which is what makes enforcement mode survivable.
- **For prompt injection, 0.22 recall on real attacks is a real gap**, and
  `ml-classifier-baseline.md` says so plainly: *"Lakera/Nightfall/Harmonic catch phrasing,
  not just literals."*

So: claim determinism and precision where they are true, claim breadth everywhere, and do
not claim to out-detect an injection-focused vendor until the ML gate clears.

### The landscape, in two tiers that behave very differently

The single most useful thing to know here: **the free competition and the paid competition
are not the same companies, and they lose to us for opposite reasons.**

**Tier 1 — commercial AI-security vendors.** Harmonic, Nightfall, Knostic, Prompt Security
(**acquired by SentinelOne in 2025** — now an incumbent-backed offering, not a startup),
Lakera (acquired by Check Point). SaaS, sales-led. Per-competitor teardowns with sources are
in [competitor-teardowns.md](competitor-teardowns.md); two observations that matter:

- **None of them offers a free self-hosted edition.** Where free tiers exist they are
  usage-capped SaaS (Azure 5K records/month, Model Armor 2M tokens/month, Portkey 10K
  logs), not "run it yourself, indefinitely". Our free self-host is *more* generous than
  the field, not a concession to it.
- **None of them publishes usable prices on their own site**; every one routes to a demo.
  (They do list public pricing on AWS Marketplace — Harmonic and Knostic both do — which
  is a procurement channel, not a pricing page.) Publishing $12/seat is a different
  posture from the field, deliberately.

Where they beat us: detection of injection *phrasing* rather than literals — the axis
[ml-classifier-baseline.md](ml-classifier-baseline.md) already names.

**Tier 2 — the open-source guardrail layer.** LLM Guard (Protect AI, MIT), NeMo Guardrails
(NVIDIA), Presidio (Microsoft, MIT), Guardrails AI, Llama Guard. Genuinely free, genuinely
good, and the real competition for our free self-hosted edition.

**They are libraries, not deployed systems.** LLM Guard is "import scanners and call them
in your existing application code"; NeMo is a dialog-flow engine with its own DSL. They
protect an LLM app *you are building*. They have no browser extension, no egress proxy, no
SaaS OAuth discovery, no console, no attribution, no coverage reconciliation — they cannot
tell you someone in finance pasted a customer list into ChatGPT, because they were never in
that path.

That distinction is the whole argument, and it is the same one as the moat ordering above:
**we are not a better scanner, we are in places a scanner never is.**

**Sourcing caveat, and it matters if you are about to say this out loud:** most of the
pricing claims above come from comparison sites rather than vendor pages, and one is
Nightfall's own competitor blog, which is not a neutral referee. Verify against primary
sources before repeating any specific number to a prospect. What was actually read
(2026-09-09):

- [Nightfall, "Harmonic Security Alternatives"](https://www.nightfall.ai/blog/harmonic-security-alternatives) — Lakera/Check Point; **vendor blog, treat as adversarial**
- [accuroai, "What AI Security Actually Costs in 2026"](https://accuroai.co/blog/what-ai-security-actually-costs) — the "nobody publishes prices" finding, and the capped free tiers
- [tech-insider, "Harmonic vs Reco vs Nightfall 2026"](https://tech-insider.org/harmonic-vs-reco-vs-nightfall-shadow-ai-2026/)
- [LLM Guard](https://appsecsanta.com/llm-guard) and [NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails) — the library-not-system distinction
- [Cloudthrill, "LLM guardrail solutions: open source vs commercial"](https://cloudthrill.ca/llm-guardrail-solutions)

**Now closed (2026-09):** per-competitor teardowns for Prompt Security, Nightfall, and
Knostic exist in [competitor-teardowns.md](competitor-teardowns.md), with primary-source
citations and a "what to actually say in the room" section. **Still open:** Harmonic and
Lakera/Check Point have no teardown yet.

**The teardowns forced one honest correction to the moat.** Surface *breadth* is narrower
than the pitch above implies: Nightfall already ships a browser plugin, SaaS integrations,
endpoint agents, and an MCP gateway; Prompt Security ships a browser/endpoint sensor and
shadow-MCP discovery. The surfaces still genuinely differentiating are the **egress proxy**,
**SaaS OAuth _discovery_** (vs per-app integrations), and **local _stdio_ MCP inspection** —
plus free self-host, published pricing, and the agent primitives (attestation, A2A) none of
the three evidence. Keep the breadth claim, but lead with those specifics, not a generic
"we cover more surfaces."

---

## 2. What problem does it solve?

The best-evidenced answer, and the one to lead with. `/coverage` is the honest document:
every surface with what it actually needs, and the gaps listed deliberately. `check-claims.mjs`
fails the build when the marketing pages drift off it.

Use that as a **trust asset**, not a liability. Very few vendors in this category can show a
prospect a page listing what they do not cover. Showing it early converts the "what are you
hiding" reflex into "these people are honest."

---

## 3. Who cares?

**This is the weakest answer and no document can fix it.**

There is no named design partner or reference tenant anywhere in this repo.
[pilot-smoke-test.md](pilot-smoke-test.md) is a checklist *for* a pilot — it anticipates one
rather than evidencing one.

It also blocks the moat: the ML gate requires *"consented captures, analyst-labeled, held
out by time window"*, which means the detection story cannot improve until a real tenant
runs in production. One pilot unblocks the moat, the proof point, and the pricing test at
once.

---

## 4. Why will they care?

What exists: capability counts, drift-proofed by `gen-stats.mjs`.

What does not exist, and is worth more than any feature currently on the roadmap: **one
quantified outcome from one real tenant.** The shape to aim for —

> In their first week: N prompts containing credentials blocked, across M people nobody
> knew were using AI tools.

The second clause is the actual sale. Buyers do not know their shadow-AI population, and
discovering it is what makes the problem feel urgent rather than theoretical.

---

## 5. Will they pay?

Priced today: **Team $12/user/month** ($10 annual), **Enterprise** custom annual, 14-day
full-feature trial.

**The objection to have an answer ready for.** The public repo offers *"a free self-hosted
edition (full detection, no LLM key required)"*. So a technical buyer will ask, reasonably:

> Why pay $12/seat when the self-hosted edition is free and detection is complete?

**The answer is not detection.** The free open-source layer (LLM Guard, NeMo Guardrails,
Presidio) already has decent detection, and on injection recall it may well beat our regex
engine. Arguing detection here loses on the merits.

The answer is that **the free thing is a library and the paid thing is a deployed system.**
Those tools scan text you hand them, from inside an app you wrote. What $12/seat buys is
the part that is expensive to operate rather than expensive to compute: the capture planes
that see traffic nobody instrumented, per-person attribution, coverage reconciliation
against the shadow set, the console, hosting, and support. A team that only needs "scan
this string" should genuinely use LLM Guard, and saying so costs nothing — they were never
going to buy.

What remains a **pricing decision, not a docs task**, is where exactly the line falls: which
capabilities are in the free self-hosted edition versus Team. Today the public README says
free self-host gets *"full detection"*, which is the right thing to give away under this
argument — but nobody has decided whether it also gets, say, multi-user attribution or the
connectors. Until that is decided, the line gets drawn improvisationally per call.

Marketplaces matter to this question more than they look: enterprise procurement burns
committed cloud spend, which makes a marketplace listing *effectively discounted* against
an invoice vendor.

---

## 6. How will they hear about it?

The best-developed answer.

- **Chrome Web Store** — extension listing, live.
- **Public repo** (`SOC-Foundry/palivane-clients`) — everything that runs on a customer
  machine, auditable before install. A security buyer checks this.
- **`install.sh` one-liner** — self-serve, no sales contact.
- **Cloud marketplaces** — AWS/GCP/Azure runbooks written, with the sequencing already
  decided and justified: tiers 1–2 now, transactable billing only when a real deal asks.
- **MCP server + Product Hunt** — the current launch motion.

**Open:** whether the tier-1/2 marketplace listings were actually submitted. The runbook
says "this week"; nothing in the repo records that it happened.

---

## The honest summary

Palivane is **feature-rich and evidence-poor**. Nearly every competitive track reads *built,
unverified*: the ML gate is not cleared, agentic-browser parsing ships unverified (no Linux
builds exist to verify against), and three of four SaaS connectors have not been run against
a real tenant.

That is a normal place to be, and it is recoverable in one move rather than ten. The
constraint is not engineering; it is that four of the six questions above resolve the moment
one real tenant is in production and willing to be cited.
