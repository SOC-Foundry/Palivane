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

### Known competitors, and what we actually know about them

Thin, and worth marking as thin rather than dressing up:

- **Harmonic, Knostic** — both list on AWS Marketplace with public pricing
  ([marketplaces/README.md](../marketing/marketplaces/README.md)).
- **Lakera, Nightfall, Harmonic** — named in the ML baseline as catching phrasing rather
  than literals, which is the specific axis where the regex engine loses.

**Open:** no feature-by-feature teardown of any competitor exists. If a deal is lost on
comparison, that is the first thing to write.

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

That is a deliberate open-source strategy, and the answer is presumably hosting, support,
the console, and the enterprise controls — but **it is not written down anywhere**, which
means it currently gets improvised per call. Writing it is a pricing decision, not a docs
task, so it is flagged here rather than answered.

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
