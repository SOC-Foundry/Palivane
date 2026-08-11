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

**Status: positioning decision.** The MCP 2026-07-28 spec makes EMA an official extension —
IdPs govern client-to-server access natively, which erodes standalone identity value. The
move is to integrate rather than compete: act as the **PEP / audit layer** for EMA policy
(Palivane's agent identity + session audit already sit in the right place). This is a design
+ partnership decision to make before writing code, not a detector to add.

## Agentic browsers (Atlas / Comet / Dia)

**Status: partial — discovered, not inline-intercepted.** These browsers run the agent
themselves, so the model call doesn't come through a page fetch the extension wraps. Today
we discover the usage where it reaches a known model host; inline interception needs
per-browser work (each exposes different hooks, if any). Listed as a known gap on /coverage.
Next step: verify extension behavior in each and evaluate a native-messaging or
browser-policy path.

## SaaS-AI OAuth discovery — live pulls shipping, per-platform buildout

The OAuth-grant ingest (`POST /api/discovery/oauth-grants`) covers the mechanism, and the
connector framework (`backend/app/saas_connectors.py` + `/api/discovery/connectors`) now
does **live pulls**: store a platform admin credential (encrypted at rest), sync on demand
or from an operator cron, grants land through the same ingest path as a manual export.
First connector: **Google Workspace** (service account with domain-wide delegation).
Remaining work is per-platform fetchers in the PLATFORMS registry — M365 (Graph
`servicePrincipals`/`oauth2PermissionGrants`), Slack, Salesforce, Notion, … — each an
admin-API client that normalizes to the same grant shape.
