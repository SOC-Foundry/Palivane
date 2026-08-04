# 09 — Risk Management Policy

**Owner:** Founder · **Effective:** 2026-07-19 · **Review:** annual (register: continuous)

## Method

Risks are assessed on likelihood × impact (High/Medium/Low), owned, and given a
treatment: mitigate, accept (with rationale), or transfer. The register lives in this
file and is updated whenever architecture or business context changes materially —
via PR, so history is the audit trail.

## Register (2026-07-19)

| Risk | L | I | Treatment |
|---|---|---|---|
| Single-operator dependency (availability of the one human) | M | H | Mitigate: full runbook/IaC coverage so any competent engineer can operate from the repo (Policy 05); accept residual until first hire |
| Tenant-isolation defect exposes cross-org data | L | H | Mitigated: RLS beneath app scoping, isolation test suite, adversarial audits; pen test scheduled |
| Credential/secret leak (operator or supply chain) | M | H | Mitigated: Secret Manager only, hashed keys, short-lived agent tokens, rotation runbook (exercised 2026-07-16), Palivane dogfoods its own secret detection |
| Credential stuffing / abuse of public signup | M | M | Mitigated: edge per-IP limits, app throttles, email verification, domain capture, quotas/lifecycle |
| us-central1 regional outage | L | M | Accept at current scale; rebuild procedure documented (Policy 05) |
| Google vendor concentration | L | M | Accept; documented in Policy 06 |
| Judge provider (Anthropic) unavailability | M | L | Mitigated: detection degrades to the pattern engine automatically; multi-provider judge support exists |
| Dependency/supply-chain compromise | M | H | Mitigated: minimal deps, lockfiles, CI gate, MCP binary pinning for our own tooling; monitor |
| Marketplace account compromise (extension distribution) | L | M | Mitigated: MFA on accounts; extensions are thin clients with no standing credentials |

## Inputs

Audit findings, incident post-mortems, pen-test results, vendor reviews, and dependency
alerts all feed the register. Every High-impact mitigation must map to a tested
control, not an intention.
