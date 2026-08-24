# 06. Vendor & Third-Party Risk Management

**Owner:** Founder · **Effective:** 2026-07-19 · **Review:** annual

## Approved subprocessors (customer data may transit/reside)

| Vendor | Purpose | Data exposure | Their attestations |
|---|---|---|---|
| Google Cloud | Hosting, database, secrets, build, monitoring (us-central1) | All service data | SOC 1/2/3, ISO 27001 |
| Cloudflare | Edge/TLS/WAF for app.palivane.io | Traffic in transit | SOC 2, ISO 27001 |
| Anthropic | LLM judge (detection quality) | Scanned content, only when the org's judge is enabled (per-org opt-out; no training on API data) | SOC 2 |
| Google Workspace | Transactional email | Email addresses, notification metadata | SOC 2, ISO 27001 |

Public list mirrored on /trust; the DPA commits to notifying customers of additions.

## Supporting vendors (no customer data)

GitHub (source + CI, repo is access-controlled and branch-protected), npm/PyPI
(dependencies, see Policy 08 supply-chain controls), VS Code/Chrome marketplaces
(distribution only).

## Adding a vendor

Before use: confirm security attestation (SOC 2 or equivalent), data location,
subprocessor terms; grant least-privilege scopes; record it here via PR (the change
gate is the approval record). Vendors are reviewed annually, attestation still
current, scopes still minimal, still needed at all.

## Concentration note

Google is a deliberate concentration (hosting + email + identity) accepted for
operational simplicity at current scale; recorded in the risk register with the
full-rebuild procedure (Policy 05) as the mitigation.
