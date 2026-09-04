# Risk register

Reviewed at least annually (or after material change). Scoring: likelihood × impact, 1–3
each; treat ≥6 first. Last review 2026-09.

| # | Risk | L | I | Score | Treatment |
|---|---|---|---|---|---|
| 1 | Single-maintainer bus factor (ops + code + audit trail in one person) | 2 | 3 | 6 | Documented runbooks (`deploy/`, `ops.yml`), IaC, break-glass doc for successor; hire is the real fix |
| 2 | Tenant data exposure via app vulnerability | 1 | 3 | 3 | RLS beneath app scoping, per-tenant DEKs, bug bashes, planned external pentest |
| 3 | Supply-chain compromise (deps, actions) | 2 | 3 | 6 | Pinned actions in our own CI, dependency updates via PR + CI, palivane-ci-scan dogfooded on this repo |
| 4 | Provider key leak (gateway/judge upstream keys) | 1 | 3 | 3 | Secret Manager only, per-tenant sealed keys, no keys in code/env files, rotation via secret versions |
| 5 | Prod deploy of a bad build | 2 | 2 | 4 | Manual deploy gate, image-by-SHA, verified rollback (redeploy prior SHA), post-deploy live verification |
| 6 | Cloudflare/GCP regional outage | 1 | 2 | 2 | Documented RTO/RPO (BCDR policy); Cloud SQL PITR; single-region accepted at current scale |
| 7 | Compromised founder workstation | 2 | 3 | 6 | Disk encryption + screen lock + MFA everywhere; endpoint control formalized in P1 gap #11 |
| 8 | GitHub account takeover → main push (no branch protection today) | 2 | 3 | 6 | P0 gap #1: GitHub Team upgrade + required PR/checks; hardware-key MFA on the org |
