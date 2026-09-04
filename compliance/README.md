# SOC 2 program

Working directory for Palivane's SOC 2 Type II program. Scope: **Security,
Confidentiality, Availability** (Processing Integrity and Privacy deferred to a later
period). Same contract as the public `/trust` page: nothing in here describes a control
we don't actually operate — a policy that doesn't match reality is an audit finding, not
a head start.

## Layout

| Path | What it is |
|---|---|
| `soc2-gap-assessment.md` | Control-by-control readiness: what exists (with evidence pointers) and what doesn't (with the concrete action) |
| `policies/` | The policy pack — adopted versions are dated and versioned in each file's header |
| `vendor-register.md` | Subservice organizations and critical vendors, with data-access tiers and review dates |
| `risk-register.md` | The risk assessment worksheet (reviewed at least annually) |

## Roadmap

| Phase | Window | Work |
|---|---|---|
| **1 — Foundations** (now) | Month 0–1 | Adopt the policy pack; close the P0 gaps in the assessment (branch protection, uptime monitoring, access-review cadence, restore test); stand up the risk + vendor registers |
| **2 — Platform & auditor** | Month 1–2 | Choose the compliance-automation platform (decision deferred, see assessment §Platform), connect GCP/GitHub/Workspace integrations, engage the auditor, fix whatever the platform's automated checks flag |
| **3 — Type I** (optional but useful) | Month 2–3 | Point-in-time audit: proves design of controls, gives sales a document a year before the Type II lands |
| **4 — Observation window** | Month 3–9 | Operate the controls; evidence accrues automatically (access reviews, change tickets = PRs, incident drills, backup-restore tests on calendar) |
| **5 — Type II audit** | Month 9–12 | Fieldwork over the observation window; report issued |

## Ground rules

- **Evidence is a by-product, not a project.** Controls that generate their own records
  (PR history, audit_log table, Secret Manager versions, Terraform state) beat controls
  that need a human to remember a screenshot.
- **One owner.** The Security Officer (currently the founder) owns every control below
  until the org is big enough to delegate; the policies say so plainly rather than
  inventing committees an auditor will ask to meet.
- **Solo-maintainer reality is documented, not hidden.** Where a control normally
  assumes two people (peer review, separation of duties), the compensating controls are
  written down in the gap assessment and in the relevant policy.
