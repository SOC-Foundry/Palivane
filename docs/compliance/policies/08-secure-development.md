# 08 — Secure Development Policy

**Owner:** Founder · **Effective:** 2026-07-19 · **Review:** annual

## Standards

- **Tests are the gate:** the backend suite (700+ tests, including dedicated security
  suites — tenant isolation, authn/z, SSRF, redaction, encryption, RLS) must pass in
  CI before any merge (Policy 03).
- **Security-relevant invariants get tests**, not comments: every audit finding fixed
  in July 2026 landed with a regression test.
- **Input handling:** Pydantic schema validation at every API boundary; SSRF guards on
  all user-supplied URLs (webhooks, SIEM, upstreams) at write time and send time;
  size caps on content fields.
- **Secrets hygiene:** no credentials in code, images, or env files — Secret Manager
  only; the repo's own product (warden-secrets) scans for credentials at rest.
- **Dependencies:** minimal by design (CLI tools are stdlib-only on purpose);
  lockfiles committed; Palivane's own dependency-risk detector and OSV data inform
  updates; GitHub alerts triaged as they arrive.
- **AI-assisted development:** all AI-generated changes flow through the same PR + CI
  gate as human ones; the Founder reviews and owns every merge (sole commit author).

## Reviews and testing

- Internal adversarial security audits: two multi-perspective audits completed July
  2026 (authn/MFA, path traversal, SSRF, TOTP replay, extension XSS, deploy posture,
  tenant isolation) — all findings remediated on `main`.
- Third-party penetration test: scheduled under the SOC 2 program; findings will be
  tracked in the risk register to closure.

## Environments

Development uses local SQLite and seeded demo data — never production data. The demo
org is synthetic. Production operator tasks run as auditable one-off Cloud Run jobs.
