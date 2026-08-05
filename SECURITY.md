# Security policy

## Reporting a vulnerability

Email **security@tachtech.net** with a description, reproduction steps, and impact.
You'll get an acknowledgment within 2 business days and a status update at least every
7 days until resolution.

- Please give us a reasonable window to fix before public disclosure (we aim for a fix
  or mitigation within 90 days, faster for critical issues).
- Good-faith research against your own Palivane org (or a self-hosted instance you run)
  is welcome. Don't access other tenants' data — use two orgs you control to test
  isolation. No volumetric/DoS testing against the hosted service.
- No bug bounty program yet; we credit reporters in release notes if desired.

## Scope

- This repository (backend, frontend, CLI tools, browser and VS Code extensions,
  deploy tooling)
- The hosted service at palivane.tachtech.net

## Security posture

See https://palivane.tachtech.net/trust for the current public summary (encryption,
tenant isolation, backups, subprocessors, compliance status).
