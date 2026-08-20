# Security policy

## Reporting a vulnerability

Email **security@palivane.io** with a description, reproduction steps, and impact.
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
- The hosted service at app.palivane.io

## Security posture

See https://app.palivane.io/trust for the current public summary (encryption,
tenant isolation, backups, subprocessors, compliance status).

## Verifying downloads

The CLI installer verifies a signed release manifest (ECDSA P-256) and each script's
SHA-256 before running anything, and the served scripts are reproducible from a source
checkout. To verify by hand, see
https://app.palivane.io/docs/verifying-downloads.
