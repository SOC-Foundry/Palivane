# Licensing — vendor runbook

How Warden (the vendor) grants Team / Enterprise tiers. Two mechanisms, one per
deployment model:

| Deployment | The license is… | You grant it with… |
|---|---|---|
| Hosted SaaS (warden.tachtech.net) | the `tenant.plan` column | `set-plan` (below) |
| Self-hosted | a signed `WDN1.…` license file | `app.licensing issue` (below) |

Plan gates and quotas live in `backend/app/plans.py`; the license format and
verification in `backend/app/licensing.py`. Customer-facing instructions:
`docs/setup.md` §6.

## SaaS: set a tenant's plan

Plans are operator-set only (no tenant-facing API — upgrades are sales-led). The prod
DB is private-IP, so run it as a one-off Cloud Run job (same pattern as bootstrap):

    python -m app.users set-plan --tenant <slug> --plan team|enterprise|free
    python -m app.users list-tenants          # shows each org's plan

## Self-hosted: issue a license file

The Ed25519 **signing key** lives only in Secret Manager
(`warden-license-signing-key`, project `erudite-calling-502022-k6`) — never in the
repo, image, or a customer environment. The matching public key is embedded in
`app/licensing.py`, so every Warden build can verify but only the vendor can sign.

Issue (prints the `WDN1.…` blob — send it to the customer):

    gcloud secrets versions access latest --secret warden-license-signing-key \
        --project erudite-calling-502022-k6 | \
      python -m app.licensing issue --key - \
        --org "Acme Corp" --plan enterprise --seats 200 --days 365

- `--plan` — `team` or `enterprise` (`free` needs no license)
- `--seats` — becomes the instance's default users quota (0 = plan default)
- `--days 365` or `--expires YYYY-MM-DD`

Sanity-check any blob (verifies signature + expiry against the embedded public key):

    python -m app.licensing verify "WDN1...."

The customer sets `WARDEN_LICENSE` to the blob (or a file path holding it) and
restarts; `GET /api/health` on their instance shows `{org, plan, expires}`.

## Renewals, upgrades, revocation

- **Renewal / upgrade** = issue a fresh blob (new expiry / plan / seats); the customer
  replaces `WARDEN_LICENSE`. Old blobs need no revocation — they expire on their own.
- Expired or tampered licenses are ignored with a startup warning; the instance falls
  back to Free (nothing breaks, gated features stop configuring).
- **Key rotation** (only if the signing key ever leaks): `python -m app.licensing
  keygen`, add the new private key as a Secret Manager version, replace
  `VENDOR_PUBKEY_PEM` in `app/licensing.py`, ship a release — then reissue active
  customer licenses (old ones stop verifying on the new build).
