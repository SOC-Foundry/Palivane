# Licensing — vendor runbook

How Palivane (the vendor) grants Team / Enterprise tiers. Two mechanisms, one per
deployment model:

| Deployment | The license is… | You grant it with… |
|---|---|---|
| Hosted SaaS (app.palivane.io) | the `tenant.plan` column | `set-plan` (below) |
| Self-hosted | a signed `WDN1.…` license file | `app.licensing issue` (below) |

Plan gates and quotas live in `backend/app/plans.py`; the license format and
verification in `backend/app/licensing.py`. Customer-facing instructions:
`docs/setup.md` §6.

## SaaS: set a tenant's plan

Plans are operator-set only (no tenant-facing API — upgrades are sales-led). The prod
DB is private-IP, so run it as a one-off Cloud Run job (same pattern as bootstrap):

    python -m app.users set-plan --tenant <slug> --plan team|enterprise|free
    python -m app.users list-tenants          # shows each org's plan

## SaaS: the trial → paid pipeline

You don't have to watch trials by hand — two things surface buyers:

- **Trial lifecycle emails** (`app/trial.py`, sent from the background loop when SMTP is
  configured): the org's admins get a 7-days-left, 2-days-left, and expiry email. Each
  points at the console's "Request upgrade" form.
- **Upgrade requests**: an org admin hits "Request upgrade" on Settings → Your plan. It
  pages the ops webhook (`PALIVANE_OPS_WEBHOOK`), emails `PALIVANE_SALES_EMAIL`, and lands
  in the operator console (`/admin` → Upgrade requests).

Working the queue: agree terms with the contact → `set-plan` (SaaS) or issue a license
(self-hosted, below) → hit **Close** on the request in `/admin`. Closing is bookkeeping
only; the plan change is always set-plan / a license.

## Self-hosted: issue a license file

The Ed25519 **signing key** lives only in Secret Manager
(`palivane-license-signing-key`, project `erudite-calling-502022-k6`) — never in the
repo, image, or a customer environment. The matching public key is embedded in
`app/licensing.py`, so every Palivane build can verify but only the vendor can sign.

**Issue + record it in the registry** (short-term + renewal model — this is what you
almost always want, because it makes the license visible and revocable):

    gcloud secrets versions access latest --secret palivane-license-signing-key \
        --project erudite-calling-502022-k6 | \
      python -m app.users license-issue --key - \
        --org "Acme Corp" --plan enterprise --seats 200 --contract-months 12

- `--plan` — `team` or `enterprise` (`free` needs no license)
- `--seats` — becomes the instance's default users quota (0 = plan default)
- `--term-days` — the signed blob's life (default: the short renewal term, ~45d). The
  customer's instance renews before it lapses; you don't hand-reissue every term.
- `--contract-months` — the hard stop: renewals are refused past this (0 = no stop).
- prints the `WDN1.…` blob to send the customer AND records `lic_…` in the registry.

The customer sets `PALIVANE_LICENSE` to the blob (or a file path) and restarts;
`GET /api/health` shows `{org, plan, expires}`. `python -m app.licensing issue …` (no
registry) still exists for a one-off untracked blob, and `verify` sanity-checks any blob.

## See, renew, cancel

- **See every license:** `python -m app.users license-list`, or `GET /api/admin/licenses`
  (token-gated by `PALIVANE_METRICS_TOKEN`, same as the plan roster / funnel). SaaS orgs use
  the plan column instead — see them with `python -m app.users plans`.
- **Renewal is automatic:** the customer's instance re-fetches from `POST /api/license/renew`
  (presenting its current blob; the signature is the credential) before its term ends and
  gets a fresh short-term blob. Enabled only when the signing key is mounted in the app via
  the `palivane-license-signing-key` secret (deploy.sh wires it; the endpoint 503s otherwise).
  NOTE: mounting the signing key lets the running app sign — acceptable because a forged
  self-hosted license only unlocks features on the forger's own instance (no tenant-data or
  SaaS impact), but it is the reason the key is opt-in per deployment.
- **Cancel (self-hosted):** `python -m app.users license-revoke --id lic_…`. Renewals are
  then refused; the instance keeps working only until its current short term expires, then
  drops to Free. Same effect when `--contract-months` passes. (This is why terms are short —
  it bounds how long a cancelled license lingers.)
- **Cancel (SaaS):** `python -m app.users set-plan --tenant <slug> --plan free` — instant.
- **Upgrade / change seats:** re-issue (a new `lic_…`) or, for the same license, it renews
  with whatever the registry row now says. Expired/tampered blobs fall back to Free with a
  startup warning; nothing breaks.
- **Key rotation** (only if the signing key leaks): `python -m app.licensing keygen`, add
  the new private key as a Secret Manager version, replace `VENDOR_PUBKEY_PEM` in
  `app/licensing.py`, ship a release — then reissue active licenses (old ones stop
  verifying on the new build).
