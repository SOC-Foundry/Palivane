# Batch D runbook — the Warden → Palivane infrastructure cutover

Status as of the code rename (batches A–C + B-final, including the B-final completion sweep
that moved every deploy surface, doc, client, and console snippet off the `WARDEN_*` names):
**every user-visible, developer-visible, and client-visible surface is already Palivane.** The console, public site, docs, CLI binaries
(`palivane-*`), env vars (`PALIVANE_*`), capture header (`X-Palivane-Token`), browser
extension, metrics, and API responses all say Palivane. `palivane.tachtech.net` is the live
primary host; `warden.tachtech.net` still serves and 301-redirects human traffic to it.

What remains is **infrastructure resource names** — GCP service, secrets, SQL instance,
Cloudflare worker, the `*.run.app` origin, and the legacy domain. This runbook covers them.

---

## TL;DR — recommendation

**Most of Batch D is not worth doing, and one item is dangerous. Do only item 1.**

| # | Item | User-visible? | Effort | Risk | Recommendation |
|---|------|:---:|:---:|:---:|---|
| 1 | **Legacy domain `warden.tachtech.net`** | **Yes** | Low | Low | **Decide: keep the 301-redirect (recommended) or hard-retire.** |
| 2 | Cloud Run service name `warden` | No | High | Medium | **Skipped — decided 2026-08-10.** Internal only; Terraform state move + IAM re-bind + worker repoint + redeploy for zero user benefit. See the decision note under item 2. |
| 3 | Secret *resource* names `warden-*` | No | Medium | Low–Med | **Skip** (or do lazily). Internal; needs new secret versions + deploy + TF. |
| 4 | **SQL instance `warden-db` / database `warden`** | No | — | **DATA LOSS** | **Never.** Cloud SQL instances/DBs can't be renamed in place — a rename recreates = total data loss. Leave as-is permanently. |
| 5 | Cloudflare worker name `warden-front` | No | Low | Low | Optional cosmetic; skip unless you want the dashboard tidy. |
| 6 | `*.run.app` origin hostname | No | (tied to #2) | — | Only changes if #2 does. Skip. |
| 7 | Artifact Registry repo `warden` | No | Med | Low | Skip. Internal; only affects image push paths. |

**The honest bottom line:** the rename that matters to customers, prospects, and your own
developers is **100% complete**. Items 2–7 are ops cosmetics on names nobody outside the
GCP/Cloudflare consoles ever sees, they're Terraform-managed (so each is a state move, not a
click), and item 4 would destroy the database. The only decision with real value is **item 1
— what happens to the old domain.**

---

## Item 1 — the legacy domain `warden.tachtech.net` (the one that matters)

Two options. Both are fine; pick by taste.

### Option A — keep the redirect forever (recommended)

Do nothing. The worker already 301-redirects human navigation on `warden.tachtech.net` →
`palivane.tachtech.net` (and proxies any stray API call transparently). Leaving it:

- catches bookmarks, old links, and anyone with muscle memory,
- preserves any SEO/link equity,
- costs nothing (same worker, same account).

This is what most renamed products do — the old domain quietly forwards indefinitely.

### Option B — hard-retire the old domain

Only if you specifically want `warden.tachtech.net` to stop resolving.

1. **Remove the worker route** (Cloudflare — needs your `wrangler` login):
   ```
   # edit deploy/cloudflare/wrangler.toml: delete the
   #   { pattern = "warden.tachtech.net/*", zone_name = "tachtech.net" }
   # route line, keeping only the palivane.tachtech.net route, then:
   cd deploy/cloudflare && npx wrangler deploy
   ```
2. **Delete the DNS record** `warden` in the `tachtech.net` Cloudflare zone (dashboard).
3. **Drop `warden.tachtech.net` from the app's allowlist** so it's no longer trusted:
   ```
   gh variable set PALIVANE_ALLOWED_HOSTS --body \
     "palivane.tachtech.net,warden-442729333907.us-central1.run.app,warden-r6keoxospq-uc.a.run.app"
   ```
   (and the next deploy propagates it; or update the live service env directly.)
4. Remove the `LEGACY_HOST`/redirect block from `deploy/cloudflare/worker.js` in a follow-up
   commit (cosmetic once the route is gone).

**Recommendation: Option A.** There's no upside to making the old URL 404, and a small
downside (broken links). Keep the redirect.

---

## Items 2–7 — internal GCP/Cloudflare resource names (skip, but documented)

These are invisible to every user. If you nonetheless want a zero-"warden" GCP project, here
is the exact procedure and the risk on each. **Read item 4 first.**

### ⚠️ Item 4 — SQL instance / database: DO NOT RENAME

`deploy/terraform/sql.tf` defines the Cloud SQL instance as `"${var.service_name}-db"`
(= `warden-db`) and the database as `"warden"`. **Cloud SQL does not support renaming an
instance or a database in place** — Terraform would destroy and recreate it, which means
**total data loss** (all tenants, users, findings, licenses). There is no benefit worth this.
**Leave `warden-db` and the `warden` database named as they are, permanently.**

> **Both guardrails are now in place** (added 2026-08-10). Two different mechanisms, and it
> is worth knowing why both:
>
> - `deletion_protection = true` on the instance — the Cloud SQL API's own flag, so it also
>   blocks a console/`gcloud` delete. It was always there. But it refuses during **apply**,
>   partway through a run.
> - `lifecycle { prevent_destroy = true }` on the instance **and on the database** — refuses
>   at **plan** time, and covers *replacement*, not just deletion. This is the one that
>   matters for a rename: `name` is immutable, so editing `var.service_name` plans a
>   destroy+create, and that plan is now rejected before anything is touched. The database
>   needs its own guard because the instance's `deletion_protection` does not cover the
>   database inside it — dropping that resource deletes every table while the instance
>   survives.
>
> Removing either line is a deliberate, reviewable act. If you ever genuinely must replace
> the instance, take the guard off in its own commit so the intent is on the record.

### Item 2 — Cloud Run service `warden` → `palivane`

The service is Terraform-managed (`google_cloud_run_v2_service.warden` in `cloudrun.tf`,
referenced by `iam.tf` and `outputs.tf`) and the name is also the `SERVICE` default in
`deploy/cloudrun/deploy.sh`. Cloud Run **can't rename a service in place** either — you deploy
a *new* service and delete the old. Full procedure:

1. Change `variable "service_name"` (or the resource name) — but note this also feeds the SQL
   instance name (item 4!) and registry (item 7). **Decouple first**: give the Cloud Run
   service its own variable so renaming it doesn't touch `warden-db`.
2. `terraform state mv google_cloud_run_v2_service.warden google_cloud_run_v2_service.palivane`
   (rename the TF resource address without destroy), then update all references in
   `cloudrun.tf`, `iam.tf`, `outputs.tf`.
3. Deploy the new service `palivane` (new URL `palivane-<hash>-uc.a.run.app`).
4. **Re-grant IAM**: the `warden-front` worker SA needs `run.invoker` on the new service:
   ```
   gcloud run services add-iam-policy-binding palivane --region us-central1 \
     --member="serviceAccount:warden-front@erudite-calling-502022-k6.iam.gserviceaccount.com" \
     --role=roles/run.invoker
   ```
5. **Repoint the worker**: set `ORIGIN` in `deploy/cloudflare/worker.js` to the new run.app
   URL, add the new run.app host to `PALIVANE_ALLOWED_HOSTS`, `npx wrangler deploy`.
6. Verify `palivane.tachtech.net/api/health` → `ok`, then delete the old `warden` service.

Effort: ~1–2 hrs with careful verification. Benefit: an internal service name nobody sees.
**Recommendation: skip.**

#### Decision — 2026-08-10: skipped, deliberately

Raised again and declined. Nothing about the analysis changed: `palivane.tachtech.net` is
already the primary host, the worker already routes it, and the service name is visible only
in the GCP console. Two things found while re-checking it are worth recording, because both
are traps in the procedure above.

**The step order hides a silent failure.** `deploy/cloudrun/deploy.sh:14` is
`SERVICE="${SERVICE:-warden}"`. If that default (or the workflow's service name) is changed
to `palivane` *before* step 5 repoints the worker, the next merge to main deploys the new
image to the new service while every request still reaches the old one. Production stops
receiving updates and **nothing fails** — no red check, no error, just a frozen site. If you
ever do this, repoint the worker (step 5) and change `SERVICE` in the *same* window, and
confirm a real deploy lands by watching a version string change through the public host, not
by reading the workflow's green tick.

**Step 2 assumes Terraform state that does not exist.** `terraform state mv` presumes the
service is in state; production was built by hand and still isn't. `.github/workflows/
terraform-apply.yml` remains `workflow_dispatch`-only for exactly this reason ("the existing
production infra was built by hand and is NOT yet in Terraform state"). So anyone following
this runbook literally will fail at step 2 and should either import prod into state first, or
treat items 2/3/7 as pure `gcloud` operations with the Terraform files updated afterward.

**Cutover access:** step 5 needs Cloudflare credentials (`wrangler login` or
`CLOUDFLARE_API_TOKEN`). GCP owner alone is not enough to move traffic — the origin and the
ID-token audience both live in the worker.

### Item 3 — Secret *resource* names `warden-*` → `palivane-*`

`deploy/cloudrun/deploy.sh` maps env→secret as `PALIVANE_SECRET_KEY=warden-secret-key:latest`
etc. The left side (env var) is already Palivane; the right side is the Secret Manager
*resource* name. To rename the resources (values are copied, not regenerated — so JWT sessions
and the license signing key stay valid):

```
for s in secret-key database-url metrics-token license-signing-key smtp-pass; do
  gcloud secrets create palivane-$s --replication-policy=automatic --project erudite-calling-502022-k6
  gcloud secrets versions access latest --secret warden-$s --project erudite-calling-502022-k6 \
    | gcloud secrets versions add palivane-$s --data-file=- --project erudite-calling-502022-k6
done
```

Then update the right-hand sides in `deploy.sh` (`warden-secret-key` → `palivane-secret-key`,
…), the `google_secret_manager_secret` resources in `cloudrun.tf` (+ `terraform state mv` each),
grant the compute SA `secretAccessor` on the new secrets, redeploy, verify, and delete the old
secrets. Note `warden-database-url` embeds the Cloud SQL connection name (which references
`warden-db` from item 4) — the *value* is unchanged, only the secret resource name changes.

Effort: ~1 hr + TF. Benefit: internal secret names. **Recommendation: skip, or do opportunistically.**

### Item 5 — Cloudflare worker name `warden-front` → `palivane-front`

`name` in `deploy/cloudflare/wrangler.toml`. Renaming creates a *new* worker (Cloudflare keys
by name) and orphans the old one, so you must re-put the `GCP_SA_KEY` secret and re-bind the
Durable Object migration on the new worker, then delete the old. Low value; **skip** unless you
want the Cloudflare dashboard tidy.

### Item 7 — Artifact Registry repo `warden`

`registry.tf`. Only affects the image push path in CI/deploy. Renaming needs a new repo + TF
state move + updating the image URL in `deploy.sh`. Internal. **Skip.**

---

## Rollback notes

- **Item 1B (domain retire):** re-add the `warden` proxied CNAME + the worker route, redeploy
  the worker. Fully reversible.
- **Items 2–3, 5, 7:** because these use `terraform state mv` (not destroy) and copy secret
  values (not regenerate), a rollback is the reverse `state mv` + revert the config. Keep the
  old resources until the new ones are verified serving; delete last.
- **Item 4:** N/A — never attempted.

---

## Summary

The Warden → Palivane rename is **functionally complete**. Batch D is optional infra hygiene on
invisible resource names; the single decision worth making is **item 1 — keep the old domain as
a redirect (recommended) or retire it.** Everything else (service, secrets, SQL, worker,
registry names) should stay as-is: the SQL instance *must* (data loss otherwise), and the rest
are high-effort, zero-visibility changes.

## Decision log

| Date | Item | Decision |
|---|---|---|
| 2026-08-10 | 2 — Cloud Run service name | **Skipped.** Internal-only benefit against an outage window, a silent deploy-drift trap, and a Terraform-state prerequisite that isn't met. Revisit only alongside a planned infra change. |

| 2026-08-10 | 4 — Cloud SQL guardrail | **Done.** `prevent_destroy` added to the instance and the database, so a rename-driven replace fails at plan time rather than during apply. `deletion_protection` was already set on the instance. |
