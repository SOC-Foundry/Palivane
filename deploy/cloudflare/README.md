# Cloudflare Worker front door

Public entry for Palivane at `app.palivane.io` without granting `allUsers`
run.invoker (forbidden by the org's domain-restricted-sharing policy). The Worker
attaches a Google ID token for the `palivane-front` service account to every request,
so the Cloud Run service stays IAM-locked: direct `*.run.app` access is 403 for
anyone but the Worker, which makes Cloudflare's WAF/rate limiting unbypassable.

```
browser/agent ──TLS──> Cloudflare (orange cloud, WAF)
                          └─ Worker: + X-Serverless-Authorization: Bearer <SA ID token>
                               └────> Cloud Run (IAM: only palivane-front@ may invoke)
```

## Deploy

Prereqs: the `palivane-front` SA exists with `roles/run.invoker` on the service, and
you have its JSON key.

```sh
cd deploy/cloudflare
npx wrangler login                                   # or CLOUDFLARE_API_TOKEN
npx wrangler secret put GCP_SA_KEY < palivane-front-key.json
npx wrangler deploy
```

Then in the Cloudflare DNS dashboard: set `app.palivane.io` to **Proxied**
(orange cloud) — the Worker route only fires on proxied traffic.

## Cutover checklist (from IAP)

1. `gcloud beta run services update palivane --region us-central1 --no-iap`
2. Deploy the Worker (above) + flip DNS to Proxied.
3. Delete the now-unused Cloud Run domain mapping (its Google-managed cert can't
   renew behind the proxy and would sit in a failed state):
   `gcloud beta run domain-mappings delete --domain app.palivane.io --region us-central1`
4. Verify: `https://app.palivane.io` serves the app; `*.run.app` returns 403.

## Key rotation

The SA key lives only in the Worker secret. To rotate:

```sh
gcloud iam service-accounts keys create key.json \
  --iam-account palivane-front@palivane.iam.gserviceaccount.com
npx wrangler secret put GCP_SA_KEY < key.json && rm key.json
gcloud iam service-accounts keys list \
  --iam-account palivane-front@palivane.iam.gserviceaccount.com
gcloud iam service-accounts keys delete <OLD_KEY_ID> \
  --iam-account palivane-front@palivane.iam.gserviceaccount.com
```

## Notes

- The app's own `Authorization` header (agent JWTs) is untouched; the infra token
  uses `X-Serverless-Authorization`, which Cloud Run validates and strips.
- Real client IPs arrive in `CF-Connecting-IP` (Cloud Run's `X-Forwarded-For` will
  show Cloudflare egress IPs).
- Team access no longer needs per-user `run.invoker`/IAP grants — auth is Palivane's
  own login. GCP-side access for teammates is only about deploy/admin rights.
