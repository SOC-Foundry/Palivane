# Cloudflare Worker front door

Public entry for Palivane at `palivane.io` (the site) and `app.palivane.io` (the console
and the API) without granting `allUsers`
run.invoker (forbidden by the org's domain-restricted-sharing policy). The Worker
attaches a Google ID token for the `palivane-front` service account to every request,
so the Cloud Run service stays IAM-locked: direct `*.run.app` access is 403 for
anyone but the Worker, which makes Cloudflare's WAF/rate limiting unbypassable.

```
browser/agent ──TLS──> Cloudflare (orange cloud, WAF)
                          └─ Worker: + X-Serverless-Authorization: Bearer <SA ID token>
                               └────> Cloud Run (IAM: only palivane-front@ may invoke)
```

## Two hosts, one worker

Both routes reach the same worker and the same Cloud Run origin. `worker.js` decides who
owns a page and 301s browser navigation accordingly:

| request | goes to |
| --- | --- |
| `palivane.io/`, `/pricing`, `/docs/*`, … | served here — the public site |
| `palivane.io/app/*` | `app.palivane.io` — the console |
| `app.palivane.io/` | served here — signed out that is the site, signed in the SPA routes to `/app/findings` |
| `app.palivane.io/pricing`, `/docs/*`, … | `palivane.io` — the public site |
| `/api/*`, `/v1` on either host | **never redirected** |
| assets, `/cli/*`, `/install.sh`, `/admin` | served on whichever host asked |

Cross-host redirects are **302**, not 301. The apex used to answer `301 Moved Permanently`
pointing at the app host, and browsers cache that indefinitely — anyone who loaded
`palivane.io` before the split still bounces to `app.palivane.io` without asking. That
cache cannot be invalidated from the server; it ages out on its own. Which host owns a page
is a layout decision that has now changed once, so the redirects are temporary and the next
change will not be sticky. `app.palivane.io/` is deliberately not redirected: it is where
every stale 301 lands, and forwarding it would drop people who asked for the website into a
sign-in screen.

API and gateway traffic is never redirected because installed CLIs, the extension and MDM
clients POST there and a 301 would not replay their bodies — they keep working against
whichever host they enrolled on. Assets are excluded so a console page does not fetch its
own JavaScript across origins.

**The SPA has to agree with this.** It is built with `VITE_PALIVANE_APP_ORIGIN` (set in
`.github/workflows/deploy.yml`) so "Sign in" on a marketing page navigates to the console's
origin; the session token lives in per-origin localStorage, so a same-origin sign-in on the
apex would store it where the console cannot read it. **Deploy Cloud Run before the
worker** — the other order leaves a window where the apex serves the site to a build whose
sign-in button is still same-origin.

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
