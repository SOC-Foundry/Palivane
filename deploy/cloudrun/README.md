# Deploy Warden to Cloud Run + Cloud SQL

Runs the whole app as **one Cloud Run service** (FastAPI serves the built SPA *and* the
API — single origin, no nginx), backed by **Cloud SQL (Postgres)**. This is the recommended
production shape: your existing container + managed Postgres, minimal ops, auto TLS, custom
domain. No Kubernetes.

```
Browser / extension / Claude Code ──HTTPS──► Cloud Run (SPA + /api + /v1) ──socket──► Cloud SQL
                                                     └─ secrets from Secret Manager
```

## One-time setup

```bash
PROJECT_ID=my-proj
REGION=us-central1
gcloud config set project "$PROJECT_ID"

# 1. Enable APIs
gcloud services enable run.googleapis.com sqladmin.googleapis.com \
  artifactregistry.googleapis.com cloudbuild.googleapis.com secretmanager.googleapis.com

# 2. Artifact Registry repo for the image
gcloud artifacts repositories create warden --repository-format=docker --location="$REGION"

# 3. Cloud SQL Postgres (smallest tier to start)
gcloud sql instances create warden-db --database-version=POSTGRES_16 \
  --tier=db-f1-micro --region="$REGION"
gcloud sql databases create warden --instance=warden-db
gcloud sql users create warden --instance=warden-db --password='CHOOSE-A-STRONG-PASSWORD'
#   Connection name (used below): PROJECT:REGION:warden-db
SQL_CONNECTION="$(gcloud sql instances describe warden-db --format='value(connectionName)')"

# 4. Secrets (Secret Manager). DATABASE_URL uses the Cloud SQL unix socket Cloud Run mounts.
printf '%s' "$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')" \
  | gcloud secrets create warden-secret-key --data-file=-
printf '%s' "postgresql+psycopg2://warden:CHOOSE-A-STRONG-PASSWORD@/warden?host=/cloudsql/${SQL_CONNECTION}" \
  | gcloud secrets create warden-database-url --data-file=-
# Optional provider keys (added to the deploy automatically if present):
# printf '%s' "sk-ant-…" | gcloud secrets create gateway-anthropic-key --data-file=-
# printf '%s' "sk-…"     | gcloud secrets create openai-api-key --data-file=-
# printf '%s' "…"        | gcloud secrets create gemini-api-key --data-file=-

# 5. Let Cloud Run's service account read secrets + reach Cloud SQL
SA="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')-compute@developer.gserviceaccount.com"
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:$SA" --role=roles/secretmanager.secretAccessor
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:$SA" --role=roles/cloudsql.client
```

## Deploy

```bash
PROJECT_ID=my-proj REGION=us-central1 \
SQL_CONNECTION="$SQL_CONNECTION" \
DOMAIN=app.warden.io \
GATEWAY_ENFORCE=true \
./deploy/cloudrun/deploy.sh
```

The script builds the image (`deploy/cloudrun/Dockerfile`), pushes it, and deploys the
service with the Cloud SQL socket, secrets, and env. On start the container waits for the DB
and runs `alembic upgrade head` (migrations), then serves. It prints the service URL.

## Custom domain + TLS (Cloud Run domain mapping)

Single-origin, streaming-safe, free — no load balancer, no Firebase (Firebase Hosting's CDN
can buffer the gateway's SSE streaming). Run the helper, or the steps by hand:

```bash
PROJECT_ID=my-proj REGION=us-central1 DOMAIN=app.warden.io ./deploy/cloudrun/map-domain.sh
```

By hand:
```bash
# 1. Verify domain ownership (one-time) — opens Search Console; add the TXT record it gives.
gcloud domains verify tachtech.net
gcloud domains list-user-verified                 # confirm it appears

# 2. Map the domain to the service (auto-provisions a managed TLS cert).
gcloud beta run domain-mappings create --service warden --domain app.warden.io --region "$REGION"

# 3. Add the DNS records it prints at your registrar (A/AAAA or CNAME to ghs.googlehosted.com).
gcloud beta run domain-mappings describe --domain app.warden.io --region "$REGION" \
  --format='table(status.resourceRecords[].name, status.resourceRecords[].type, status.resourceRecords[].rrdata)'

# 4. Wait for DNS + cert (~15-60 min); watch:
gcloud beta run domain-mappings describe --domain app.warden.io --region "$REGION" \
  --format='value(status.conditions[].type, status.conditions[].status)'
```

Then redeploy so `CORS_ORIGINS=https://palivane.tachtech.net` (the `deploy.sh` `DOMAIN` var sets it).
Because SPA + API share this one origin, that's the only origin you need — and it's what the
extension/CLI sign-in hands back as the backend.

> Domain mapping isn't available in every region. If yours is unsupported (or you later want
> Cloud Armor / a static IP / multi-region), front the service with a **global external HTTPS
> Load Balancer** instead — same container, no app changes.

## Wire the clients to this domain
- **Extension (prod build):** `PALIVANE_SAAS_URL=https://palivane.tachtech.net ./extension/build.sh`
- **Claude Code (self-serve):** `palivane-connect https://palivane.tachtech.net`
- **Managed fleets:** point `managed-settings.json` / managed policy / `/api/policy-pack` at it.

## Notes
- **Migrations** run on container start (fine for launch). For strict zero-downtime, run them
  as a one-off first: `gcloud run jobs` executing the same image with the CMD
  `alembic upgrade head`, then deploy the service — instead of on every cold start.
- **Streaming (SSE)** works on Cloud Run directly. If you ever front this with Firebase
  Hosting rewrites, its CDN can buffer SSE — keep streaming clients pointed at the Cloud Run
  domain. Single-origin Cloud Run (this setup) avoids that entirely.
- **Egress proxy** (`proxy/`) is **not** deployed here — it runs at the customer's network
  edge (system proxy + CA), not in your SaaS cloud.
- Scale/cost: starts at `min-instances=0` (scale to zero). Set `MIN_INSTANCES=1` to avoid
  cold starts once you have traffic.
