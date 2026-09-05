# Palivane Helm chart

The self-hosted edition for Kubernetes — the same single-container image the
docker-compose stack runs (SPA + API on one port), with bring-your-own Postgres.

```bash
helm install palivane ./deploy/helm/palivane \
  --set-string databaseUrl='postgresql+psycopg2://user:pass@postgres:5432/palivane' \
  --set-string secretKey="$(openssl rand -hex 32)" \
  --set env.PALIVANE_PUBLIC_URL=https://palivane.internal.example \
  --set ingress.enabled=true --set ingress.host=palivane.internal.example
```

Secrets: pass `existingSecret` (keys `DATABASE_URL`, `PALIVANE_SECRET_KEY`) to keep them
out of Helm values entirely. Every other setting from `deploy/palivane.env.example`
threads through `env`/`extraEnv`. Key loss = loss of encrypted finding content — treat
`PALIVANE_SECRET_KEY` accordingly.
