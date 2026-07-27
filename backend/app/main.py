"""Warden — AI Security Gateway API.

Detects attacks on the org's own LLMs (prompt injection / jailbreak / exfiltration)
and sensitive data leaving for AI tools (secrets / PII / source code), across the
gateway, browser extension, and egress proxy.
"""

from __future__ import annotations

import hmac
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from .auth import get_current_user, require_admin, router as auth_router
from .distribution import router as distribution_router
from .domains import router as domains_router
from .config import settings
from .gateway import gemini_router, router as gateway_router
from .database import Base, engine as db_engine, get_db
from .detectors import AnalysisInput, Surface
from .engine import engine
from .models import Agent, AgentRole, Finding, PolicyOverride, Tenant, User
from .schemas import (
    AIUsageIngest,
    AnalyzeRequest,
    BatchAnalyzeRequest,
    AgentConfigScan,
    CodeScanRequest,
    CoverageRequest,
    DiscoveryIngest,
    IDEExtScan,
    OversharingScan,
    PolicyOverrideIn,
    MCPBatchIngest,
    ExceptionRequest,
    ExceptionResolve,
    SimulateIn,
    MCPConfigScan,
    MCPIngest,
    ProvisionRequest,
    ScannerImport,
    SecretAtRest,
    S3Scan,
    SecretScan,
    BulkStatusUpdate,
    StatusUpdate,
)
from .security import using_insecure_key
from .service import run_analysis
from .remediation import remediation_for

# SQLite (local dev) auto-creates its schema; Postgres is managed by Alembic
# migrations (run via the container entrypoint / `alembic upgrade head`).
if settings.database_url.startswith("sqlite"):
    Base.metadata.create_all(bind=db_engine)


_WEAK_SECRET_KEYS = {"dev-insecure-change-me", "dev-insecure-key-change-me",
                     "changeme", "change-me", "secret", "changeme123"}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    import logging
    log = logging.getLogger("uvicorn.error")
    prod = not settings.database_url.startswith("sqlite")   # Postgres => a real deployment
    weak = using_insecure_key() or settings.auth_secret_key in _WEAK_SECRET_KEYS \
        or len(settings.auth_secret_key) < 16
    if weak:
        if prod:
            # Refuse to boot with a forgeable JWT key on a production-shaped deployment — an
            # unset OR well-known/short key both let anyone forge an admin session for any
            # tenant. (SQLite = local dev, where the dev key is allowed with a warning.)
            raise RuntimeError(
                "WARDEN_SECRET_KEY is unset or weak. On a non-SQLite (production) deployment "
                "JWTs would be forgeable and anyone could mint an admin session. Set "
                "WARDEN_SECRET_KEY to a strong random value (openssl rand -hex 32) and restart.")
        log.warning("WARDEN_SECRET_KEY is unset/weak — using an insecure dev key (SQLite dev only).")

    # Periodic alert digests: tick every few minutes and send any tenant digests that are due.
    # Each send is claimed via a conditional DB update, so multiple workers won't duplicate.
    import asyncio

    async def _digest_loop():
        from . import alerts, metering
        from .database import SessionLocal
        ticks = 0
        while True:
            try:
                await asyncio.sleep(300)   # 5-minute tick; per-tenant hourly/daily gating in run_digests
                ticks += 1
                db = SessionLocal()
                try:
                    await asyncio.to_thread(alerts.run_digests, db)
                    # Prune the usage/metering counter (rows past the retention horizon) so
                    # gateway_usage doesn't grow unbounded. ~hourly (every 12th 5-min tick).
                    if ticks % 12 == 0:
                        await asyncio.to_thread(metering.prune, db)
                    # Scrub stored prompt content past the content TTL (keeps the finding +
                    # metadata, drops the prose) so opt-in-content tenants don't retain it
                    # forever. ~hourly.
                    if ticks % 12 == 0:
                        from .service import scrub_expired_content
                        await asyncio.to_thread(scrub_expired_content, db)
                finally:
                    db.close()
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.warning("digest loop error: %s", e)

    task = asyncio.create_task(_digest_loop())
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(
    title="Warden — AI Security Gateway",
    description="Detects attacks on your LLMs and stops sensitive data leaking to AI tools.",
    version="0.1.0",
    lifespan=lifespan,
    # FastAPI's interactive API docs live under /api/* — the bare /docs path belongs to
    # the public documentation pages in the SPA (FastAPI's default /docs was shadowing
    # them; its Swagger CDN assets are CSP-blocked in prod anyway).
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
)

_CORS_ORIGINS = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
# The browser extension calls the API from its own origin (chrome-extension://<id>) with
# no manifest host_permission for the backend — deliberately, so one store package works
# against any org's deployment. CORS is the gate instead: allow the published extension.
if settings.extension_id:
    _CORS_ORIGINS.append(f"chrome-extension://{settings.extension_id}")

# Reject requests with a spoofed Host (defense-in-depth against host-header injection into
# any base_url-derived link). Enabled only when an allowlist is configured; the public
# origin's host is always included.
_ALLOWED_HOSTS = [h.strip() for h in settings.allowed_hosts.split(",") if h.strip()]
if settings.public_base_url:
    from urllib.parse import urlparse as _urlparse
    _ph = _urlparse(settings.public_base_url).hostname
    if _ph and _ph not in _ALLOWED_HOSTS:
        _ALLOWED_HOSTS.append(_ph)
if _ALLOWED_HOSTS:
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=_ALLOWED_HOSTS + ["testserver"])

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    # Never pair a wildcard origin with credentials; we authenticate via the Authorization
    # header (not cookies), so credentials aren't needed and methods/headers are explicit.
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Warden-Token", "x-api-key",
                   "anthropic-version", "anthropic-beta"],
)


@app.middleware("http")
async def _guard(request: Request, call_next):
    # Reject oversized bodies up front (DoS/OOM) — the detectors run many regex passes over
    # request content, so bound it before parsing. Backs the per-field Pydantic caps.
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > settings.max_body_bytes:
        from fastapi.responses import JSONResponse as _JR
        return _JR(status_code=413, content={"detail": "request body too large"})
    resp = await call_next(request)
    # Baseline hardening headers.
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    # HSTS: force HTTPS for a year (incl. subdomains). Emitted only on HTTPS requests (via
    # the forwarded proto, since Cloudflare/Cloud Run terminate TLS) so a local http dev
    # origin is never pinned.
    if request.headers.get("x-forwarded-proto", request.url.scheme) == "https":
        resp.headers.setdefault("Strict-Transport-Security",
                                "max-age=31536000; includeSubDomains")
    # CSP: the SPA loads only same-origin bundles (no inline/external scripts); React uses
    # inline style attributes (hence style 'unsafe-inline'); posters/video/data-URI icons are
    # same-origin or data:. frame-ancestors 'none' complements X-Frame-Options.
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; media-src 'self'; font-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
        "form-action 'self'; object-src 'none'")
    return resp


app.include_router(auth_router)
app.include_router(domains_router)
app.include_router(distribution_router)
app.include_router(gateway_router)
app.include_router(gemini_router)


@app.middleware("http")
async def _metrics_middleware(request, call_next):
    import time
    from . import metrics
    start = time.perf_counter()
    response = await call_next(request)
    metrics.observe(request.method, metrics.route_template(request),
                    response.status_code, time.perf_counter() - start)
    return response


@app.get("/api/health")
def health():
    from . import email as email_mod
    from .licensing import current as license_current
    lic = license_current()
    return {
        "status": "ok",
        "judge_enabled": engine.judge_enabled,
        "judge_model": engine.judge.model if engine.judge_enabled else None,
        "judge_provider": engine.judge.provider if engine.judge_enabled else None,
        "allow_signup": settings.allow_signup,
        "email_enabled": email_mod.enabled(),
        # Self-hosted licensing (see app/licensing.py); absent on the hosted SaaS where
        # tenant.plan is authoritative.
        "license": {"org": lic["org"], "plan": lic["plan"],
                    "expires": lic["expires"]} if lic else None,
    }


@app.get("/api/setup-status")
def setup_status(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Per-plane activity (findings in the last 24h) + enforcement/judge state, for the
    console's onboarding/health card — 'is each capture plane actually reporting?'"""
    from datetime import datetime, timedelta
    since = datetime.utcnow() - timedelta(hours=24)
    rows = (db.query(Finding.surface, func.count(Finding.id))
            .filter(Finding.tenant_id == current.tenant_id, Finding.created_at >= since)
            .group_by(Finding.surface).all())
    by_surface = {s: c for s, c in rows}
    from .upstreams import PROVIDERS, forwards as upstream_forwards
    return {
        "planes": {
            "gateway": by_surface.get("llm_io", 0),      # first-party LLM (gateway)
            "shadow_ai": by_surface.get("ai_usage", 0),  # extension / proxy
            "mcp": by_surface.get("mcp", 0),             # agentic tool-use
            "secrets": by_surface.get("secrets", 0),     # credentials at rest (warden-secrets)
        },
        # Which providers the gateway will actually forward for this org (vs. the stub) —
        # the console warns when Claude Code is routed here but anthropic can't forward.
        "upstream_forwards": {p: upstream_forwards(p, current.tenant_id, db) for p in PROVIDERS},
        "judge_enabled": engine.judge_enabled,
        "gateway_enforce": settings.gateway_enforce,
        "mcp_enforce": settings.mcp_enforce,
    }


@app.post("/api/alerts/test")
def test_alert(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Send a sample alert to the tenant's configured webhook (Settings → Alerts)."""
    from . import alerts
    t = db.get(Tenant, current.tenant_id)
    if not t or not (t.alert_webhook or "").strip():
        raise HTTPException(status_code=400, detail="no alert webhook configured")
    ok = alerts.send_sync(t.alert_webhook.strip(), {
        "text": ":shield: Warden test alert — your webhook is connected.",
        "warden": {"test": True, "org": t.slug}})
    return {"ok": ok}


@app.post("/api/siem/test")
def test_siem(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Send a sample event to the tenant's configured SIEM collector (Settings → SIEM)."""
    from . import siem
    t = db.get(Tenant, current.tenant_id)
    if not t or not (t.siem_url or "").strip():
        raise HTTPException(status_code=400, detail="no SIEM endpoint configured")
    fields = siem._fields(
        {"severity": "high", "risk_score": 75, "finding_id": 0,
         "signals": [{"category": "secret_leak"}]},
        subject="Warden SIEM test event", actor="warden", surface="test", org=t.slug)
    ok = siem.send_sync(t.siem_url.strip(), t.siem_token or "", t.siem_format or "json", fields)
    return {"ok": ok}


@app.post("/api/siem/s3/test")
def test_siem_s3(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Write a sample object to the tenant's configured S3 delivery bucket (Settings → SIEM)."""
    from . import siem_s3
    t = db.get(Tenant, current.tenant_id)
    if not t or not (t.siem_s3_bucket or "").strip():
        raise HTTPException(status_code=400, detail="no S3 bucket configured")
    ok, detail = siem_s3.test(t.siem_s3_bucket.strip(), t.siem_s3_prefix or "",
                              t.siem_s3_region or "", t.siem_s3_key_id or "", t.siem_s3_secret or "")
    return {"ok": ok, "detail": detail}


@app.post("/api/alerts/digest/run")
def run_digest_now(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Force-send this tenant's digest now if one is due (Settings → Alerts button, or a
    cron for ops). The background loop does this automatically every few minutes."""
    from . import alerts
    sent = alerts.run_digests(db)
    return {"sent": sent}


@app.get("/api/export/findings")
def export_findings(
    current: User = Depends(require_admin), db: Session = Depends(get_db),
    severity: str | None = None, surface: str | None = None, limit: int = 5000,
):
    """Export findings as JSONL (SIEM ingest). Admin; filterable by severity/surface."""
    import json as _json
    from fastapi.responses import Response as _Resp
    q = db.query(Finding).filter(Finding.tenant_id == current.tenant_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    if surface:
        q = q.filter(Finding.surface == surface)
    rows = q.order_by(Finding.created_at.desc()).limit(min(limit, 20000)).all()
    body = "\n".join(_json.dumps(r.to_summary()) for r in rows)
    return _Resp(content=body, media_type="application/x-ndjson",
                 headers={"Content-Disposition": "attachment; filename=warden-findings.jsonl"})


@app.get("/api/export/tenant")
def export_tenant(
    current: User = Depends(require_admin), db: Session = Depends(get_db),
    include_content: bool = False, limit: int = 50000,
):
    """Full self-serve data export for this org (security review / portability request):
    tenant config, users, keys, findings, audit log, SSO/upstream config, DPA record — as
    one JSON document. Secrets are never included; finding content only if requested."""
    import json as _json
    from fastapi.responses import Response as _Resp
    from . import audit_log, data_export
    tenant = db.get(Tenant, current.tenant_id)
    doc = data_export.build_tenant_export(db, tenant, include_content=include_content, limit=limit)
    audit_log.record(db, current.tenant_id, current.email, "tenant.export",
                     detail={"include_content": bool(include_content),
                             "findings": doc["counts"]["findings"]})
    fname = f"warden-export-{tenant.slug}.json"
    return _Resp(content=_json.dumps(doc, indent=2), media_type="application/json",
                 headers={"Content-Disposition": f"attachment; filename={fname}"})


@app.get("/livez")
def livez():
    """Liveness: the process is up (no dependencies checked)."""
    return {"status": "live"}


@app.get("/readyz")
def readyz(db: Session = Depends(get_db)):
    """Readiness: the database is reachable — for load-balancer / k8s gating."""
    from sqlalchemy import text
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception:
        return JSONResponse(status_code=503, content={"status": "not-ready"})


@app.get("/metrics")
def metrics_endpoint(request: Request):
    """Prometheus exposition. If WARDEN_METRICS_TOKEN is set, require it (Bearer or ?token=)."""
    from fastapi.responses import Response as _Resp
    from . import metrics
    tok = settings.metrics_token
    if tok:
        scheme, _, bearer = request.headers.get("authorization", "").partition(" ")
        provided = bearer if scheme.lower() == "bearer" else request.query_params.get("token", "")
        if not hmac.compare_digest(provided, tok):
            raise HTTPException(status_code=401, detail="metrics token required")
    body, content_type = metrics.exposition()
    return _Resp(content=body, media_type=content_type)


@app.get("/api/admin/funnel")
def admin_funnel(request: Request, days: int | None = None,
                 include_internal: bool = False, db: Session = Depends(get_db)):
    """Vendor product-analytics funnel (signup → activation). Operator-only: gated by the
    same WARDEN_METRICS_TOKEN as /metrics (Bearer or ?token=), NOT a tenant session — it
    aggregates across all tenants. Returns 404 when no metrics token is configured, so it
    can't be left open by accident on a deployment that never set one up."""
    from . import funnel
    _require_operator(request)
    return funnel.compute(db, days=days, include_internal=include_internal)


@app.get("/api/admin/plans")
def admin_plans(request: Request, db: Session = Depends(get_db)):
    """Operator plan roster: every org with its plan and whether it's activated. Cross-
    tenant, so — like the funnel — gated by WARDEN_METRICS_TOKEN, NOT a tenant session (a
    tenant admin must never see other orgs). 404 when no metrics token is configured."""
    from .plans import PLANS, plan_of
    from .models import Finding
    _require_operator(request)
    activated = {r[0] for r in db.query(Finding.tenant_id).distinct().all()}
    counts: dict[str, int] = {p: 0 for p in PLANS}
    rows = []
    for t in db.query(Tenant).order_by(Tenant.created_at).all():
        p = plan_of(t)
        counts[p] = counts.get(p, 0) + 1
        rows.append({"slug": t.slug, "name": t.name, "plan": p,
                     "status": t.status or "active", "activated": t.id in activated,
                     "created_at": t.created_at.isoformat() if t.created_at else None})
    return {"totals": counts, "tenants": rows}


@app.get("/api/plans")
def plan_catalog(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """This org's plan + the tier/entitlement catalog, for the console entitlements panel.
    Authenticated (any member); shows only the caller's own plan — no cross-tenant data."""
    from . import plans as plans_mod
    return plans_mod.catalog(db.get(Tenant, current.tenant_id))


@app.get("/api/admin/licenses")
def admin_licenses(request: Request, db: Session = Depends(get_db)):
    """Owner license registry — every issued self-hosted license and its status. Vendor-
    only: gated by WARDEN_METRICS_TOKEN (not a tenant session); 404 without a token."""
    from .models import License
    _require_operator(request)
    rows = db.query(License).order_by(License.issued_at.desc()).all()
    return {"licenses": [r.to_dict() for r in rows]}


@app.post("/api/admin/licenses")
def admin_license_issue(body: dict, request: Request, db: Session = Depends(get_db)):
    """Issue + record a self-hosted license from the operator console. Operator-gated;
    signs with the mounted signing key (503 if unmounted, like renewal). Returns the blob
    to hand the customer plus the registry row."""
    from datetime import date, datetime, timedelta
    from . import licensing
    from .models import License
    import secrets as _secrets
    _require_operator(request)
    key = licensing.signing_key()
    if not key:
        raise HTTPException(status_code=503, detail="license issuing not enabled here (no signing key)")
    org = (body.get("org") or "").strip()
    plan = (body.get("plan") or "").strip()
    if not org or plan not in ("team", "enterprise"):
        raise HTTPException(status_code=400, detail="org and plan (team|enterprise) required")
    seats = int(body.get("seats") or 0)
    term_days = int(body.get("term_days") or licensing.DEFAULT_TERM_DAYS)
    contract_months = int(body.get("contract_months") or 12)
    expires = date.today() + timedelta(days=term_days)
    lic_id = f"lic_{_secrets.token_hex(4)}"
    try:
        blob = licensing.issue(key, org, plan, seats, expires.isoformat(), lic_id=lic_id)
    except licensing.LicenseError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    contract = _naive_now() + timedelta(days=30 * contract_months) if contract_months else None
    row = License(id=lic_id, org=org, plan=plan, seats=seats,
                  expires_at=datetime(expires.year, expires.month, expires.day),
                  contract_until=contract, note=(body.get("note") or "").strip())
    db.add(row)
    db.commit()
    return {"license": blob, **row.to_dict()}


@app.post("/api/admin/licenses/{lic_id}/revoke")
def admin_license_revoke(lic_id: str, request: Request, db: Session = Depends(get_db)):
    """Revoke a self-hosted license from the operator console — renewals refused, the
    instance drops to Free at term end. Operator-gated."""
    from .models import License
    _require_operator(request)
    row = db.get(License, lic_id)
    if row is None:
        raise HTTPException(status_code=404, detail="license not found")
    row.status = "revoked"
    db.commit()
    return row.to_dict()


@app.post("/api/license/renew")
def license_renew(body: dict, db: Session = Depends(get_db)):
    """Self-hosted instances renew their short-term license here (customer-facing, no
    session — the presented blob's signature IS the credential). Verifies the blob, looks
    it up in the registry, and re-signs a fresh term UNLESS it's revoked or past its
    contract end — that's how the owner cancels a self-hosted license. Disabled (503) on
    deployments without the signing key mounted (WARDEN_LICENSE_SIGNING_KEY)."""
    from datetime import date, datetime, timedelta
    from . import licensing
    from .models import License
    key = licensing.signing_key()
    if not key:
        raise HTTPException(status_code=503, detail="license renewal not enabled here")
    blob = (body or {}).get("license", "")
    try:
        payload = licensing.verify(blob, allow_expired=True)   # term may be expiring — expected
    except licensing.LicenseError as exc:
        raise HTTPException(status_code=400, detail=f"invalid license: {exc}")
    row = db.get(License, payload.get("id", ""))
    if row is None:
        raise HTTPException(status_code=404, detail="license not on record")
    now = _naive_now()
    if row.status != "active":
        raise HTTPException(status_code=403, detail="license revoked")
    if row.contract_until and row.contract_until < now:
        raise HTTPException(status_code=403, detail="license contract ended — contact sales@tachtech.net")
    new_expiry = date.today() + timedelta(days=licensing.DEFAULT_TERM_DAYS)
    fresh = licensing.issue(key, row.org, row.plan, row.seats or 0,
                            new_expiry.isoformat(), lic_id=row.id)
    row.expires_at = datetime(new_expiry.year, new_expiry.month, new_expiry.day)
    row.renewed_at = now
    row.renew_count = (row.renew_count or 0) + 1
    db.commit()
    return {"license": fresh, "expires": new_expiry.isoformat()}


def _input_from_request(req: AnalyzeRequest) -> AnalysisInput:
    metadata = {"destination": req.destination} if req.destination else {}
    return AnalysisInput(
        content=req.content,
        subject=req.subject,
        surface=Surface(req.surface),
        metadata=metadata,
    )


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest, current: User = Depends(get_current_user),
            db: Session = Depends(get_db)):
    return run_analysis(_input_from_request(req), req.persist, db, tenant_id=current.tenant_id)


@app.post("/api/analyze/batch")
def analyze_batch(req: BatchAnalyzeRequest, current: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    """Analyze many items in one call — e.g. a SIEM exporting a batch of messages."""
    results = [run_analysis(_input_from_request(it), it.persist, db, tenant_id=current.tenant_id)
               for it in req.items]
    return {"count": len(results), "results": results}


def _ingest_tenant_id(db: Session) -> int | None:
    ref = settings.ingest_tenant.strip()
    if not ref:
        return None
    t = db.query(Tenant).filter(Tenant.slug == ref).first()
    if t is None and ref.isdigit():
        t = db.get(Tenant, int(ref))
    return t.id if t else None


_ACTION_RANK = {"benign": 0, "low": 1, "suspicious": 2, "high": 3, "critical": 4}
_SEV_BY_RANK = {v: k for k, v in _ACTION_RANK.items()}


def _action_for(severity: str, block_severity: str = "high") -> str:
    """Map a verdict severity to allow/warn/block. Block at/above the block threshold;
    warn at suspicious+ but never below the block line (a lower threshold escalates)."""
    rank = _ACTION_RANK.get(severity, 0)
    block_at = _ACTION_RANK.get(block_severity, 3)
    if rank >= block_at:
        return "block"
    return "warn" if rank >= 2 else "allow"


def _enforce_rate(db: Session, tenant_id: int | None) -> None:
    """Count one capture request against the tenant's sensor/ingest quota; 429 if over.
    Uses the `ingest` counter — separate from the gateway budget — so agentic tool-call
    volume can't starve real LLM traffic (bounded by `ingest_rate_limit`, default off)."""
    from .lifecycle import ensure_active
    from .metering import check_daily_ingest, record_and_check
    ensure_active(db, tenant_id)
    allowed, _count, limit = record_and_check(db, tenant_id, kind="ingest")
    if not allowed:
        raise HTTPException(status_code=429, detail=f"ingest rate limit exceeded ({limit}/min)",
                            headers={"Retry-After": "60"})
    if tenant_id is not None:
        day_ok, _today, day_limit = check_daily_ingest(db, tenant_id)
        if not day_ok:
            raise HTTPException(status_code=429,
                                detail=f"daily ingest quota exceeded ({day_limit}/day)",
                                headers={"Retry-After": "3600"})


def _ingest_auth(x_warden_token: str, db: Session) -> tuple[int | None, str]:
    """Resolve (tenant_id, default_actor) from a per-tenant API key (`ak_…`) or the
    shared EXTENSION_INGEST_TOKEN. Used by the token-gated ingest & scan endpoints, which
    are deployed via policy/CI and so authenticate with a capture token, not a user JWT."""
    from .security import looks_like_agent_token, looks_like_api_key, looks_like_jwt

    if looks_like_api_key(x_warden_token):
        from .gateway import _resolve_api_key
        principal = _resolve_api_key(x_warden_token, db)   # 401s on bad/expired key
        return principal.tenant_id, principal.actor
    if looks_like_agent_token(x_warden_token):
        ag = _resolve_agent_token(x_warden_token, db)      # 401s on bad/disabled agent
        return ag.tenant_id, ag.name
    if looks_like_jwt(x_warden_token):                     # OIDC/workload agent identity
        ag = _resolve_agent_jwt(x_warden_token, db)
        if ag is None:
            raise HTTPException(status_code=401, detail="unrecognized or invalid agent JWT")
        return ag.tenant_id, ag.name
    token = settings.extension_ingest_token
    if not token or not hmac.compare_digest(x_warden_token, token):
        raise HTTPException(status_code=401, detail="invalid or missing ingest token")
    return _ingest_tenant_id(db), ""


def _naive_now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _require_operator(request: Request) -> None:
    """Gate the vendor /api/admin/* surface on WARDEN_METRICS_TOKEN (Bearer or ?token=) —
    a cross-tenant operator credential, NOT a tenant session. 404 when no token is
    configured so the surface can't be left open by accident on a deployment that never
    set one up (and isn't even discoverable there)."""
    tok = settings.metrics_token
    if not tok:
        raise HTTPException(status_code=404, detail="not found")
    scheme, _, bearer = request.headers.get("authorization", "").partition(" ")
    provided = bearer if scheme.lower() == "bearer" else request.query_params.get("token", "")
    if not hmac.compare_digest(provided, tok):
        raise HTTPException(status_code=401, detail="operator token required")


def _resolve_agent_token(token: str, db: Session) -> Agent:
    """Resolve an `ag_…` agent token to its Agent (401 on unknown/disabled). Bumps last_seen."""
    from .security import hash_token
    row = (db.query(Agent)
             .filter(Agent.token_hash == hash_token(token), Agent.active.is_(True))
             .one_or_none())
    if row is None:
        raise HTTPException(status_code=401, detail="invalid or disabled agent token")
    row.last_seen = _naive_now()
    db.commit()
    return row


def _resolve_agent_jwt(token: str, db: Session):
    """Validate an OIDC/workload agent JWT and map it to an Agent. The unverified `iss` picks
    the tenant whose agent-OIDC trust to verify against; the validated `sub`/`client_id`/`azp`
    maps to Agent.oidc_subject. Returns the Agent, or None (unknown issuer / no matching
    agent). Raises HTTP 401 on a token that fails signature/claims validation."""
    from .security import jwt_unverified_claims
    from . import oidc
    iss = (jwt_unverified_claims(token).get("iss") or "").strip()
    if not iss:
        return None
    # SECURITY: an issuer is NOT tenant-unique — e.g. GitHub Actions' issuer
    # (token.actions.githubusercontent.com) is identical for every org. Resolve the tenant by
    # the *audience* the token actually validates against, not by .first() on the issuer.
    matched = db.query(Tenant).filter(Tenant.agent_oidc_issuer == iss).all()
    if not matched:
        return None
    with_aud = [t for t in matched if (t.agent_oidc_audience or "").strip()]
    if not with_aud:
        # Require a configured audience; without it any validly-signed token from this issuer
        # (minted for another app/tenant) would authenticate. Fail closed.
        raise HTTPException(status_code=401,
                            detail="agent JWT rejected: workload OIDC has no audience configured")
    last_err = None
    for t in with_aud:
        try:
            claims = oidc.validate_agent_jwt(iss, t.agent_oidc_audience.strip(), token,
                                             jwks_uri=t.agent_oidc_jwks or "")
        except oidc.OIDCError as e:
            last_err = e   # wrong audience for this tenant — try the next one sharing the issuer
            continue
        # Audience validated → this is the token's tenant. Map sub → agent (else no attribution).
        subject = (claims.get("sub") or claims.get("client_id") or claims.get("azp") or "").strip()
        if not subject:
            return None
        ag = (db.query(Agent).filter(Agent.tenant_id == t.id, Agent.oidc_subject == subject,
                                     Agent.active.is_(True)).one_or_none())
        if ag is not None:
            ag.last_seen = _naive_now()
            db.commit()
        return ag
    raise HTTPException(status_code=401,
                        detail=f"agent JWT rejected: {last_err or 'no matching audience'}")


def _capture_agent(x_warden_token: str, x_warden_agent: str, tenant_id, db: Session) -> str:
    """Best-effort agent name for attribution: an `X-Warden-Agent` header or the primary token
    when it's an `ag_…` or an OIDC/workload JWT. Returns "" if none/mismatched (never raises)."""
    from .security import hash_token, looks_like_agent_token, looks_like_jwt
    tok = (x_warden_agent or "").strip() or (x_warden_token or "")
    if looks_like_agent_token(tok):
        row = (db.query(Agent)
                 .filter(Agent.token_hash == hash_token(tok), Agent.active.is_(True))
                 .one_or_none())
        if row is None or (tenant_id is not None and row.tenant_id != tenant_id):
            return ""
        row.last_seen = _naive_now()
        db.commit()
        return row.name
    if looks_like_jwt(tok):
        try:
            ag = _resolve_agent_jwt(tok, db)
        except HTTPException:
            return ""
        if ag is None or (tenant_id is not None and ag.tenant_id != tenant_id):
            return ""
        return ag.name
    return ""


def _score_ai_usage(content: str, actor: str, tool: str, destination: str,
                    tenant_id: int | None, agent: str, db: Session) -> tuple[dict, dict]:
    """Score one ai-usage capture on the AI_USAGE surface + feed discovery. Shared by the
    ai-usage ingest endpoint and the OTLP receiver so their behavior can't drift. Returns
    (verdict, metadata)."""
    meta: dict = {"destination": destination} if destination else {}
    meta["sanctioned_tools"] = _tenant_or_global(
        tenant_id, db, "sanctioned_ai_tools", settings.sanctioned_ai_tools)
    meta["custom_pii"] = _tenant_or_global(tenant_id, db, "custom_pii_patterns", "")
    item = AnalysisInput(
        content=content, sender=actor, channel=tool or "ai_tool",
        surface=Surface.AI_USAGE, metadata=meta,
    )
    from .policy import detect_tool, signal_filter_for
    suppress = _tenant_or_global(tenant_id, db, "tool_suppress", settings.gateway_tool_suppress)
    sig_filter = signal_filter_for(detect_tool(explicit=tool), extra=suppress)
    result = run_analysis(item, persist=True, db=db, tenant_id=tenant_id,
                          signal_filter=sig_filter, agent=agent,
                          persist_benign=settings.usage_persist_benign)
    # Feed the shadow-AI discovery inventory (best-effort — never breaks the verdict).
    from .discovery import record_capture
    record_capture(db, tenant_id, actor, destination, tool,
                   result["signals"], result["risk_score"])
    return result, meta


@app.post("/api/ingest/ai-usage")
def ingest_ai_usage(
    body: AIUsageIngest,
    x_warden_token: str = Header(default=""),
    x_warden_agent: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Score content a browser extension / proxy captured on its way to an AI tool.

    Authenticated by a per-tenant API key (`ak_…`, minted in the console) or the shared
    static EXTENSION_INGEST_TOKEN — not a user JWT — so it can be deployed via policy.
    Returns an action the client enforces: allow / warn / block."""
    tenant_id, default_actor = _ingest_auth(x_warden_token, db)
    _enforce_rate(db, tenant_id)
    actor = body.user or default_actor
    agent = _capture_agent(x_warden_token, x_warden_agent, tenant_id, db)
    _record_heartbeat(db, tenant_id, actor, "ai-usage", body.tool)
    result, meta = _score_ai_usage(body.content, actor, body.tool, body.destination,
                                   tenant_id, agent, db)
    from .detectors.shadow_ai import confirmed_leak
    return {
        "action": _action_for(result["severity"]),
        "risk_score": result["risk_score"],
        "severity": result["severity"],
        "signals": result["signals"],
        "finding_id": result["finding_id"],
        # >1 when this event folded into an already-recorded finding (its seen_count).
        "recurrence": result.get("recurrence"),
        "remediation": remediation_for(result["signals"]),
        # A confirmed secret/PII leak: the client should block regardless of its local
        # enforce flag ("block the certain" — monitor everything else).
        "force_block": settings.gateway_enforce_secrets and confirmed_leak(result["signals"]),
        # The org's enforce stance for local capture planes (Settings → Enforcement),
        # staged per actor/tool via policy overrides: clients honor "block" verdicts
        # when true, without any per-device flag.
        "enforce": _client_enforce_for(tenant_id, actor, body.tool, db),
        # Approved AI tools to offer the user instead of a hard "no" (shown in the block UI).
        "sanctioned_tools": _sanctioned_list(meta["sanctioned_tools"]),
    }


def _sanctioned_list(raw: str) -> list[dict]:
    """Parse the tenant's sanctioned-AI-tools CSV into [{label, url}] for the extension to
    offer as approved alternatives. Domain-like entries become clickable links."""
    out = []
    for entry in (raw or "").split(","):
        e = entry.strip()
        if not e:
            continue
        host = e.replace("https://", "").replace("http://", "").rstrip("/")
        url = f"https://{host}" if ("." in host and " " not in host) else ""
        out.append({"label": e, "url": url})
    return out


@app.post("/api/exception-request")
def exception_request(
    body: ExceptionRequest,
    x_warden_token: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """A user asking their security team to allow a blocked send (from the extension's block
    modal). Recorded to the audit log so an admin can review/act — turns a hard wall into a
    request, which reduces shadow-AI workarounds. Token-gated (the extension's capture key)."""
    from . import audit_log
    tenant_id, default_actor = _ingest_auth(x_warden_token, db)
    _enforce_rate(db, tenant_id)
    audit_log.record(
        db, tenant_id, body.user or default_actor, "exception_requested",
        target=body.destination or "",
        detail={"finding_id": body.finding_id, "reason": body.reason[:500],
                "categories": body.categories[:8]})
    # First-class queue row (the audit entry above is kept for compat/history): admins
    # review these under Policies → Exceptions and can approve into a scoped override.
    from .models import ExceptionRecord
    row = ExceptionRecord(
        tenant_id=tenant_id, finding_id=body.finding_id,
        actor=(body.user or default_actor)[:320],
        destination=body.destination[:2048],
        categories=",".join(dict.fromkeys(c.strip() for c in body.categories[:8] if c.strip())),
        reason=body.reason[:2000])
    db.add(row)
    db.commit(); db.refresh(row)
    return {"ok": True, "id": row.id}


_OTLP_MAX_RECORDS = 1000   # cap Claude-Code events processed per OTLP export (DoS guard)


@app.post("/v1/logs")
async def otlp_logs(
    request: Request,
    x_warden_token: str = Header(default=""),
    x_warden_agent: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """OTLP/HTTP logs receiver (JSON) — the fileless alternative to the `warden-otel` CLI.

    Point a claude-otel collector's `otlphttp` logs exporter (encoding: json) here with an
    `X-Warden-Token` header; Claude Code's user_prompt / tool_result / mcp_server_connection
    events are mapped to the same detection as the ingest API. **Monitor-only** — OTEL is
    post-hoc, so this records but can't block. Always returns OTLP success: a telemetry
    export must never back up because of us (bad records are skipped, not rejected)."""
    from . import otel
    tenant_id, default_actor = _ingest_auth(x_warden_token, db)   # 401 on a bad token
    _enforce_rate(db, tenant_id)
    agent = _capture_agent(x_warden_token, x_warden_agent, tenant_id, db)
    try:
        doc = await request.json()
    except Exception:
        return {"partialSuccess": {}}
    allowed = _tenant_mcp_allow(tenant_id, db)
    block = _tenant_mcp_block_severity(tenant_id, db)
    # Cap records processed per export so one 12 MB body can't fan out into tens of
    # thousands of detection passes + finding writes (each export is one ingest-quota hit).
    processed = 0
    for name, attrs in otel.iter_events(doc):
        if processed >= _OTLP_MAX_RECORDS:
            break
        try:
            if name == "user_prompt":
                f = otel.prompt_fields(attrs)
                if f:
                    _score_ai_usage(f["content"], f["user"] or default_actor, f["tool"],
                                    f["destination"], tenant_id, agent, db)
                    processed += 1
            elif name in ("tool_result", "mcp_server_connection"):
                f = otel.mcp_fields(name, attrs)
                if f:
                    _score_mcp(MCPIngest(**f), tenant_id, default_actor, allowed, block, db, agent=agent)
                    processed += 1
        except Exception:
            continue  # one bad record never fails the whole export
    return {"partialSuccess": {}}


# An agent reading code is normal, and MCP has no external AI destination — so on the
# mcp surface drop source_code_leak / unsanctioned_ai and keep the agentic-action +
# secret/PII signals.
_MCP_DROP = {"source_code_leak", "unsanctioned_ai"}


def _mcp_filter(signals: list) -> list:
    return [s for s in signals if s.category.value not in _MCP_DROP]


def _agent_role_ctx(agent: str, tenant_id, db: Session):
    """(effective_role_dict, enforce) for a named agent, or None. Thin wrapper over the
    shared resolver so both the ingest and gateway paths enforce roles identically."""
    from .authz import role_context
    return role_context(db, tenant_id, agent)


def _authz_signal(enforce: bool, title: str, detail: str, evidence: str):
    from .detectors.base import Category, Signal
    return Signal(
        category=Category.AGENT_AUTHZ, title=title,
        detail=f"{detail} ({'enforce' if enforce else 'monitor'})",
        weight=0.85 if enforce else 0.55, confidence=0.9, detector="authz",
        evidence=evidence, check="agent_authz",
    )


def _agent_authz_probe(agent: str, tenant_id, body, db: Session):
    """Return (signal_filter, decision) for an agent's MCP action. The filter records the
    least-privilege verdict as a finding signal (visibility, monitor + enforce). `decision`
    is a mutable dict {enforce, denied, reason} updated during filtering — the caller
    hard-blocks on enforce+denied *independently* of scoring severity and of the
    disabled-checks/override filter, so authz is a real control, not a mutable signal."""
    from .authz import decision as _authz_decide, RESTRICTED_DATA
    ctx = _agent_role_ctx(agent, tenant_id, db)
    dec = {"enforce": False, "denied": False, "reason": ""}
    if ctx is None:
        return _mcp_filter, dec
    role_d, enforce = ctx
    dec["enforce"] = enforce

    def _filter(signals):
        out = _mcp_filter(signals)
        # Decide against the RAW categories (the MCP filter drops source_code_leak, but a
        # role's data-scope may still forbid it).
        cats = {s.category.value for s in signals}
        denied, reason = _authz_decide(role_d, body.server, body.tool, body.args_text, cats)
        if denied:
            dec["denied"] = True
            dec["reason"] = reason
            out.append(_authz_signal(enforce, "Agent action outside its role", reason,
                                     f"{agent} → {(body.tool or body.server or '')[:60]}"))
        return out

    return _filter, dec


def _tenant_or_global(tenant_id: int | None, db: Session, attr: str, global_value: str) -> str:
    """A tenant's own list for `attr` if set, else the global env default."""
    if tenant_id is not None:
        t = db.get(Tenant, tenant_id)
        if t and (getattr(t, attr, "") or "").strip():
            return getattr(t, attr).strip()
    return global_value


def _tenant_client_enforce(tenant_id: int | None, db: Session) -> bool:
    """Effective enforce stance for the local capture planes (CLI hooks + desktop proxy):
    the tenant's tri-state client_enforce if set, else the global CLIENT_ENFORCE default.
    Returned in ingest verdicts so the console governs clients without any per-device
    config; clients may still force enforce locally via WARDEN_ENFORCE."""
    if tenant_id is not None:
        t = db.get(Tenant, tenant_id)
        if t is not None and t.client_enforce is not None:
            return bool(t.client_enforce)
    return settings.client_enforce


def _client_enforce_for(tenant_id: int | None, actor: str, tool: str, db: Session) -> bool:
    """Staged enforcement: the tenant/global stance, unless a policy override with an
    explicit enforce matches this actor (+ tool) — so an org can enforce a pilot user,
    a group glob, or one tool while everyone else stays in monitor."""
    base = _tenant_client_enforce(tenant_id, db)
    if tenant_id is None or not actor:
        return base
    from .policies import resolve_enforce
    overrides = db.query(PolicyOverride).filter(PolicyOverride.tenant_id == tenant_id).all()
    effective, _ = resolve_enforce(base, actor, overrides, channel=tool)
    return effective


def _record_heartbeat(db: Session, tenant_id: int | None, actor: str,
                      plane: str, tool: str = "") -> None:
    """Best-effort fleet-health upsert — never breaks the capture path it rides on."""
    try:
        from datetime import datetime, timezone

        from .models import SensorHeartbeat
        row = (db.query(SensorHeartbeat)
                 .filter(SensorHeartbeat.tenant_id == tenant_id,
                         SensorHeartbeat.actor == (actor or ""),
                         SensorHeartbeat.plane == plane,
                         SensorHeartbeat.tool == (tool or "")[:64])
                 .one_or_none())
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if row is None:
            row = SensorHeartbeat(tenant_id=tenant_id, actor=(actor or ""), plane=plane,
                                  tool=(tool or "")[:64], first_seen=now)
            db.add(row)
        row.last_seen = now
        row.count = (row.count or 0) + 1
        db.commit()
    except Exception:
        db.rollback()


def _tenant_mcp_allow(tenant_id: int | None, db: Session) -> str:
    """Effective MCP server allowlist for a tenant: its own list, else the global default."""
    return _tenant_or_global(tenant_id, db, "mcp_allowed_servers", settings.mcp_allowed_servers)


def _tenant_mcp_block_severity(tenant_id: int | None, db: Session) -> str:
    """Effective block threshold for capture-plane MCP verdicts (tenant, else global)."""
    return _tenant_or_global(tenant_id, db, "mcp_block_severity",
                             settings.mcp_block_severity) or "high"


def _score_mcp(body: MCPIngest, tenant_id: int | None, default_actor: str,
               allowed_servers: str, block_severity: str, db: Session, agent: str = "",
               client_ua: str = "") -> dict:
    """Score one MCP activity on the `mcp` surface and return the client verdict.

    Benign (allow-level) verdicts aren't persisted unless WARDEN_MCP_PERSIST_BENIGN is set
    — most tool calls are benign noise, not findings. Shared by the single + batch endpoints
    so their behavior can't drift."""
    actor = body.user or default_actor
    # Synthesize the scannable text: tool arguments, resource URI, and advertised tool
    # descriptions — so shadow-AI catches secrets/PII in args and the finding has context.
    content = "\n".join(p for p in [
        body.args_text, body.resource, "\n".join(body.tool_descriptions),
    ] if p) or f"MCP {body.method} {body.tool or body.server}".strip()

    item = AnalysisInput(
        content=content, sender=actor, channel=body.tool or "mcp",
        subject=f"MCP {body.method}".strip(),
        surface=Surface.MCP,
        metadata={
            "method": body.method, "server": body.server, "tool": body.tool,
            "args_text": body.args_text, "resource": body.resource,
            "tool_descriptions": body.tool_descriptions, "transport": body.transport,
            "allowed_servers": allowed_servers,
            "command": body.command, "binary_sha256": body.binary_sha256,
            "pin_status": body.pin_status,
        },
    )
    # Least-privilege: fold agent role authz (action + shell command + data-scope) into the
    # MCP scan. The finding records it (monitor + enforce); an enforce-deny then hard-blocks
    # below — independent of severity and of the disabled-checks/override filter, so authz is
    # a control, not a mutable signal.
    authz_filter, authz = _agent_authz_probe(agent, tenant_id, body, db)
    result = run_analysis(item, persist=True, db=db, tenant_id=tenant_id,
                          signal_filter=authz_filter,
                          agent=agent, persist_benign=settings.mcp_persist_benign)
    action = _action_for(result["severity"], block_severity)
    if authz["enforce"] and authz["denied"]:
        action = "block"
    # Feed shadow-AI discovery: the MCP surface has no destination domain, so the plane's
    # User-Agent (warden-cursor-hook / -hook / -gemini / -codex / -mcp) names the tool. This
    # is how Cursor, Claude Code, Gemini CLI and Codex show up in the inventory at all.
    from .ai_catalog import classify_client
    from .discovery import record_capture_client
    record_capture_client(db, tenant_id, actor, classify_client(client_ua),
                          result["signals"], result["risk_score"])
    return {
        "action": action,
        "risk_score": result["risk_score"],
        "severity": result["severity"],
        "signals": result["signals"],
        "finding_id": result["finding_id"],
        "remediation": remediation_for(result["signals"]),
        # Org enforce stance for local capture planes — same field as ai-usage verdicts,
        # staged per actor/tool via policy overrides.
        "enforce": _client_enforce_for(tenant_id, actor, body.tool or "mcp", db),
    }


@app.post("/api/ingest/mcp")
def ingest_mcp(
    body: MCPIngest,
    x_warden_token: str = Header(default=""),
    x_warden_agent: str = Header(default=""),
    user_agent: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Score an MCP JSON-RPC activity a capture client (proxy, warden-hook, warden-mcp)
    saw (agentic tool-use). Token-gated; returns an action the client enforces on the
    `mcp` surface: allow/warn/block. Benign verdicts aren't persisted by default."""
    tenant_id, default_actor = _ingest_auth(x_warden_token, db)
    _enforce_rate(db, tenant_id)
    agent = _capture_agent(x_warden_token, x_warden_agent, tenant_id, db)
    _record_heartbeat(db, tenant_id, body.user or default_actor, "mcp", body.tool)
    return _score_mcp(body, tenant_id, default_actor, _tenant_mcp_allow(tenant_id, db),
                      _tenant_mcp_block_severity(tenant_id, db), db, agent=agent,
                      client_ua=user_agent)


@app.post("/api/ingest/mcp/batch")
def ingest_mcp_batch(
    body: MCPBatchIngest,
    x_warden_token: str = Header(default=""),
    x_warden_agent: str = Header(default=""),
    user_agent: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Score many MCP activities in one request — for long-lived capture clients
    (warden-mcp) that would otherwise post per tool call. Counts as a single ingest
    request against the tenant's sensor quota. Returns per-item verdicts, index-aligned."""
    tenant_id, default_actor = _ingest_auth(x_warden_token, db)
    _enforce_rate(db, tenant_id)
    agent = _capture_agent(x_warden_token, x_warden_agent, tenant_id, db)
    if body.items:
        _record_heartbeat(db, tenant_id, body.items[0].user or default_actor, "mcp",
                          body.items[0].tool)
    allowed = _tenant_mcp_allow(tenant_id, db)
    block = _tenant_mcp_block_severity(tenant_id, db)
    results = [_score_mcp(item, tenant_id, default_actor, allowed, block, db, agent=agent,
                          client_ua=user_agent)
               for item in body.items]
    return {"results": results}


def _parse_mcp_servers(content: str) -> list[dict]:
    """Pull the server map from an MCP config file — Claude Code/Desktop & Cursor
    (`mcpServers`) or VS Code (`servers` / `mcp.servers`). Returns [{name, ...spec}]."""
    import json as _json
    try:
        j = _json.loads(content)
    except (ValueError, TypeError):
        return []
    if not isinstance(j, dict):
        return []
    servers = j.get("mcpServers")
    if not isinstance(servers, dict):
        servers = j.get("servers")
    if not isinstance(servers, dict):
        mcp = j.get("mcp")
        servers = mcp.get("servers") if isinstance(mcp, dict) else None
    if not isinstance(servers, dict):
        return []
    return [{"name": name, **spec} for name, spec in servers.items() if isinstance(spec, dict)]


@app.post("/api/scan/mcp-config")
def scan_mcp_config(
    body: MCPConfigScan,
    x_warden_token: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Vet an MCP configuration file (in CI, via the git plane, or the console).

    Enumerates the declared MCP servers — including **local stdio** ones the network can't
    see — and flags unapproved servers (`MCP_ALLOWED_SERVERS`), dangerous launch commands,
    sensitive paths, and secrets committed in the config. Agentless: it reads config, not
    a running process. Token-gated; returns an overall action + per-server detail."""
    from urllib.parse import urlparse
    tenant_id, default_actor = _ingest_auth(x_warden_token, db)
    _enforce_rate(db, tenant_id)
    _record_heartbeat(db, tenant_id, default_actor, "posture", "mcp-config")

    from .detectors.dep_guard import extract_mcp_packages
    from . import osv

    flagged: list[dict] = []
    worst = 0
    allowed = _tenant_mcp_allow(tenant_id, db)
    block_sev = _tenant_mcp_block_severity(tenant_id, db)
    servers = _parse_mcp_servers(body.content)

    # Supply-chain: resolve each server's launcher to the registry package it runs, then OSV
    # the pinned ones for CVEs (matches Kirin's "MCP dependencies" check).
    _srv_pkgs = {s.get("name", ""): extract_mcp_packages(s.get("command", ""), s.get("args") or [])
                 for s in servers}
    _pin_vulns: dict = {}
    if settings.dep_osv_enabled:
        pins = [p for pkgs in _srv_pkgs.values() for p in pkgs if p[2]]
        if pins:
            _pin_vulns = osv.query(list(dict.fromkeys(pins)))
    from .policies import parse_disabled
    _t = db.get(Tenant, tenant_id) if tenant_id is not None else None
    _mcp_disabled = parse_disabled(getattr(_t, "disabled_checks", "") if _t else "")

    for s in servers:
        name = s.get("name", "")
        url = s.get("url") or s.get("serverUrl") or ""
        command = s.get("command", "")
        args = s.get("args") or []
        env = s.get("env") or {}
        if url:
            server_host = urlparse(url).hostname or url
            transport = "http"
        else:
            server_host = name          # local stdio has no host — key it by name
            transport = "stdio"
        args_text = " ".join([str(command)] + [str(a) for a in args]
                             + [str(v) for v in (env.values() if isinstance(env, dict) else [])])
        item = AnalysisInput(
            content=args_text or name, subject=f"mcp-config: {name}", channel="mcp-config",
            surface=Surface.MCP,
            metadata={"method": "initialize", "server": server_host, "tool": name,
                      "args_text": args_text, "transport": transport,
                      "allowed_servers": allowed},
        )
        result = run_analysis(item, persist=bool(body.record) and tenant_id is not None,
                              db=db, tenant_id=tenant_id, signal_filter=_mcp_filter)
        signals = list(result["signals"])
        sev = result["severity"]
        # Supply-chain signals for this server's launcher package (respects the
        # dependency_risk policy toggle).
        # Known-CVE check on the server's pinned launcher package (Kirin "MCP dependencies").
        # Only pinned deps are flagged — unpinned npx/uvx is the norm, so warning on it would
        # be pure noise; the OSV advisory on a concrete version is the precise signal.
        if "dependency_risk" not in _mcp_disabled:
            for (eco, pname, ver) in _srv_pkgs.get(name, []):
                ids = _pin_vulns.get((eco, pname, ver)) if ver else None
                if ids:
                    signals.append({"category": "dependency_risk", "title": "MCP server dependency vuln (OSV)",
                                    "detail": f"{pname}@{ver} has {len(ids)} known advisory(ies): {', '.join(ids[:4])}.",
                                    "weight": 0.9, "confidence": 0.95, "detector": "osv", "evidence": ", ".join(ids[:4])})
                    sev = "critical"
        action = _action_for(sev, block_sev)
        worst = max(worst, _ACTION_RANK.get(sev, 0))
        if action != "allow":
            flagged.append({"name": name, "transport": transport, "action": action,
                            "severity": sev, "risk_score": result["risk_score"],
                            "signals": signals})

    overall = _action_for(_SEV_BY_RANK[worst], block_sev)
    return {"action": overall, "scanned": len(servers), "servers": flagged}


# Categories that matter for a repo commit: a repo is *expected* to contain code, so
# drop source_code_leak; there's no external destination, so drop unsanctioned_ai.
_VCS_KEEP = {"secret_leak", "pii_exposure"}


def _vcs_filter(signals: list) -> list:
    return [s for s in signals if s.category.value in _VCS_KEEP]


@app.post("/api/scan/code")
def scan_code(
    body: CodeScanRequest,
    x_warden_token: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Scan code/diffs (pre-commit hook, CI) for secrets & PII before they reach a repo.

    Reuses the detection engine but keeps only data-loss categories — a repo is meant to
    hold code, so source_code_leak is ignored. Token-gated like the ingest endpoint.
    Returns an overall action plus per-file detail for files that aren't clean."""
    tenant_id, _ = _ingest_auth(x_warden_token, db)
    _enforce_rate(db, tenant_id)

    flagged: list[dict] = []
    worst = 0
    for f in body.files[:1000]:
        item = AnalysisInput(content=f.content, subject=f.path, channel="git",
                             surface=Surface.AI_USAGE)
        result = run_analysis(item, persist=False, db=db, tenant_id=tenant_id,
                              signal_filter=_vcs_filter)
        action = _action_for(result["severity"])
        worst = max(worst, _ACTION_RANK.get(result["severity"], 0))
        if action != "allow":
            flagged.append({
                "path": f.path, "action": action, "severity": result["severity"],
                "risk_score": result["risk_score"], "signals": result["signals"],
            })
            if body.record and tenant_id is not None:
                run_analysis(item, persist=True, db=db, tenant_id=tenant_id,
                             signal_filter=_vcs_filter)

    overall = "block" if worst >= 3 else ("warn" if worst >= 2 else "allow")
    return {"action": overall, "scanned": len(body.files[:1000]), "files": flagged}


@app.post("/api/scan/s3")
def scan_s3(
    body: S3Scan,
    x_warden_token: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Scan an S3 bucket's objects for secrets & PII at rest (warden-s3-scan streams them
    here). Same data-loss detection as the code scanner, plus the bucket's public-exposure
    flag: a world-readable bucket holding sensitive data is the crown-jewel case, so a
    non-clean object in a public bucket is escalated to `block` and tagged for alerting.
    Token-gated. Returns an overall action + per-object detail; `public` echoes exposure."""
    tenant_id, _ = _ingest_auth(x_warden_token, db)
    _enforce_rate(db, tenant_id)

    flagged: list[dict] = []
    worst = 0
    for obj in body.objects[:1000]:
        meta = {"bucket": body.bucket, "key": obj.key, "region": body.region,
                "public": body.public, "source": "s3-scan"}
        item = AnalysisInput(content=obj.content, subject=f"s3://{body.bucket}/{obj.key}",
                             channel="s3", surface=Surface.AI_USAGE, metadata=meta)
        result = run_analysis(item, persist=False, db=db, tenant_id=tenant_id,
                              signal_filter=_vcs_filter)
        action = _action_for(result["severity"])
        if action == "allow":
            continue
        # Public bucket + sensitive object = the worst case — escalate to a hard block.
        if body.public:
            action = "block"
        worst = max(worst, 3 if body.public else _ACTION_RANK.get(result["severity"], 0))
        flagged.append({
            "key": obj.key, "action": action, "severity": result["severity"],
            "risk_score": result["risk_score"], "signals": result["signals"],
            "public": body.public,
        })
        if body.record and tenant_id is not None:
            run_analysis(item, persist=True, db=db, tenant_id=tenant_id,
                         signal_filter=_vcs_filter)

    overall = "block" if worst >= 3 else ("warn" if worst >= 2 else "allow")
    return {"action": overall, "scanned": len(body.objects[:1000]),
            "bucket": body.bucket, "public": body.public, "objects": flagged}


@app.post("/api/scan/deps")
def scan_deps(
    body: CodeScanRequest,
    x_warden_token: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Vet dependency manifests (package.json, requirements.txt) for supply-chain risk in
    CI / the git plane — install-script abuse, non-registry sources, and known-bad packages.

    Heuristic checks always run; when DEP_OSV_ENABLED is set, pinned dependencies are also
    checked against the OSV.dev advisory feed for known CVEs (fails open on outage).
    Token-gated; returns an overall action plus per-file detail for manifests that aren't clean."""
    from .detectors.dep_guard import extract_pinned
    from . import osv
    tenant_id, _ = _ingest_auth(x_warden_token, db)
    _enforce_rate(db, tenant_id)

    files = body.files[:1000]
    dep_deny = _tenant_or_global(tenant_id, db, "dep_denylist", settings.dep_denylist)

    # Optional OSV advisory lookup — batch every pinned dep across all files in one call.
    vulns: dict = {}
    if settings.dep_osv_enabled:
        all_pins: list = []
        for f in files:
            all_pins.extend(extract_pinned(f.content, f.path))
        vulns = osv.query(list(dict.fromkeys(all_pins)))

    flagged: list[dict] = []
    worst = 0
    for f in files:
        item = AnalysisInput(content=f.content, subject=f.path, channel="deps",
                             surface=Surface.DEPS,
                             metadata={"dep_denylist": dep_deny})
        result = run_analysis(item, persist=bool(body.record) and tenant_id is not None,
                              db=db, tenant_id=tenant_id)
        signals = list(result["signals"])
        # Merge OSV advisories for this file's pinned deps.
        for (eco, name, ver) in extract_pinned(f.content, f.path):
            ids = vulns.get((eco, name, ver))
            if ids:
                signals.append({
                    "category": "dependency_risk", "title": "Known vulnerability (OSV)",
                    "detail": f"{name}@{ver} has {len(ids)} known advisory(ies): "
                              f"{', '.join(ids[:4])}.",
                    "weight": 0.9, "confidence": 0.95, "detector": "osv",
                    "evidence": ", ".join(ids[:4]),
                })
        severity = "critical" if any(s["detector"] == "osv" for s in signals) else result["severity"]
        action = _action_for(severity)
        worst = max(worst, _ACTION_RANK.get(severity, 0))
        if action != "allow":
            flagged.append({"path": f.path, "action": action, "severity": severity,
                            "risk_score": result["risk_score"], "signals": signals})

    overall = "block" if worst >= 3 else ("warn" if worst >= 2 else "allow")
    return {"action": overall, "scanned": len(files), "files": flagged}


@app.post("/api/scan/ide-extensions")
def scan_ide_extensions(
    body: IDEExtScan,
    x_warden_token: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Vet a list of IDE extensions (from `.vscode/extensions.json` in CI, or an MDM software
    inventory) for known-bad / unapproved editor plugins. Agentless — reads a list, not a
    running IDE. Token-gated; returns an action plus the flagged extensions."""
    tenant_id, default_actor = _ingest_auth(x_warden_token, db)
    _enforce_rate(db, tenant_id)
    _record_heartbeat(db, tenant_id, default_actor, "posture", "ide-extensions")
    content = body.content or "\n".join(body.extensions)
    item = AnalysisInput(content=content, subject="ide-extensions", channel="ide",
                         surface=Surface.IDE,
                         metadata={
                             "allowed": _tenant_or_global(tenant_id, db, "ide_ext_allowed", settings.ide_ext_allowed),
                             "denylist": _tenant_or_global(tenant_id, db, "ide_ext_denylist", settings.ide_ext_denylist),
                         })
    result = run_analysis(item, persist=bool(body.record) and tenant_id is not None,
                          db=db, tenant_id=tenant_id)
    return {
        "action": _action_for(result["severity"]),
        "severity": result["severity"],
        "risk_score": result["risk_score"],
        "extensions": result["signals"],
    }


@app.post("/api/scan/agent-config")
def scan_agent_config(
    body: AgentConfigScan,
    x_warden_token: str = Header(default=""),
    x_warden_agent: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Scan an AI coding-assistant config (Cursor settings.json, MCP client config, agent CLI
    flags) for unsafe autonomy — YOLO / auto-apply / auto-run / skip-permissions. Attributed
    to the submitting user, so findings show per-registered-user. Token-gated for the posture
    sensor / cursor hook."""
    tenant_id, default_actor = _ingest_auth(x_warden_token, db)
    _enforce_rate(db, tenant_id)
    actor = body.user or default_actor
    agent = _capture_agent(x_warden_token, x_warden_agent, tenant_id, db)
    _record_heartbeat(db, tenant_id, actor, "posture", body.tool or "agent-config")
    item = AnalysisInput(content=body.content, sender=actor,
                         channel=f"{body.tool or 'agent'}-config", surface=Surface.IDE,
                         metadata={"kind": "agent_config", "tool": body.tool})
    result = run_analysis(item, persist=bool(body.record) and tenant_id is not None,
                          db=db, tenant_id=tenant_id, agent=agent)
    return {
        "action": _action_for(result["severity"]),
        "severity": result["severity"],
        "risk_score": result["risk_score"],
        "signals": result["signals"],
        "remediation": remediation_for(result["signals"]),
    }


@app.post("/api/scan/oversharing")
def scan_oversharing(
    body: OversharingScan,
    x_warden_token: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Need-to-know check: given an LLM response and the user who received it, flag when it
    surfaced restricted data (confidential / PII / keywords) the recipient isn't permitted to
    see — the "LLM oversharing" problem. Rules come from the tenant's need-to-know config.
    For enterprise search / Copilot / RAG integrations to call with each answer."""
    tenant_id, _default_actor = _ingest_auth(x_warden_token, db)
    _enforce_rate(db, tenant_id)
    # Need-to-know authorization uses ONLY the explicitly-supplied recipient — never the
    # token's own actor. Falling back to default_actor here let the integration's API-key
    # label serve as the recipient, so a key named to match an allowed glob (or a caller
    # setting user to an authorized value) could silently suppress the oversharing finding.
    # The recipient is schema-validated (required, email-shaped); an unknown one matches no
    # glob, so the check fails closed.
    actor = body.user
    rules = _tenant_or_global(tenant_id, db, "oversharing_rules", "")
    item = AnalysisInput(content=body.content, sender=actor,
                         channel=body.source or "llm-response", surface=Surface.OVERSHARING,
                         subject=f"LLM response to {actor or 'user'}",
                         metadata={"oversharing_rules": rules})
    result = run_analysis(item, persist=bool(body.record) and tenant_id is not None,
                          db=db, tenant_id=tenant_id)
    return {
        "action": _action_for(result["severity"]),
        "severity": result["severity"],
        "risk_score": result["risk_score"],
        "signals": result["signals"],
        "remediation": remediation_for(result["signals"]),
    }


@app.post("/api/scan/secrets")
def scan_secrets(
    body: SecretScan,
    x_warden_token: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Record credentials the local `warden-secrets` scanner found AT REST on a device
    (SSH/RSA keys, cloud/VCS tokens, .env, .git-credentials). Privacy-preserving: the
    scanner sends only metadata (type, path, masked preview, world-readability) — never
    the raw secret. Each file is scored as a `credential_at_rest` finding; the response
    carries a per-item remediation plan. Token-gated."""
    tenant_id, actor = _ingest_auth(x_warden_token, db)
    _enforce_rate(db, tenant_id)
    host = (body.host or "").strip()
    results = []
    for it in body.items:
        results.append(_record_secret(it, host, actor, tenant_id, bool(body.record), db))
    flagged = [r for r in results if r["severity"] not in ("benign", "low")]
    return {"scanned": len(results), "flagged": len(flagged), "findings": results}


def _record_secret(it: SecretAtRest, host: str, actor: str, tenant_id, record: bool,
                   db: Session) -> dict:
    """Score + (optionally) persist one at-rest credential finding; shared by the
    warden-secrets scan and the third-party scanner importer."""
    item = AnalysisInput(
        content=f"{it.path}\n{it.masked}", subject=it.path,
        sender=actor, channel=host or "endpoint", surface=Surface.SECRETS,
        metadata={"secret_types": it.secret_types, "path": it.path,
                  "world_readable": it.world_readable, "verified": it.verified,
                  "source": it.source, "evidence": it.masked or it.path},
    )
    r = run_analysis(item, persist=record and tenant_id is not None, db=db, tenant_id=tenant_id)
    return {
        "path": it.path, "secret_types": it.secret_types, "line": it.line,
        "verified": it.verified, "source": it.source,
        "severity": r["severity"], "risk_score": r["risk_score"],
        "action": _action_for(r["severity"]),
        "remediation": _secret_remediation(it),
    }


@app.post("/api/scan/import")
def scan_import(
    body: ScannerImport,
    x_warden_token: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Ingest a third-party secret scanner's output (TruffleHog / Gitleaks / GitGuardian)
    and turn it into Warden `credential_at_rest` findings — one console, one scoring model,
    one alert/SIEM path across every scanner. The raw secret is masked at ingest and never
    persisted; TruffleHog's `Verified` flag escalates a finding to critical. Token-gated."""
    from . import scanner_import
    tenant_id, actor = _ingest_auth(x_warden_token, db)
    _enforce_rate(db, tenant_id)
    normalized = scanner_import.normalize(body.tool, body.results)
    if not normalized:
        raise HTTPException(status_code=400,
                            detail=f"no findings parsed for tool '{body.tool}' "
                                   "(supported: trufflehog, gitleaks, gitguardian)")
    normalized = normalized[:5000]   # bound work from an oversized scanner report
    host = (body.host or "").strip()
    results = [
        _record_secret(
            SecretAtRest(path=f["path"], secret_types=f["secret_types"], masked=f["masked"],
                         line=f["line"], verified=f["verified"], source=f["source"]),
            host, actor, tenant_id, bool(body.record), db)
        for f in normalized
    ]
    flagged = [r for r in results if r["severity"] not in ("benign", "low")]
    verified = [r for r in results if r["verified"]]
    return {"tool": body.tool, "scanned": len(results), "flagged": len(flagged),
            "verified_live": len(verified), "findings": results}


def _secret_remediation(it: SecretAtRest) -> list[str]:
    """A concrete rotate/lock-down plan for one at-rest credential."""
    steps: list[str] = []
    types = " ".join(it.secret_types).lower()
    if "private key" in types:
        steps.append("Rotate the key pair and remove the private key from disk; use an SSH "
                     "agent or the OS keychain instead of a plaintext key file.")
    if "github" in types:
        steps.append("Revoke the token at github.com/settings/tokens and re-issue a "
                     "fine-grained, expiring PAT via the gh keyring / a secret manager.")
    if "aws" in types:
        steps.append("Deactivate the access key in IAM and switch to short-lived creds "
                     "(aws sso / STS) — stop storing long-lived keys in ~/.aws/credentials.")
    if not steps:
        steps.append("Rotate the credential and move it out of the file into a secret "
                     "manager or the OS keychain.")
    if it.world_readable:
        steps.append(f"Tighten permissions now: chmod 600 {it.path} (currently readable by "
                     "other local users — prime infostealer target).")
    return steps


@app.get("/api/policy-pack")
def policy_pack(
    base_url: str = "https://warden.example.com",
    proxy_host: str = "",
    proxy_port: int = 8081,
    hook_path: str = "/usr/local/bin/warden-hook",
    posture_path: str = "/usr/local/bin/warden-posture",
    cursor_hook_path: str = "/usr/local/bin/warden-cursor-hook",
    gemini_hook_path: str = "/usr/local/bin/warden-gemini-hook",
    codex_hook_path: str = "/usr/local/bin/warden-codex-hook",
    secrets_engine: str = "trufflehog",
    ext_update_url: str = "",
    ext_crx_url: str = "",
    browser_ext_lockdown: bool = False,
    browser_ext_blocklist: str = "",
    browser_ext_allowlist: str = "",
    browser_ext_blocked_hosts: str = "",
    route_gateway: bool = False,
    current: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Generate the MDM policy pack (agentless enforcement config): VS Code extension
    allowlist, system-proxy profiles, browser force-install, a CA-deployment note, and
    the Claude Code managed-settings.json (local-plane hooks; by default Claude Code
    keeps its own sign-in with forceLoginMethod=claudeai — pass route_gateway=true to
    route prompts through the gateway and bill the org's provider key instead).

    Applied by the org's MDM (Jamf/Intune/GPO) — no Warden agent on the device. The
    extension allow/deny lists use this tenant's IDE-vetting config, else the global."""
    from . import policy_pack as pp
    from .plans import require_feature
    require_feature(db.get(Tenant, current.tenant_id), "mdm")
    allowed_raw = _tenant_or_global(current.tenant_id, db, "ide_ext_allowed", settings.ide_ext_allowed)
    denied_raw = _tenant_or_global(current.tenant_id, db, "ide_ext_denylist", settings.ide_ext_denylist)
    allowed = [x.strip() for x in allowed_raw.split(",") if x.strip()]
    denied = [x.strip() for x in denied_raw.split(",") if x.strip()]
    _csv = lambda s: [x.strip() for x in (s or "").split(",") if x.strip()]
    artifacts = pp.render_pack(base_url=base_url, extension_id=settings.extension_id,
                               proxy_host=proxy_host, proxy_port=proxy_port,
                               allowed_exts=allowed, denied_exts=denied,
                               hook_path=hook_path, posture_path=posture_path,
                               cursor_hook_path=cursor_hook_path,
                               gemini_hook_path=gemini_hook_path,
                               codex_hook_path=codex_hook_path,
                               secrets_engine=secrets_engine,
                               ext_update_url=ext_update_url, ext_crx_url=ext_crx_url,
                               browser_ext_lockdown=browser_ext_lockdown,
                               browser_ext_blocklist=_csv(browser_ext_blocklist),
                               browser_ext_allowlist=_csv(browser_ext_allowlist),
                               browser_ext_blocked_hosts=_csv(browser_ext_blocked_hosts),
                               route_gateway=route_gateway)
    return {"artifacts": artifacts}


@app.get("/api/findings")
def list_findings(
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    severity: str | None = None,
    status: str | None = None,
    surface: str | None = None,
    actor: str | None = None,
    limit: int = 100,
):
    q = db.query(Finding).filter(Finding.tenant_id == current.tenant_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    if status:
        q = q.filter(Finding.status == status)
    if surface:
        q = q.filter(Finding.surface == surface)
    if actor:
        q = q.filter(Finding.sender == actor)
    # Order by last activity so a folded recurrence resurfaces its original row. last_seen
    # is always set (model default + migration backfill); plain DESC keeps the
    # (tenant_id, last_seen) index usable — a coalesce() here would force a full sort.
    rows = (q.order_by(Finding.last_seen.desc().nullslast(), Finding.id.desc())
             .limit(min(limit, 500)).all())
    return {"findings": [r.to_summary() for r in rows]}


@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: int, current: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    row = db.get(Finding, finding_id)
    if not row or row.tenant_id != current.tenant_id:
        raise HTTPException(status_code=404, detail="finding not found")
    from .crypto import unwrap_dek
    tenant = db.get(Tenant, current.tenant_id)
    dek = unwrap_dek(tenant.dek_wrapped) if tenant and tenant.dek_wrapped else None
    return row.to_detail(dek)


@app.patch("/api/findings/{finding_id}")
def update_status(finding_id: int, body: StatusUpdate,
                  current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    row = db.get(Finding, finding_id)
    if not row or row.tenant_id != current.tenant_id:
        raise HTTPException(status_code=404, detail="finding not found")
    row.status = body.status
    db.commit()
    from . import audit_log
    audit_log.record(db, current.tenant_id, current.email, "finding.status",
                     target=str(finding_id), detail={"status": row.status})
    return {"id": finding_id, "status": row.status}


@app.post("/api/findings/bulk-status")
def bulk_update_status(body: BulkStatusUpdate, current: User = Depends(get_current_user),
                       db: Session = Depends(get_db)):
    """Set the status of many findings at once (group triage from the console). Only rows
    in the caller's tenant are touched; unknown/foreign ids are silently skipped."""
    n = (db.query(Finding)
         .filter(Finding.tenant_id == current.tenant_id, Finding.id.in_(body.ids))
         .update({Finding.status: body.status}, synchronize_session=False))
    db.commit()
    from . import audit_log
    audit_log.record(db, current.tenant_id, current.email, "finding.bulk_status",
                     detail={"status": body.status, "count": n, "ids": body.ids[:50]})
    return {"updated": n, "status": body.status}


@app.post("/api/findings/purge")
def purge_findings(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Delete this tenant's findings older than its retention window (0 = keep forever).
    Idempotent; run it from a scheduler for ongoing enforcement."""
    from datetime import datetime, timedelta, timezone
    tenant = db.get(Tenant, current.tenant_id)
    days = tenant.retention_days if tenant else 0
    if not days:
        return {"deleted": 0, "retention_days": 0}
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
    n = (db.query(Finding)
         .filter(Finding.tenant_id == current.tenant_id, Finding.created_at < cutoff)
         .delete())
    db.commit()
    from . import audit_log
    audit_log.record(db, current.tenant_id, current.email, "findings.purge",
                     detail={"deleted": n, "retention_days": days})
    return {"deleted": n, "retention_days": days}


@app.post("/api/findings/dismiss-benign")
def dismiss_benign_findings(current: User = Depends(require_admin),
                            db: Session = Depends(get_db)):
    """Bulk-dismiss this tenant's open allow-level (benign/low) findings — one-time cleanup
    for backlogs recorded before benign captures stopped persisting (see
    WARDEN_USAGE_PERSIST_BENIGN). Idempotent; verdicts and content are kept."""
    n = (db.query(Finding)
         .filter(Finding.tenant_id == current.tenant_id, Finding.status == "open",
                 Finding.severity.in_(["benign", "low"]))
         .update({Finding.status: "dismissed"}, synchronize_session=False))
    db.commit()
    from . import audit_log
    audit_log.record(db, current.tenant_id, current.email, "findings.dismiss_benign",
                     detail={"dismissed": n})
    return {"dismissed": n}


@app.get("/api/corpus/export")
def export_corpus(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Export this tenant's triaged/dismissed findings as eval-corpus JSONL.

    Feeds the detection feedback loop: analyst decisions become labeled data you can
    run through `python -m app.eval --corpus <file>` to measure quality on real traffic."""
    from fastapi.responses import PlainTextResponse

    from .eval.export import export_examples, to_jsonl

    examples = export_examples(db, current.tenant_id)
    return PlainTextResponse(to_jsonl(examples), media_type="application/x-ndjson")


@app.post("/api/coverage/reconcile")
def coverage_reconcile(body: CoverageRequest, current: User = Depends(require_admin),
                       db: Session = Depends(get_db)):
    """Reconcile an IdP/CASB list of who used AI tools against Warden's capture.

    Returns the actors using AI that Warden never saw — likely on unmanaged devices or
    bypassing the capture planes (the shadow set)."""
    from datetime import datetime, timedelta, timezone

    from .coverage import reconcile

    q = (
        db.query(Finding.sender)
        .filter(Finding.tenant_id == current.tenant_id,
                Finding.surface.in_(["llm_io", "ai_usage"]),
                Finding.sender != "")
    )
    if body.window_days:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=body.window_days)).replace(tzinfo=None)
        q = q.filter(Finding.created_at >= cutoff)
    covered = {r[0] for r in q.distinct().all()}
    return reconcile(body.events, covered)


@app.get("/api/activity/users")
def activity_users(current: User = Depends(require_admin), db: Session = Depends(get_db),
                   limit: int = 200):
    """Per-registered-user scan log: each actor Warden has findings for, with counts,
    severity mix, the categories they trip, and last-seen — the 'who is doing what' view."""
    _RANK = {"benign": 0, "low": 1, "suspicious": 2, "high": 3, "critical": 4}
    rows = (db.query(Finding)
              .filter(Finding.tenant_id == current.tenant_id, Finding.sender != "")
              .order_by(Finding.created_at.desc()).limit(20000).all())
    users: dict[str, dict] = {}
    for r in rows:
        u = users.setdefault(r.sender, {
            "actor": r.sender, "findings": 0, "high": 0, "critical": 0, "max_risk": 0,
            "surfaces": set(), "categories": {}, "last_seen": ""})
        u["findings"] += 1
        if r.severity == "critical":
            u["critical"] += 1
        if r.severity in ("high", "critical"):
            u["high"] += 1
        u["max_risk"] = max(u["max_risk"], r.risk_score or 0)
        u["surfaces"].add(r.surface)
        for s in (r.signals or []):
            c = s.get("category")
            if c:
                u["categories"][c] = u["categories"].get(c, 0) + 1
        ls = r.created_at.isoformat() if r.created_at else ""
        if ls > u["last_seen"]:
            u["last_seen"] = ls
    out = []
    for u in users.values():
        top = sorted(u["categories"].items(), key=lambda kv: kv[1], reverse=True)[:4]
        out.append({**u, "surfaces": sorted(u["surfaces"]),
                    "categories": [{"category": k, "count": v} for k, v in top]})
    out.sort(key=lambda x: (x["critical"], x["high"], x["max_risk"], x["findings"]), reverse=True)
    return {"users": out[:min(limit, 1000)]}


@app.post("/api/discovery/ingest")
def discovery_ingest(body: DiscoveryIngest, current: User = Depends(require_admin),
                     db: Session = Depends(get_db)):
    """Classify AI usage from CASB / SWG / proxy / DNS logs into the discovery inventory.

    Each log line (actor + destination) is matched against Warden's AI-tool catalog; matches
    are attributed to the actor (and team, if present). No content is inspected here — this
    is how you discover shadow AI on devices the capture planes never touched."""
    from .discovery import ingest_logs
    return ingest_logs(db, current.tenant_id, body.events)


@app.get("/api/policies")
def policies_catalog(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """The detection-policy catalog for the tenant: every check, grouped, with its current
    enabled/disabled state and the available presets. Toggling is a PATCH /api/tenant with
    `disabled_checks`."""
    from .policies import catalog_for, parse_disabled
    tenant = db.get(Tenant, current.tenant_id)
    disabled = parse_disabled(getattr(tenant, "disabled_checks", "") if tenant else "")
    out = catalog_for(disabled)
    overrides = (db.query(PolicyOverride)
                   .filter(PolicyOverride.tenant_id == current.tenant_id)
                   .order_by(PolicyOverride.scope, PolicyOverride.match).all())
    out["overrides"] = [o.to_dict() for o in overrides]
    return out


@app.post("/api/policies/overrides")
def policy_override_upsert(body: PolicyOverrideIn, current: User = Depends(require_admin),
                           db: Session = Depends(get_db)):
    """Create or update a per-user (exact email) or per-group (glob) policy override. Its
    disabled-check set replaces the tenant default for matched actors."""
    from .policies import VALID_KEYS
    bad = [k for k in body.disabled_checks if k not in VALID_KEYS]
    if bad:
        raise HTTPException(status_code=400, detail=f"unknown policy check(s): {', '.join(bad[:5])}")
    match = body.match.strip().lower()   # matching is case-insensitive; store normalized
    if not match:
        raise HTTPException(status_code=400, detail="match is required")
    channel = body.channel.strip().lower()  # tool glob; "" = any tool
    disabled = ",".join(dict.fromkeys(k for k in body.disabled_checks if k in VALID_KEYS))
    row = (db.query(PolicyOverride)
             .filter(PolicyOverride.tenant_id == current.tenant_id,
                     PolicyOverride.scope == body.scope, PolicyOverride.match == match,
                     PolicyOverride.channel == channel)
             .one_or_none())
    if row is None:
        row = PolicyOverride(tenant_id=current.tenant_id, scope=body.scope, match=match,
                             channel=channel)
        db.add(row)
    row.label = body.label.strip()
    row.disabled_checks = disabled
    # Staged enforcement: tri-state → True/False/None (None = tenant default applies).
    row.enforce = {"on": True, "off": False}.get(body.enforce)
    db.commit(); db.refresh(row)
    from . import audit_log
    audit_log.record(db, current.tenant_id, current.email, "policy_override.upsert",
                     target=f"{body.scope}:{match}",
                     detail={"scope": body.scope, "match": match, "channel": channel,
                             "enforce": body.enforce,
                             "disabled_checks": body.disabled_checks})
    return row.to_dict()


@app.delete("/api/policies/overrides/{override_id}")
def policy_override_delete(override_id: int, current: User = Depends(require_admin),
                          db: Session = Depends(get_db)):
    row = (db.query(PolicyOverride)
             .filter(PolicyOverride.id == override_id,
                     PolicyOverride.tenant_id == current.tenant_id).one_or_none())
    if row is None:
        raise HTTPException(status_code=404, detail="override not found")
    scope, match, disabled = row.scope, row.match, row.disabled_checks
    db.delete(row); db.commit()
    from . import audit_log
    audit_log.record(db, current.tenant_id, current.email, "policy_override.delete",
                     target=f"{scope}:{match}", detail={"disabled_checks": disabled})
    return {"ok": True}


# --- Exception queue (block-screen requests → reviewed → optionally an override) --------


@app.get("/api/exceptions")
def exceptions_list(status: str = "pending", current: User = Depends(require_admin),
                    db: Session = Depends(get_db)):
    """The exception-request queue. `status=pending|approved|denied|all`."""
    from .models import ExceptionRecord
    q = db.query(ExceptionRecord).filter(ExceptionRecord.tenant_id == current.tenant_id)
    if status != "all":
        q = q.filter(ExceptionRecord.status == status)
    rows = q.order_by(ExceptionRecord.created_at.desc()).limit(200).all()
    return {"exceptions": [r.to_dict() for r in rows]}


@app.post("/api/exceptions/{req_id}/resolve")
def exception_resolve(req_id: int, body: ExceptionResolve,
                      current: User = Depends(require_admin),
                      db: Session = Depends(get_db)):
    """Approve or deny a queued exception request. Approving materializes a per-user
    policy override that disables the requested checks for that actor (optionally scoped
    to one tool) — the request stops being a suggestion box and becomes policy."""
    from datetime import datetime, timezone

    from . import audit_log
    from .models import ExceptionRecord
    from .policies import VALID_KEYS
    row = (db.query(ExceptionRecord)
             .filter(ExceptionRecord.id == req_id,
                     ExceptionRecord.tenant_id == current.tenant_id).one_or_none())
    if row is None:
        raise HTTPException(status_code=404, detail="exception request not found")
    if row.status != "pending":
        raise HTTPException(status_code=409, detail=f"already {row.status}")

    if body.action == "approve":
        checks = [k for k in (body.disable_checks or
                              [c for c in (row.categories or "").split(",") if c])
                  if k in VALID_KEYS]
        if not checks:
            raise HTTPException(status_code=400,
                                detail="nothing to approve: no valid checks requested — "
                                       "pass disable_checks explicitly")
        if not row.actor:
            raise HTTPException(status_code=400, detail="request has no actor to scope to")
        channel = body.channel.strip().lower()
        ov = (db.query(PolicyOverride)
                .filter(PolicyOverride.tenant_id == current.tenant_id,
                        PolicyOverride.scope == "user",
                        PolicyOverride.match == row.actor.lower(),
                        PolicyOverride.channel == channel).one_or_none())
        if ov is None:
            ov = PolicyOverride(tenant_id=current.tenant_id, scope="user",
                                match=row.actor.lower(), channel=channel,
                                label=f"exception #{row.id}")
            db.add(ov)
        merged = dict.fromkeys([c for c in (ov.disabled_checks or "").split(",") if c]
                               + checks)
        ov.disabled_checks = ",".join(merged)
        db.flush()
        row.applied_override_id = ov.id

    row.status = "approved" if body.action == "approve" else "denied"
    row.resolved_at = datetime.now(timezone.utc).replace(tzinfo=None)
    row.resolved_by = current.email
    row.resolution_note = body.note.strip()
    db.commit(); db.refresh(row)
    audit_log.record(db, current.tenant_id, current.email, f"exception.{row.status}",
                     target=row.actor,
                     detail={"request_id": row.id, "note": body.note[:200],
                             "override_id": row.applied_override_id})
    return row.to_dict()


@app.get("/api/policies/analytics")
def policies_analytics(days: int = 30, current: User = Depends(require_admin),
                       db: Session = Depends(get_db)):
    """Per-check activity over the window: how often each check fired, how often those
    findings were dismissed — the data an admin tunes policy from (a check with a high
    dismiss rate is a noise source; one with zero hits costs nothing to keep on)."""
    from datetime import datetime, timedelta, timezone
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=max(1, min(days, 365)))
    rows = (db.query(Finding.signals, Finding.status)
              .filter(Finding.tenant_id == current.tenant_id,
                      Finding.last_seen >= since)
              .limit(20000).all())
    stats: dict[str, dict] = {}
    for signals, status in rows:
        checks = {(s.get("check") or s.get("category") or "") for s in (signals or [])}
        for c in checks - {""}:
            st = stats.setdefault(c, {"check": c, "findings": 0, "dismissed": 0})
            st["findings"] += 1
            if status == "dismissed":
                st["dismissed"] += 1
    out = sorted(stats.values(), key=lambda s: -s["findings"])
    for st in out:
        st["dismiss_rate"] = round(st["dismissed"] / st["findings"], 3) if st["findings"] else 0.0
    return {"days": days, "checks": out}


# --- Fleet health (sensor heartbeats + dead-key visibility) ------------------------------


@app.get("/api/fleet")
def fleet_health(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Sensor-health ledger: who reported, from which plane, how recently — plus devices
    still presenting a revoked/expired key. This is what distinguishes "protected and
    quiet" from "silently dark" on a fail-open control."""
    from datetime import datetime, timedelta, timezone

    from .models import ApiKey, SensorHeartbeat
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rows = (db.query(SensorHeartbeat)
              .filter(SensorHeartbeat.tenant_id == current.tenant_id)
              .order_by(SensorHeartbeat.last_seen.desc()).limit(2000).all())

    def _bucket(last_seen) -> str:
        if last_seen is None:
            return "dark"
        age = now - last_seen
        if age <= timedelta(hours=24):
            return "fresh"
        if age <= timedelta(hours=72):
            return "stale"
        return "dark"

    sensors = []
    for r in rows:
        d = r.to_dict()
        d["health"] = _bucket(r.last_seen)
        sensors.append(d)
    dead_cutoff = now - timedelta(days=7)
    dead = (db.query(ApiKey)
              .filter(ApiKey.tenant_id == current.tenant_id,
                      ApiKey.active.is_(False),
                      ApiKey.last_failed_at.isnot(None),
                      ApiKey.last_failed_at >= dead_cutoff)
              .order_by(ApiKey.last_failed_at.desc()).limit(100).all())
    summary = {"actors": len({s["actor"] for s in sensors}),
               "fresh": sum(1 for s in sensors if s["health"] == "fresh"),
               "stale": sum(1 for s in sensors if s["health"] == "stale"),
               "dark": sum(1 for s in sensors if s["health"] == "dark"),
               "dead_keys": len(dead)}
    return {"summary": summary, "sensors": sensors,
            "dead_keys": [k.to_dict() for k in dead]}


# --- Exec summary report ------------------------------------------------------------------


@app.get("/api/reports/summary")
def report_summary(days: int = 30, current: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    """The numbers a security lead forwards upward: window totals, what was prevented,
    where it came from, who's covered. Printable from the console's Report page."""
    from datetime import datetime, timedelta, timezone

    from .detectors.shadow_ai import confirmed_leak
    from .models import GatewayUsage, SensorHeartbeat
    days = max(1, min(days, 365))
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    since = now - timedelta(days=days)

    rows = (db.query(Finding.severity, Finding.status, Finding.signals,
                     Finding.channel, Finding.sender, Finding.recommended_action)
              .filter(Finding.tenant_id == current.tenant_id,
                      Finding.last_seen >= since)
              .limit(20000).all())
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_tool: dict[str, int] = {}
    actors: set[str] = set()
    prevented = 0
    for severity, status, signals, channel, sender, action in rows:
        by_severity[severity] = by_severity.get(severity, 0) + 1
        for c in {(s.get("category") or "") for s in (signals or [])} - {""}:
            by_category[c] = by_category.get(c, 0) + 1
        if channel:
            by_tool[channel] = by_tool.get(channel, 0) + 1
        if sender:
            actors.add(sender)
        # "Prevented" mirrors what clients actually hard-block: a block-band verdict, or
        # a confirmed secret/PII leak (force_block even in monitor mode).
        if action == "block" or confirmed_leak(signals or []):
            prevented += 1

    hb = (db.query(SensorHeartbeat)
            .filter(SensorHeartbeat.tenant_id == current.tenant_id).all())
    covered = {h.actor for h in hb if h.actor and h.last_seen and h.last_seen >= since}
    analyzed = (db.query(func.coalesce(func.sum(GatewayUsage.count), 0))
                  .filter(GatewayUsage.tenant_id == current.tenant_id,
                          GatewayUsage.window_start >= since).scalar() or 0)
    return {"days": days, "generated_at": now.isoformat(),
            "analyzed_events": int(analyzed),
            "findings": len(rows), "prevented_blocks": prevented,
            "by_severity": by_severity,
            "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
            "by_tool": dict(sorted(by_tool.items(), key=lambda kv: -kv[1])[:15]),
            "actors_with_findings": len(actors),
            "covered_actors": len(covered)}


# --- Protection simulator (nothing persisted) --------------------------------------------


@app.post("/api/simulate")
def simulate(body: SimulateIn, current: User = Depends(require_admin),
             db: Session = Depends(get_db)):
    """'Test my protection': run content through the real scoring pipeline — same
    detectors, same tenant policy/overrides — without persisting anything, and report
    the verdict a client would enforce on each posture (monitor vs enforce)."""
    from .detectors.shadow_ai import confirmed_leak
    from .policies import parse_disabled, resolve_disabled, resolve_enforce

    plane_tool = {"prompt": "claude-code", "tool": "claude-code",
                  "desktop": "claude-desktop", "browser": "claude.ai"}
    tool = body.tool or plane_tool[body.plane]
    actor = body.actor.strip().lower()
    destination = body.destination or ("api.anthropic.com" if body.plane == "desktop"
                                       else "claude.ai" if body.plane == "browser" else tool)

    meta = {"destination": destination,
            "sanctioned_tools": _tenant_or_global(current.tenant_id, db,
                                                  "sanctioned_ai_tools",
                                                  settings.sanctioned_ai_tools),
            "custom_pii": _tenant_or_global(current.tenant_id, db, "custom_pii_patterns", "")}
    if body.plane == "tool":
        item = AnalysisInput(content=body.content, sender=actor, channel=tool,
                             subject="MCP tools/call", surface=Surface.MCP,
                             metadata={"method": "tools/call", "tool": tool,
                                       "args_text": body.content, "transport": "stdio",
                                       "allowed_servers": _tenant_mcp_allow(current.tenant_id, db)})
    else:
        item = AnalysisInput(content=body.content, sender=actor, channel=tool,
                             surface=Surface.AI_USAGE, metadata=meta)
    from .policy import detect_tool, signal_filter_for
    suppress = _tenant_or_global(current.tenant_id, db, "tool_suppress",
                                 settings.gateway_tool_suppress)
    sig_filter = signal_filter_for(detect_tool(explicit=tool), extra=suppress)
    result = run_analysis(item, persist=False, db=db, tenant_id=current.tenant_id,
                          signal_filter=sig_filter)

    tenant = db.get(Tenant, current.tenant_id)
    overrides = (db.query(PolicyOverride)
                   .filter(PolicyOverride.tenant_id == current.tenant_id).all())
    _, matched_checks = resolve_disabled(
        parse_disabled(getattr(tenant, "disabled_checks", "") if tenant else ""),
        actor, overrides, channel=tool)
    base_enforce = _tenant_client_enforce(current.tenant_id, db)
    effective_enforce, matched_enforce = resolve_enforce(base_enforce, actor, overrides,
                                                         channel=tool)

    if body.plane == "tool":
        action = _action_for(result["severity"],
                             _tenant_mcp_block_severity(current.tenant_id, db))
        force = False   # the mcp surface emits no force_block
    else:
        action = _action_for(result["severity"])
        force = settings.gateway_enforce_secrets and confirmed_leak(result["signals"])

    def _outcome(enforce: bool) -> str:
        if force:
            return "block"
        if action == "block":
            return "block" if enforce else "warn"
        return action

    # Monitor-mode tool calls are reported asynchronously (fire-and-forget) — the hook
    # never blocks or warns interactively there, it only records.
    outcome_monitor = "log" if body.plane == "tool" else _outcome(False)
    return {"action": action, "force_block": force,
            "risk_score": result["risk_score"], "severity": result["severity"],
            "signals": result["signals"],
            "remediation": remediation_for(result["signals"]),
            "enforce_stance": effective_enforce,
            "matched_override": matched_enforce or matched_checks,
            "outcome_monitor": outcome_monitor,
            "outcome_enforce": _outcome(True)}


@app.get("/api/discovery/inventory")
def discovery_inventory(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """The shadow-AI inventory: every AI tool observed, by tool and by team/department, each
    marked sanctioned/unsanctioned against the tenant's live allowlist — plus the actual
    sensitive-data exposure the capture planes saw per tool."""
    from .discovery import build_inventory
    sanctioned = _tenant_or_global(current.tenant_id, db, "sanctioned_ai_tools",
                                   settings.sanctioned_ai_tools)
    return build_inventory(db, current.tenant_id, sanctioned)


@app.get("/api/usage")
def usage(current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Gateway usage for this tenant: current-minute count, last-24h total, per-day totals,
    and the effective per-minute limit (metering + quota visibility)."""
    from .metering import usage_summary
    return usage_summary(db, current.tenant_id)


@app.post("/api/provision")
def provision(body: ProvisionRequest, current: User = Depends(require_admin),
              db: Session = Depends(get_db)):
    """Mint a reusable enrollment token and return prefilled device-setup script(s).

    One artifact per OS, runnable on the whole fleet: at runtime each machine self-enrolls
    (POST /api/enroll) for its own per-device key, then configures Claude Code + the browser
    extension policy (+ optional desktop proxy). Per-device keys mean per-device attribution
    and independent revocation — no shared credential baked in."""
    from datetime import datetime, timedelta, timezone

    from . import provision as prov
    from .plans import require_feature
    # Self-serve device installers are free (device_setup) so any org can seamlessly
    # onboard its fleet; the MDM policy pack (/api/policy-pack) stays gated on "mdm".
    require_feature(db.get(Tenant, current.tenant_id), "device_setup")
    from .models import EnrollmentToken
    from .security import generate_enrollment_token

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    # Fleet token lives in a distributable file, so bound its lifetime by default.
    expires_at = now + timedelta(days=body.expires_in_days) if body.expires_in_days else None
    token, prefix, token_hash = generate_enrollment_token()
    et = EnrollmentToken(tenant_id=current.tenant_id, label=body.label, prefix=prefix,
                         token_hash=token_hash, max_uses=body.max_uses,
                         expires_at=expires_at, created_at=now)
    db.add(et)
    db.commit()

    ext_id = body.extension_id or settings.extension_id   # default to the configured published id
    platforms = ["macos", "windows"] if body.platform == "both" else [body.platform]
    scripts = {p: prov.render(p, body.base_url, token, ext_id, body.proxy_host,
                              body.route_gateway)
               for p in platforms}
    expiry_note = (f" Expires in {body.expires_in_days} day(s)." if body.expires_in_days
                   else " Does not expire.")
    return {"enroll_token_prefix": prefix, "scripts": scripts,
            "expires_at": expires_at.isoformat() + "Z" if expires_at else None,
            "note": "Contains a reusable enrollment token; each device self-enrolls for its "
                    "own key. Distribute over a trusted channel; revoke via "
                    "/api/enroll/tokens." + expiry_note}


@app.get("/api/stats")
def stats(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scoped = db.query(Finding).filter(Finding.tenant_id == current.tenant_id)

    def _count(q):
        return q.with_entities(func.count(Finding.id)).scalar() or 0

    total = _count(scoped)
    by_severity = dict(
        scoped.with_entities(Finding.severity, func.count(Finding.id))
        .group_by(Finding.severity).all()
    )
    by_surface = dict(
        scoped.with_entities(Finding.surface, func.count(Finding.id))
        .group_by(Finding.surface).all()
    )
    open_count = _count(scoped.filter(Finding.status == "open"))
    ai_attacks = _count(scoped.filter(Finding.ai_generated.is_(True), Finding.attack_intent.is_(True)))
    high_risk = _count(scoped.filter(Finding.severity.in_(["high", "critical"])))
    # True traffic volume (gateway + sensor/ingest requests metered per minute). Findings
    # no longer track it since benign captures aren't persisted; floor at the findings
    # count for tenants whose only traffic is unmetered manual /api/analyze submissions.
    from .models import GatewayUsage
    metered = (db.query(func.coalesce(func.sum(GatewayUsage.count), 0))
               .filter(GatewayUsage.tenant_id == current.tenant_id).scalar() or 0)
    return {
        "total": total,
        "analyzed_total": max(int(metered), total),
        "open": open_count,
        "high_risk": high_risk,
        "ai_weaponized": ai_attacks,
        "by_severity": by_severity,
        "by_surface": by_surface,
        "judge_enabled": engine.judge_enabled,
    }


# --- Single-origin SPA serving (Cloud Run / any single-container deploy) --------------
# When WARDEN_STATIC_DIR points at a built frontend (dist), serve it from this same app so
# the SPA + API share one origin (no nginx). No-op in dev/tests (var unset). Registered
# last so it never shadows the API routers/routes above.
import os as _os  # noqa: E402


def _safe_static_file(root: str, full_path: str) -> str | None:
    """Resolve `full_path` under the static `root`, returning the file path only if it stays
    inside root and exists. Guards path traversal (e.g. percent-encoded ../../etc/passwd),
    which would otherwise be an unauthenticated arbitrary file read via the SPA catch-all."""
    if not full_path:
        return None
    cand = _os.path.realpath(_os.path.join(root, full_path))
    inside = cand == root or cand.startswith(root + _os.sep)
    return cand if (inside and _os.path.isfile(cand)) else None


_STATIC_DIR = _os.getenv("WARDEN_STATIC_DIR", "")
if _STATIC_DIR and _os.path.isdir(_STATIC_DIR):
    from fastapi.responses import FileResponse  # noqa: E402
    from fastapi.staticfiles import StaticFiles  # noqa: E402

    _assets = _os.path.join(_STATIC_DIR, "assets")
    if _os.path.isdir(_assets):
        app.mount("/assets", StaticFiles(directory=_assets), name="assets")

    _API_PREFIXES = ("api/", "v1/", "v1beta/", "livez", "readyz", "metrics", "assets/")

    _STATIC_ROOT = _os.path.realpath(_STATIC_DIR)

    @app.get("/{full_path:path}")
    def _spa(full_path: str):
        # Let API/probe paths 404 through the app instead of returning index.html.
        if full_path.startswith(_API_PREFIXES):
            raise HTTPException(status_code=404, detail="not found")
        cand = _safe_static_file(_STATIC_ROOT, full_path)
        if cand is not None:
            return FileResponse(cand)                    # real file (logo, favicon, …)
        return FileResponse(_os.path.join(_STATIC_ROOT, "index.html"))  # SPA routes
