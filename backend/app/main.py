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
from .config import settings
from .gateway import gemini_router, router as gateway_router
from .database import Base, engine as db_engine, get_db
from .detectors import AnalysisInput, Surface
from .engine import engine
from .models import Finding, Tenant, User
from .schemas import (
    AIUsageIngest,
    AnalyzeRequest,
    BatchAnalyzeRequest,
    CodeScanRequest,
    CoverageRequest,
    IDEExtScan,
    MCPBatchIngest,
    MCPConfigScan,
    MCPIngest,
    ProvisionRequest,
    ScannerImport,
    SecretAtRest,
    SecretScan,
    StatusUpdate,
)
from .security import using_insecure_key
from .service import run_analysis

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
    if using_insecure_key():
        if prod:
            # Refuse to boot with a forgeable JWT key on a production-shaped deployment.
            raise RuntimeError(
                "WARDEN_SECRET_KEY is unset. On a non-SQLite (production) deployment this "
                "means JWTs are signed with a public dev key and anyone can forge an admin "
                "session. Set WARDEN_SECRET_KEY to a strong random value and restart.")
        log.warning("WARDEN_SECRET_KEY is unset — using an insecure dev key (SQLite dev only).")
    elif settings.auth_secret_key in _WEAK_SECRET_KEYS:
        # Warn (don't fail): the local Docker stack uses a well-known dev key on Postgres.
        log.warning("WARDEN_SECRET_KEY is a well-known weak value — set a strong random "
                    "key before production.")
    yield


app = FastAPI(
    title="Warden — AI Security Gateway",
    description="Detects attacks on your LLMs and stops sensitive data leaking to AI tools.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
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
    return {
        "status": "ok",
        "judge_enabled": engine.judge_enabled,
        "judge_model": engine.judge.model if engine.judge_enabled else None,
        "judge_provider": engine.judge.provider if engine.judge_enabled else None,
        "allow_signup": settings.allow_signup,
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
    return {
        "planes": {
            "gateway": by_surface.get("llm_io", 0),      # first-party LLM (gateway)
            "shadow_ai": by_surface.get("ai_usage", 0),  # extension / proxy
            "mcp": by_surface.get("mcp", 0),             # agentic tool-use
            "secrets": by_surface.get("secrets", 0),     # credentials at rest (warden-secrets)
        },
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
    from .metering import record_and_check
    allowed, _count, limit = record_and_check(db, tenant_id, kind="ingest")
    if not allowed:
        raise HTTPException(status_code=429, detail=f"ingest rate limit exceeded ({limit}/min)",
                            headers={"Retry-After": "60"})


def _ingest_auth(x_warden_token: str, db: Session) -> tuple[int | None, str]:
    """Resolve (tenant_id, default_actor) from a per-tenant API key (`ak_…`) or the
    shared EXTENSION_INGEST_TOKEN. Used by the token-gated ingest & scan endpoints, which
    are deployed via policy/CI and so authenticate with a capture token, not a user JWT."""
    from .security import looks_like_api_key

    if looks_like_api_key(x_warden_token):
        from .gateway import _resolve_api_key
        principal = _resolve_api_key(x_warden_token, db)   # 401s on bad/expired key
        return principal.tenant_id, principal.actor
    token = settings.extension_ingest_token
    if not token or not hmac.compare_digest(x_warden_token, token):
        raise HTTPException(status_code=401, detail="invalid or missing ingest token")
    return _ingest_tenant_id(db), ""


@app.post("/api/ingest/ai-usage")
def ingest_ai_usage(
    body: AIUsageIngest,
    x_warden_token: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Score content a browser extension / proxy captured on its way to an AI tool.

    Authenticated by a per-tenant API key (`ak_…`, minted in the console) or the shared
    static EXTENSION_INGEST_TOKEN — not a user JWT — so it can be deployed via policy.
    Returns an action the client enforces: allow / warn / block."""
    tenant_id, default_actor = _ingest_auth(x_warden_token, db)
    _enforce_rate(db, tenant_id)
    actor = body.user or default_actor

    meta: dict = {"destination": body.destination} if body.destination else {}
    meta["sanctioned_tools"] = _tenant_or_global(
        tenant_id, db, "sanctioned_ai_tools", settings.sanctioned_ai_tools)
    item = AnalysisInput(
        content=body.content, sender=actor, channel=body.tool or "ai_tool",
        surface=Surface.AI_USAGE, metadata=meta,
    )
    from .policy import detect_tool, signal_filter_for
    suppress = _tenant_or_global(tenant_id, db, "tool_suppress", settings.gateway_tool_suppress)
    sig_filter = signal_filter_for(detect_tool(explicit=body.tool), extra=suppress)
    result = run_analysis(item, persist=True, db=db, tenant_id=tenant_id, signal_filter=sig_filter)
    return {
        "action": _action_for(result["severity"]),
        "risk_score": result["risk_score"],
        "severity": result["severity"],
        "signals": result["signals"],
        "finding_id": result["finding_id"],
    }


# An agent reading code is normal, and MCP has no external AI destination — so on the
# mcp surface drop source_code_leak / unsanctioned_ai and keep the agentic-action +
# secret/PII signals.
_MCP_DROP = {"source_code_leak", "unsanctioned_ai"}


def _mcp_filter(signals: list) -> list:
    return [s for s in signals if s.category.value not in _MCP_DROP]


def _tenant_or_global(tenant_id: int | None, db: Session, attr: str, global_value: str) -> str:
    """A tenant's own list for `attr` if set, else the global env default."""
    if tenant_id is not None:
        t = db.get(Tenant, tenant_id)
        if t and (getattr(t, attr, "") or "").strip():
            return getattr(t, attr).strip()
    return global_value


def _tenant_mcp_allow(tenant_id: int | None, db: Session) -> str:
    """Effective MCP server allowlist for a tenant: its own list, else the global default."""
    return _tenant_or_global(tenant_id, db, "mcp_allowed_servers", settings.mcp_allowed_servers)


def _tenant_mcp_block_severity(tenant_id: int | None, db: Session) -> str:
    """Effective block threshold for capture-plane MCP verdicts (tenant, else global)."""
    return _tenant_or_global(tenant_id, db, "mcp_block_severity",
                             settings.mcp_block_severity) or "high"


def _score_mcp(body: MCPIngest, tenant_id: int | None, default_actor: str,
               allowed_servers: str, block_severity: str, db: Session) -> dict:
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
        },
    )
    result = run_analysis(item, persist=True, db=db, tenant_id=tenant_id,
                          signal_filter=_mcp_filter,
                          persist_benign=settings.mcp_persist_benign)
    return {
        "action": _action_for(result["severity"], block_severity),
        "risk_score": result["risk_score"],
        "severity": result["severity"],
        "signals": result["signals"],
        "finding_id": result["finding_id"],
    }


@app.post("/api/ingest/mcp")
def ingest_mcp(
    body: MCPIngest,
    x_warden_token: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Score an MCP JSON-RPC activity a capture client (proxy, warden-hook, warden-mcp)
    saw (agentic tool-use). Token-gated; returns an action the client enforces on the
    `mcp` surface: allow/warn/block. Benign verdicts aren't persisted by default."""
    tenant_id, default_actor = _ingest_auth(x_warden_token, db)
    _enforce_rate(db, tenant_id)
    return _score_mcp(body, tenant_id, default_actor, _tenant_mcp_allow(tenant_id, db),
                      _tenant_mcp_block_severity(tenant_id, db), db)


@app.post("/api/ingest/mcp/batch")
def ingest_mcp_batch(
    body: MCPBatchIngest,
    x_warden_token: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Score many MCP activities in one request — for long-lived capture clients
    (warden-mcp) that would otherwise post per tool call. Counts as a single ingest
    request against the tenant's sensor quota. Returns per-item verdicts, index-aligned."""
    tenant_id, default_actor = _ingest_auth(x_warden_token, db)
    _enforce_rate(db, tenant_id)
    allowed = _tenant_mcp_allow(tenant_id, db)
    block = _tenant_mcp_block_severity(tenant_id, db)
    results = [_score_mcp(item, tenant_id, default_actor, allowed, block, db)
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
    tenant_id, _ = _ingest_auth(x_warden_token, db)
    _enforce_rate(db, tenant_id)

    flagged: list[dict] = []
    worst = 0
    allowed = _tenant_mcp_allow(tenant_id, db)
    block_sev = _tenant_mcp_block_severity(tenant_id, db)
    servers = _parse_mcp_servers(body.content)
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
        action = _action_for(result["severity"], block_sev)
        worst = max(worst, _ACTION_RANK.get(result["severity"], 0))
        if action != "allow":
            flagged.append({"name": name, "transport": transport, "action": action,
                            "severity": result["severity"], "risk_score": result["risk_score"],
                            "signals": result["signals"]})

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
    tenant_id, _ = _ingest_auth(x_warden_token, db)
    _enforce_rate(db, tenant_id)
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
    secrets_engine: str = "trufflehog",
    current: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Generate the MDM policy pack (agentless enforcement config): VS Code extension
    allowlist, system-proxy profiles, browser force-install, a CA-deployment note, and
    the Claude Code managed-settings.json (gateway routing + local-plane hooks).

    Applied by the org's MDM (Jamf/Intune/GPO) — no Warden agent on the device. The
    extension allow/deny lists use this tenant's IDE-vetting config, else the global."""
    from . import policy_pack as pp
    allowed_raw = _tenant_or_global(current.tenant_id, db, "ide_ext_allowed", settings.ide_ext_allowed)
    denied_raw = _tenant_or_global(current.tenant_id, db, "ide_ext_denylist", settings.ide_ext_denylist)
    allowed = [x.strip() for x in allowed_raw.split(",") if x.strip()]
    denied = [x.strip() for x in denied_raw.split(",") if x.strip()]
    artifacts = pp.render_pack(base_url=base_url, extension_id=settings.extension_id,
                               proxy_host=proxy_host, proxy_port=proxy_port,
                               allowed_exts=allowed, denied_exts=denied,
                               hook_path=hook_path, posture_path=posture_path,
                               secrets_engine=secrets_engine)
    return {"artifacts": artifacts}


@app.get("/api/findings")
def list_findings(
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    severity: str | None = None,
    status: str | None = None,
    surface: str | None = None,
    limit: int = 100,
):
    q = db.query(Finding).filter(Finding.tenant_id == current.tenant_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    if status:
        q = q.filter(Finding.status == status)
    if surface:
        q = q.filter(Finding.surface == surface)
    rows = q.order_by(Finding.created_at.desc()).limit(min(limit, 500)).all()
    return {"findings": [r.to_summary() for r in rows]}


@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: int, current: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    row = db.get(Finding, finding_id)
    if not row or row.tenant_id != current.tenant_id:
        raise HTTPException(status_code=404, detail="finding not found")
    return row.to_detail()


@app.patch("/api/findings/{finding_id}")
def update_status(finding_id: int, body: StatusUpdate,
                  current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    row = db.get(Finding, finding_id)
    if not row or row.tenant_id != current.tenant_id:
        raise HTTPException(status_code=404, detail="finding not found")
    row.status = body.status
    db.commit()
    return {"id": finding_id, "status": row.status}


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
    from datetime import datetime, timezone

    from . import provision as prov
    from .models import EnrollmentToken
    from .security import generate_enrollment_token

    token, prefix, token_hash = generate_enrollment_token()
    et = EnrollmentToken(tenant_id=current.tenant_id, label=body.label, prefix=prefix,
                         token_hash=token_hash,
                         created_at=datetime.now(timezone.utc).replace(tzinfo=None))
    db.add(et)
    db.commit()

    ext_id = body.extension_id or settings.extension_id   # default to the configured published id
    platforms = ["macos", "windows"] if body.platform == "both" else [body.platform]
    scripts = {p: prov.render(p, body.base_url, token, ext_id, body.proxy_host)
               for p in platforms}
    return {"enroll_token_prefix": prefix, "scripts": scripts,
            "note": "Contains a reusable enrollment token; each device self-enrolls for its "
                    "own key. Distribute over a trusted channel; revoke via /api/enroll/tokens."}


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
    return {
        "total": total,
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

_STATIC_DIR = _os.getenv("WARDEN_STATIC_DIR", "")
if _STATIC_DIR and _os.path.isdir(_STATIC_DIR):
    from fastapi.responses import FileResponse  # noqa: E402
    from fastapi.staticfiles import StaticFiles  # noqa: E402

    _assets = _os.path.join(_STATIC_DIR, "assets")
    if _os.path.isdir(_assets):
        app.mount("/assets", StaticFiles(directory=_assets), name="assets")

    _API_PREFIXES = ("api/", "v1/", "v1beta/", "livez", "readyz", "metrics", "assets/")

    @app.get("/{full_path:path}")
    def _spa(full_path: str):
        # Let API/probe paths 404 through the app instead of returning index.html.
        if full_path.startswith(_API_PREFIXES):
            raise HTTPException(status_code=404, detail="not found")
        candidate = _os.path.join(_STATIC_DIR, full_path)
        if full_path and _os.path.isfile(candidate):
            return FileResponse(candidate)               # real file (logo, favicon, …)
        return FileResponse(_os.path.join(_STATIC_DIR, "index.html"))  # SPA routes
