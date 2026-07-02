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
    StatusUpdate,
)
from .security import using_insecure_key
from .service import run_analysis

# SQLite (local dev) auto-creates its schema; Postgres is managed by Alembic
# migrations (run via the container entrypoint / `alembic upgrade head`).
if settings.database_url.startswith("sqlite"):
    Base.metadata.create_all(bind=db_engine)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if using_insecure_key():
        import logging
        logging.getLogger("uvicorn.error").warning(
            "WARDEN_SECRET_KEY is unset — using an insecure dev key. "
            "Set it before any real deployment."
        )
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
        "judge_model": settings.judge_model if engine.judge_enabled else None,
        "allow_signup": settings.allow_signup,
    }


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


def _action_for(severity: str) -> str:
    rank = _ACTION_RANK.get(severity, 0)
    return "block" if rank >= 3 else ("warn" if rank >= 2 else "allow")


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
    actor = body.user or default_actor

    item = AnalysisInput(
        content=body.content, sender=actor, channel=body.tool or "ai_tool",
        surface=Surface.AI_USAGE,
        metadata={"destination": body.destination} if body.destination else {},
    )
    from .policy import detect_tool, signal_filter_for
    sig_filter = signal_filter_for(detect_tool(explicit=body.tool))
    result = run_analysis(item, persist=True, db=db, tenant_id=tenant_id, signal_filter=sig_filter)
    return {
        "action": _action_for(result["severity"]),
        "risk_score": result["risk_score"],
        "severity": result["severity"],
        "signals": result["signals"],
        "finding_id": result["finding_id"],
    }


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


@app.get("/api/findings")
def list_findings(
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    severity: str | None = None,
    status: str | None = None,
    limit: int = 100,
):
    q = db.query(Finding).filter(Finding.tenant_id == current.tenant_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    if status:
        q = q.filter(Finding.status == status)
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
