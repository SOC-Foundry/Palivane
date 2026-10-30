"""Tenant lifecycle: suspension gate + the full data-deletion cascade.

Suspension (`tenants.status = "suspended"`) is an operator action (CLI) that cuts a
tenant off everywhere traffic or logins enter — console sessions, password/SSO login,
capture ingest, and the LLM gateway — without deleting anything. Resume flips it back.

The purge cascade lives here (not in the API layer) so both the GDPR delete-org endpoint
and the operator CLI (`purge-empty` for abandoned signups) share one definition of
"every table that holds tenant data" — a partial delete isn't a delete.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from .models import (
    Agent, AgentRole, AllowEntry, ApiKey, AuditLog, BrowserExtension, ContentFingerprint,
    CorpusSample, DiscoveredUsage, EnrollmentToken, ExceptionRecord, Finding, GatewayUsage,
    InferenceHookDenial, JoinRequest,
    OAuthCode, OAuthToken, PolicyOverride, SaasConnector, SensorHeartbeat, Tenant,
    TenantDomain, TenantOIDC, TenantSAML, TenantUpstream, UpgradeRequest, User,
    UsedSamlAssertion,
)

SUSPENDED_DETAIL = "this organization is suspended — contact your Palivane operator"


def ensure_active(db: Session, tenant_id: int | None) -> None:
    """403 when the tenant is suspended. Called on every authenticated entry path;
    one PK lookup, so cheap enough to sit in the hot path."""
    if tenant_id is None:
        return
    tenant = db.get(Tenant, tenant_id)
    if tenant is not None and tenant.status == "suspended":
        from fastapi import HTTPException  # noqa: PLC0415
        raise HTTPException(status_code=403, detail=SUSPENDED_DETAIL)


# Every model with a tenant_id column, children before parents: api_keys and the OAuth
# code/token rows FK users.id, so they go before users (Postgres enforces it). The
# coverage test asserts this list matches the models, so a new tenant table can't be
# forgotten here.
TENANT_TABLES = (
    ("findings", Finding),
    ("api_keys", ApiKey),
    ("oauth_codes", OAuthCode),
    ("oauth_tokens", OAuthToken),
    ("users", User),
    ("enrollment_tokens", EnrollmentToken),
    ("upstreams", TenantUpstream),
    ("audit_log", AuditLog),
    ("usage", GatewayUsage),
    ("oidc", TenantOIDC),
    ("saml", TenantSAML),
    ("used_saml_assertions", UsedSamlAssertion),
    ("discovered_usage", DiscoveredUsage),
    ("browser_extensions", BrowserExtension),
    ("agents", Agent),
    ("agent_roles", AgentRole),
    ("policy_overrides", PolicyOverride),
    ("allow_entries", AllowEntry),
    ("exceptions", ExceptionRecord),
    ("saas_connectors", SaasConnector),
    ("content_fingerprints", ContentFingerprint),
    ("corpus_samples", CorpusSample),
    ("sensor_heartbeats", SensorHeartbeat),
    ("inference_hook_denials", InferenceHookDenial),
    ("upgrade_requests", UpgradeRequest),
    # Domain capture: freeing the claim matters — a verified domain held by a dead
    # tenant would otherwise block that company from ever signing up again.
    ("domains", TenantDomain),
    ("join_requests", JoinRequest),
)


def purge_tenant(db: Session, tenant: Tenant) -> dict:
    """Delete the tenant and ALL its rows. Returns per-table delete counts.
    Commits. Irreversible — callers own the confirmation UX."""
    tid = tenant.id
    counts = {key: db.query(model).filter(model.tenant_id == tid).delete()
              for key, model in TENANT_TABLES}
    db.delete(tenant)
    db.commit()
    return counts


def purgeable_empty_tenants(db: Session, older_than_days: int) -> list[Tenant]:
    """Abandoned-signup candidates: created > N days ago with no findings, no API keys,
    and at most one user (the signup admin who never came back). Conservative on purpose."""
    from datetime import datetime, timedelta, timezone  # noqa: PLC0415
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=older_than_days)
    out = []
    for t in db.query(Tenant).filter(Tenant.created_at < cutoff).all():
        if db.query(Finding).filter(Finding.tenant_id == t.id).limit(1).count():
            continue
        if db.query(ApiKey).filter(ApiKey.tenant_id == t.id).limit(1).count():
            continue
        if db.query(User).filter(User.tenant_id == t.id).count() > 1:
            continue
        out.append(t)
    return out


def purge_expired_findings(db: Session, tenant: Tenant, now=None) -> int:
    """Delete `tenant`'s findings older than its retention_days (0 = keep forever); commits.
    Returns the number deleted."""
    from datetime import datetime, timedelta, timezone
    days = tenant.retention_days or 0
    if days <= 0:
        return 0
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    n = (db.query(Finding)
           .filter(Finding.tenant_id == tenant.id, Finding.created_at < now - timedelta(days=days))
           .delete(synchronize_session=False))
    db.commit()
    return n


def apply_retention(db: Session, now=None) -> int:
    """Enforce every org's findings retention; run ~hourly by the background loop. Settings
    and the Trust page promise it, and until this ran only an admin's manual purge applied
    it. One org's failure doesn't stop the rest. Returns the total deleted."""
    import logging

    from . import audit_log
    total = 0
    for t in db.query(Tenant).filter(Tenant.retention_days > 0).all():
        try:
            n = purge_expired_findings(db, t, now)
        except Exception:                                          # noqa: BLE001
            db.rollback()
            logging.getLogger("palivane.retention").warning(
                "retention for %s failed", t.slug, exc_info=True)
            continue
        if n:
            audit_log.record(db, t.id, "system", "findings.retention",
                             detail={"deleted": n, "retention_days": t.retention_days})
        total += n
    return total
