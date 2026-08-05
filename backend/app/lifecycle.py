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
    Agent, AgentRole, ApiKey, AuditLog, DiscoveredUsage, EnrollmentToken, Finding,
    GatewayUsage, JoinRequest, PolicyOverride, Tenant, TenantDomain, TenantOIDC,
    TenantSAML, TenantUpstream, User,
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


def purge_tenant(db: Session, tenant: Tenant) -> dict:
    """Delete the tenant and ALL its rows. Returns per-table delete counts.
    Commits. Irreversible — callers own the confirmation UX."""
    tid = tenant.id
    counts = {
        "findings": db.query(Finding).filter(Finding.tenant_id == tid).delete(),
        "users": db.query(User).filter(User.tenant_id == tid).delete(),
        "api_keys": db.query(ApiKey).filter(ApiKey.tenant_id == tid).delete(),
        "enrollment_tokens": db.query(EnrollmentToken).filter(EnrollmentToken.tenant_id == tid).delete(),
        "upstreams": db.query(TenantUpstream).filter(TenantUpstream.tenant_id == tid).delete(),
        "audit_log": db.query(AuditLog).filter(AuditLog.tenant_id == tid).delete(),
        "usage": db.query(GatewayUsage).filter(GatewayUsage.tenant_id == tid).delete(),
        "oidc": db.query(TenantOIDC).filter(TenantOIDC.tenant_id == tid).delete(),
        "saml": db.query(TenantSAML).filter(TenantSAML.tenant_id == tid).delete(),
        "discovered_usage": db.query(DiscoveredUsage).filter(DiscoveredUsage.tenant_id == tid).delete(),
        "agents": db.query(Agent).filter(Agent.tenant_id == tid).delete(),
        "agent_roles": db.query(AgentRole).filter(AgentRole.tenant_id == tid).delete(),
        "policy_overrides": db.query(PolicyOverride).filter(PolicyOverride.tenant_id == tid).delete(),
        # Domain capture: freeing the claim matters — a verified domain held by a dead
        # tenant would otherwise block that company from ever signing up again.
        "domains": db.query(TenantDomain).filter(TenantDomain.tenant_id == tid).delete(),
        "join_requests": db.query(JoinRequest).filter(JoinRequest.tenant_id == tid).delete(),
    }
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
