"""Self-serve per-tenant data export — the whole footprint of one org in one JSON doc.

For enterprise security reviews and data-subject / portability requests. Assembled from
the models' own safe serializers, so **secrets never leave** (password hashes, API-key /
enrollment-token hashes, MFA secrets, encrypted provider keys, SSO client secrets are all
excluded). Finding content is included only when `include_content=True` (admin-authorized,
decrypted on the way out); otherwise summaries only.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from . import audit_log
from .config import settings
from .models import (
    ApiKey, EnrollmentToken, Finding, TenantOIDC, TenantSAML, TenantUpstream, User,
)

_FINDINGS_CAP = 50000
_AUDIT_CAP = 5000


def _upstreams(db: Session, tid: int) -> list[dict]:
    rows = db.query(TenantUpstream).filter(TenantUpstream.tenant_id == tid).all()
    # Report presence of a key, never the encrypted key itself.
    return [{"provider": r.provider, "base_url": r.base_url or "",
             "has_key": bool(r.key_encrypted)} for r in rows]


def _sso(db: Session, tid: int) -> dict:
    oidc = db.query(TenantOIDC).filter(TenantOIDC.tenant_id == tid).first()
    saml = db.query(TenantSAML).filter(TenantSAML.tenant_id == tid).first()
    out: dict = {}
    if oidc is not None:
        out["oidc"] = {"issuer": oidc.issuer, "client_id": oidc.client_id,
                       "enabled": oidc.enabled, "auto_provision": oidc.auto_provision,
                       "allowed_domain": oidc.allowed_domain}  # client_secret excluded
    if saml is not None:
        out["saml"] = {"idp_entity_id": saml.idp_entity_id, "idp_sso_url": saml.idp_sso_url,
                       "enabled": saml.enabled, "auto_provision": saml.auto_provision,
                       "allowed_domain": saml.allowed_domain}  # idp cert excluded
    return out


def build_tenant_export(db: Session, tenant, include_content: bool = False,
                        limit: int = _FINDINGS_CAP) -> dict:
    """Assemble the complete export document for `tenant` (a Tenant instance)."""
    tid = tenant.id
    limit = max(1, min(limit, _FINDINGS_CAP))
    findings = (db.query(Finding).filter(Finding.tenant_id == tid)
                .order_by(Finding.id).limit(limit).all())
    users = db.query(User).filter(User.tenant_id == tid).all()
    keys = db.query(ApiKey).filter(ApiKey.tenant_id == tid).all()
    tokens = db.query(EnrollmentToken).filter(EnrollmentToken.tenant_id == tid).all()

    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "warden_dpa_version": settings.dpa_version,
        "include_content": bool(include_content),
        "tenant": tenant.to_dict(),
        "users": [u.to_dict() for u in users],
        "api_keys": [k.to_dict() for k in keys],
        "enrollment_tokens": [t.to_dict() for t in tokens],
        "upstreams": _upstreams(db, tid),
        "sso": _sso(db, tid),
        "audit_log": audit_log.recent(db, tid, limit=_AUDIT_CAP),
        "findings": [f.to_detail() if include_content else f.to_summary() for f in findings],
        "counts": {"users": len(users), "api_keys": len(keys),
                   "enrollment_tokens": len(tokens), "findings": len(findings)},
    }
