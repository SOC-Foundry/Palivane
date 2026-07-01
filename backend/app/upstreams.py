"""Resolve which upstream provider config the gateway should use for a given tenant.

Precedence: a tenant's own configured base URL / key (stored encrypted) wins; otherwise
fall back to the global env defaults. This is what gives each org billing isolation —
its allowed gateway calls forward with its own provider account.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from .config import settings
from .crypto import decrypt
from .models import TenantUpstream

PROVIDERS = ("openai", "anthropic", "gemini")


def _global_default(provider: str) -> tuple[str, str]:
    """(base_url, key) from global env for the provider."""
    if provider == "openai":
        return settings.gateway_upstream_base, settings.gateway_upstream_key
    if provider == "anthropic":
        return settings.gateway_anthropic_base, (settings.gateway_anthropic_key or settings.anthropic_api_key)
    if provider == "gemini":
        return settings.gateway_gemini_base, (settings.gateway_gemini_key or settings.gemini_api_key)
    return "", ""


def resolve(provider: str, tenant_id: int | None, db: Session) -> tuple[str, str]:
    """Return (base_url, key) for this tenant+provider: tenant config over global env."""
    g_base, g_key = _global_default(provider)
    if tenant_id is None:
        return g_base, g_key
    row = (
        db.query(TenantUpstream)
        .filter(TenantUpstream.tenant_id == tenant_id, TenantUpstream.provider == provider)
        .first()
    )
    if row is None:
        return g_base, g_key
    return (row.base_url or g_base), (decrypt(row.key_encrypted) or g_key)
