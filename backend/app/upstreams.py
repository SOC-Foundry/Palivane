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

PROVIDERS = ("openai", "anthropic", "gemini", "xai")


def _global_default(provider: str) -> tuple[str, str]:
    """(base_url, key) from global env for the provider.

    Deliberately does NOT fall back to the judge keys (ANTHROPIC_API_KEY / GEMINI_API_KEY):
    forwarding bills the provider account, and on a multi-tenant deployment the platform's
    judge key must never silently pay for tenants' LLM traffic. Forwarding uses the
    GATEWAY_* keys or the tenant's own configured upstream, nothing else."""
    if provider == "openai":
        return settings.gateway_upstream_base, settings.gateway_upstream_key
    if provider == "anthropic":
        return settings.gateway_anthropic_base, settings.gateway_anthropic_key
    if provider == "gemini":
        return settings.gateway_gemini_base, settings.gateway_gemini_key
    if provider == "xai":
        return settings.gateway_xai_base, settings.gateway_xai_key
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
    # SSRF guard at call time: a tenant-set base_url is only checked statically at write
    # (hostnames pass, deferred to here). Re-validate with DNS now — if it resolves to an
    # internal/metadata address (or a rebind), drop the whole tenant upstream and use the
    # trusted global default rather than letting the gateway fetch an attacker-chosen host.
    if row.base_url:
        from .netguard import is_safe_url
        if not is_safe_url(row.base_url):
            return g_base, g_key
    from . import crypto
    key = crypto.unseal_secret(row.key_encrypted, crypto.dek_for(db, tenant_id))
    return (row.base_url or g_base), (key or g_key)


def forwards(provider: str, tenant_id: int | None, db: Session) -> bool:
    """Whether the gateway will actually forward this tenant's calls to a real provider
    (vs. answering with the inspection stub). OpenAI-shaped upstreams can be keyless
    (e.g. a local/self-hosted base URL), so a base alone counts there; Anthropic/Gemini
    need a key."""
    base, key = resolve(provider, tenant_id, db)
    return bool(base if provider == "openai" else key)
