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

PROVIDERS = ("openai", "anthropic", "gemini", "xai", "vertex", "bedrock")


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
    # vertex/bedrock carry structured config, not a (base, key) pair — the tenant's
    # encrypted blob is surfaced through resolve()'s key slot and parsed by the flavor
    # resolver below; their global config lives in dedicated settings.
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
    (e.g. a local/self-hosted base URL), so a base alone counts there; Anthropic-shaped
    traffic also forwards through a cloud contract (Vertex/Bedrock) when one resolves."""
    if provider == "anthropic":
        return resolve_anthropic_upstream(tenant_id, db) is not None
    if provider in ("vertex", "bedrock"):
        up = resolve_anthropic_upstream(tenant_id, db)
        return bool(up and up["flavor"] == provider)
    base, key = resolve(provider, tenant_id, db)
    return bool(base if provider == "openai" else key)


# --- cloud-contract Claude (Vertex AI / AWS Bedrock) --------------------------------------

def _cfg_json(blob: str) -> dict | None:
    if not (blob or "").strip().startswith("{"):
        return None
    import json
    try:
        return json.loads(blob)
    except ValueError:
        return None


def resolve_anthropic_upstream(tenant_id: int | None, db: Session) -> dict | None:
    """Which upstream serves this tenant's Anthropic-shaped traffic, richest first:
    an Anthropic API key (tenant or global) always wins; otherwise a configured Vertex
    project (tenant SA blob or global ADC), then Bedrock (tenant key blob or global).

    Returns {"flavor": "anthropic", base, key} |
            {"flavor": "vertex", project, region, sa_json|None} |
            {"flavor": "bedrock", region, key(""=SigV4 ambient chain)} | None."""
    base, key = resolve("anthropic", tenant_id, db)
    if key:
        return {"flavor": "anthropic", "base": base, "key": key}

    _, vk = resolve("vertex", tenant_id, db)
    vcfg = _cfg_json(vk) or {}
    project = vcfg.get("project") or settings.gateway_vertex_project
    if (vk or settings.gateway_vertex_project) and project:
        return {"flavor": "vertex", "project": project,
                "region": vcfg.get("region") or settings.gateway_vertex_region,
                "sa_json": vcfg.get("service_account_json")}

    _, bk = resolve("bedrock", tenant_id, db)
    bcfg = _cfg_json(bk) or {}
    region = bcfg.get("region") or settings.gateway_bedrock_region
    if (bk or settings.gateway_bedrock_region) and region:
        return {"flavor": "bedrock", "region": region,
                "key": bcfg.get("key") or settings.gateway_bedrock_key}
    return None


_VTOK_CACHE: dict[str, tuple[str, float]] = {}   # sa email|__adc__ -> (token, soft expiry)


def vertex_token(sa_json: dict | str | None) -> str:
    """A cloud-platform OAuth token for Vertex calls: the tenant's service-account key
    when configured, else Application Default Credentials (on Cloud Run, the runtime
    service account — no key material at all). Cached ~50 minutes."""
    import time as _time
    if isinstance(sa_json, str) and sa_json.strip():
        import json
        sa_json = json.loads(sa_json)
    ck = (sa_json or {}).get("client_email") or "__adc__"
    hit = _VTOK_CACHE.get(ck)
    if hit and hit[1] > _time.time():
        return hit[0]
    import google.auth
    from google.auth.transport.requests import Request as _GARequest
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    if sa_json:
        from google.oauth2 import service_account
        creds = service_account.Credentials.from_service_account_info(sa_json, scopes=scopes)
    else:
        creds, _ = google.auth.default(scopes=scopes)
    creds.refresh(_GARequest())
    _VTOK_CACHE[ck] = (creds.token, _time.time() + 3000)
    return creds.token


def bedrock_headers(region: str, key: str, url: str, body: bytes) -> dict:
    """Auth headers for one Bedrock invoke: a Bedrock API key (bearer) when configured,
    else SigV4 over these exact bytes with the standard AWS credential chain."""
    if key:
        return {"Content-Type": "application/json", "Authorization": f"Bearer {key}"}
    import botocore.session
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    creds = botocore.session.get_session().get_credentials()
    if creds is None:
        raise RuntimeError("no AWS credentials for Bedrock — set a Bedrock API key or "
                           "provide the standard chain (role / env / profile)")
    req = AWSRequest(method="POST", url=url, data=body,
                     headers={"Content-Type": "application/json"})
    SigV4Auth(creds.get_frozen_credentials(), "bedrock", region).add_auth(req)
    return dict(req.headers)
