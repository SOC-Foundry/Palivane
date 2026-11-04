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
    if row.base_url:
        # A tenant-chosen host only ever gets the tenant's own key. Pairing it with the
        # platform's global key sent that key to any host a tenant admin typed in.
        return row.base_url, key or ""
    return g_base, (key or g_key)


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


# Cloud-contract configs end up in a URL host (`{region}-aiplatform.googleapis.com`,
# `bedrock-runtime.{region}.amazonaws.com`), so their fields are held to strict shapes:
# a region with a dot, slash or '@' rewrites the host. Checked on write and on every use.
import re as _re
_REGION_RE = _re.compile(r"^[a-z]{2,12}(-[a-z0-9]{1,15}){0,3}$")
_GCP_PROJECT_RE = _re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_GOOGLE_TOKEN_URIS = ("https://oauth2.googleapis.com/token", "https://accounts.google.com/o/oauth2/token")


def valid_region(region) -> bool:
    return isinstance(region, str) and bool(_REGION_RE.match(region))


def _tenant_sa(raw) -> dict | None:
    """The tenant's own service-account key, parsed and checked, or None. Its token_uri
    must be Google's: google-auth POSTs the signed assertion there."""
    import json
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return None
    if not isinstance(raw, dict) or raw.get("type") != "service_account":
        return None
    if not (raw.get("client_email") and raw.get("private_key")):
        return None
    if raw.get("token_uri", _GOOGLE_TOKEN_URIS[0]) not in _GOOGLE_TOKEN_URIS:
        return None
    return raw


def tenant_cloud_config_error(provider: str, blob: str) -> str | None:
    """Why a tenant's Vertex/Bedrock config can't be used (None when it can)."""
    cfg = _cfg_json(blob)
    if cfg is None:
        return "config must be a JSON object"
    if not valid_region(cfg.get("region")):
        return "region must be a cloud region id like us-central1 or us-east-1"
    if provider == "vertex":
        if not _GCP_PROJECT_RE.match(str(cfg.get("project") or "")):
            return "project must be a Google Cloud project id"
        if _tenant_sa(cfg.get("service_account_json")) is None:
            return "service_account_json must be your own service-account key (Google token endpoint)"
    elif not (cfg.get("key") or "").strip():
        return "key must be your own Bedrock API key"
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

    # A tenant's cloud config is used on its own terms or not at all: never mixed with
    # the platform's project/region/key, and never authenticated with the platform's own
    # credentials (Application Default Credentials or the ambient AWS chain belong to the
    # deployment, so only the global config may use them).
    _, vk = resolve("vertex", tenant_id, db)
    if vk:
        if tenant_cloud_config_error("vertex", vk) is None:
            vcfg = _cfg_json(vk)
            return {"flavor": "vertex", "project": vcfg["project"], "region": vcfg["region"],
                    "sa_json": _tenant_sa(vcfg["service_account_json"])}
    elif settings.gateway_vertex_project and valid_region(settings.gateway_vertex_region):
        return {"flavor": "vertex", "project": settings.gateway_vertex_project,
                "region": settings.gateway_vertex_region, "sa_json": None}

    _, bk = resolve("bedrock", tenant_id, db)
    if bk:
        if tenant_cloud_config_error("bedrock", bk) is None:
            bcfg = _cfg_json(bk)
            return {"flavor": "bedrock", "region": bcfg["region"], "key": bcfg["key"].strip()}
    elif valid_region(settings.gateway_bedrock_region):
        return {"flavor": "bedrock", "region": settings.gateway_bedrock_region,
                "key": settings.gateway_bedrock_key}
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
    # Keyed by the whole credential, not a field the tenant chose: keyed by client_email,
    # a tenant naming another tenant's service account (or "__adc__") was served its token.
    import hashlib, json as _json
    ck = (hashlib.sha256(_json.dumps(sa_json, sort_keys=True).encode()).hexdigest()
          if sa_json else "__adc__")
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
