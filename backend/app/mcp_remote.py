"""Palivane as a REMOTE MCP server, mounted on the console API.

The stdio server in `mcp-server/` is a thin HTTP client to this very service. Everything
awkward about installing it — Python, a venv, two absolute paths, a key pasted into a
config file, a copy that goes stale in the field — exists because the transport is stdio,
not because anything local is being touched. Mounted here it is one
`claude mcp add --transport http` away on every client (Desktop, CLI, web), and there are
no field copies to drift out of date.

Mounted at /api/mcp rather than /mcp on purpose: the Cloudflare worker rate-limits and
never redirects paths under /api, and a new authenticated public surface should inherit
both rather than quietly sit outside them.

AUTHORIZATION, and the one thing that could not be reused.

Credential checks are shared with the REST path (auth.authenticate_console_key /
auth.user_for_console_key), so a revoked key, an expired key, an ingest-scoped key or a
deactivated user is refused here exactly as it is there — one implementation, not two.

What could NOT be shared is the write-route allowlist. `_user_for_api_key` gates writes by
(method, path), and MCP multiplexes every call — reads included — over a single
POST /api/mcp. Applied here it would refuse everything. Rather than reimplement
authorization per tool, which is the parallel permission system the scope design
deliberately avoided, this exposes READ TOOLS ONLY. There is no write to get wrong. Adding
`set_finding_status` and `sync_connector` needs a deliberate answer to "what is the
allowlist when there are no routes", and that is a separate change.

Role still applies: tools whose REST equivalent is admin-gated call require_admin() on the
resolved user, so an analyst's key sees exactly what an analyst sees. Calling an endpoint
function directly bypasses its Depends(), so this is not optional — it is the check the
route would have run.
"""

from __future__ import annotations

import contextvars
import logging

from fastapi import HTTPException
from mcp.server.fastmcp import FastMCP

from .auth import authenticate_console_key, require_admin, user_for_console_key
from .database import SessionLocal, get_db

log = logging.getLogger("uvicorn.error")


def _session():
    """A session from whatever the app is configured to use.

    Not SessionLocal directly: this code runs outside FastAPI's dependency injection (an
    ASGI wrapper and tool callables), so it would otherwise bind to the module-level engine
    and ignore any get_db override the app is running with. That is invisible in production,
    where they are the same engine, and wrong everywhere else — including under test, where
    it silently reads a different database than the one the request is being served from.
    """
    from .main import app as _app                      # local: main imports this module
    override = _app.dependency_overrides.get(get_db)
    if override is not None:
        gen = override()
        return next(gen), gen
    return SessionLocal(), None


def _close(db, gen):
    if gen is not None:
        try:
            next(gen)                                   # let the override run its teardown
        except StopIteration:
            pass
    else:
        db.close()

# The user the in-flight tool call acts as. Set by the ASGI wrapper below, read by tools.
# A contextvar rather than a global: concurrent calls on one instance must not see each
# other's identity.
_CALLER: contextvars.ContextVar[int | None] = contextvars.ContextVar("mcp_caller", default=None)

# stateless_http: this runs on Cloud Run behind a load balancer with min-instances 2, so
# consecutive requests from one client can land on different instances. A session held in
# one instance's memory would be missing from the next. Stateless is the only correct
# setting here, not a simplification.
# streamable_http_path="/": the SDK's app serves at /mcp by default, so mounting it under
# /api/mcp would put the endpoint at /api/mcp/mcp and answer /api/mcp with a 307 the MCP
# client does not follow. Serving at the mount root makes the URL the obvious one.
mcp = FastMCP("palivane", stateless_http=True, streamable_http_path="/")

# The transport's session manager is SINGLE-USE: StreamableHTTPSessionManager.run() raises
# on a second call for the same instance. One lifespan per process makes that invisible in
# production, but it is why main.py starts it in the app lifespan rather than anywhere that
# might run twice.


def _caller_and_db():
    """Re-resolve the calling user inside the tool, against a fresh session."""
    key_id = _CALLER.get()
    if key_id is None:                       # middleware always sets it; belt and braces
        raise HTTPException(status_code=401, detail="unauthenticated")
    db, gen = _session()
    from .models import ApiKey
    key = db.get(ApiKey, key_id)
    if key is None or not key.active:
        _close(db, gen)
        raise HTTPException(status_code=401, detail="invalid API key")
    user = user_for_console_key(key, db)
    return user, db, gen


def _read(fn, admin: bool, **kwargs):
    """Call a console read endpoint as the key's user, with the role check it would run."""
    user, db, gen = _caller_and_db()
    try:
        if admin:
            require_admin(user)              # the Depends() a direct call skips
        return fn(current=user, db=db, **kwargs)
    finally:
        _close(db, gen)


@mcp.tool()
def list_findings(severity: str = "", status: str = "", surface: str = "",
                  actor: str = "", limit: int = 50) -> dict:
    """Findings for your tenant, newest first. Filter by severity, status, surface, actor."""
    from . import main
    return _read(main.list_findings, admin=False,
                 severity=severity or None, status=status or None,
                 surface=surface or None, actor=actor or None, limit=min(limit, 200))


@mcp.tool()
def get_finding(finding_id: int) -> dict:
    """Full detail for one finding: signals, evidence, actor, and the owner's response."""
    from . import main
    return _read(main.get_finding, admin=False, finding_id=finding_id)


@mcp.tool()
def ai_tool_inventory() -> dict:
    """Shadow-AI inventory: which AI tools are in use, sanctioned or not, and the exposure."""
    from . import main
    return _read(main.discovery_inventory, admin=True)


@mcp.tool()
def list_connectors() -> dict:
    """SaaS connectors and their sync status."""
    from . import main
    return _read(main.connectors_list, admin=True)


@mcp.tool()
def gateway_usage() -> dict:
    """LLM-gateway usage: minute, 24h and daily totals against the limit."""
    from . import main
    return _read(main.usage, admin=True)


def _unauthorized(message: str):
    from starlette.responses import JSONResponse
    return JSONResponse({"error": message}, status_code=401,
                        headers={"WWW-Authenticate": 'Bearer realm="palivane-mcp"'})


def build_asgi_app():
    """The mounted app: authenticate the bearer key, then hand off to the MCP transport."""
    inner = mcp.streamable_http_app()

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return await inner(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        auth = headers.get("authorization", "")
        token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
        if not token:
            return await _unauthorized(
                "this endpoint needs a console-scoped Palivane API key: "
                "Authorization: Bearer ak_…")(scope, receive, send)
        db, gen = _session()
        try:
            key = authenticate_console_key(token, db)
            user_for_console_key(key, db)    # rejects a key whose user is gone
            key_id = key.id
        except HTTPException as e:
            return await _unauthorized(str(e.detail))(scope, receive, send)
        except Exception:                    # never leak an internal error as an auth answer
            log.exception("palivane-mcp: authentication failed unexpectedly")
            return await _unauthorized("authentication failed")(scope, receive, send)
        finally:
            _close(db, gen)
        tok = _CALLER.set(key_id)
        try:
            return await inner(scope, receive, send)
        finally:
            _CALLER.reset(tok)

    return app
