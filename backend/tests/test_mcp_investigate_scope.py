"""investigate_finding over the hosted MCP needs a connection that may write: a palivane:triage
OAuth grant (whose consent text says it runs the analyst) or a console_write key.

QA (H6): it ran on any connection, so a console_read key or a palivane:read OAuth token (whose
consent screen says it "cannot change anything") stored a report on the finding, wrote an
audit entry and sent the finding to the org's LLM. REST refuses POST /investigate to both.
The per-connection flag (_CAN_TRIAGE) is what the ASGI wrapper sets from the credential.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app import mcp_remote
from app.models import ApiKey, AuditLog, Finding, Tenant, User


def _key_id(client, db, scope):
    token = client.post("/api/apikeys", json={"label": f"inv-{scope}", "scope": scope}).json()["token"]
    return db.query(ApiKey).filter(ApiKey.prefix == token[:11]).one().id


def _finding(db) -> int:
    t = db.query(Tenant).filter(Tenant.slug == "acme").one()
    t.analyst_enabled = True
    f = Finding(tenant_id=t.id, fingerprint="inv-scope", channel="t", surface="ai_usage",
                severity="high", risk_score=80, subject="t", status="open")
    db.add(f); db.commit()
    return f.id


def _as(var, value, fn):
    tok = var.set(value)
    try:
        return fn()
    finally:
        var.reset(tok)


@pytest.mark.parametrize("who", ["console_read", "oauth"])
def test_read_only_connections_cannot_investigate(client, db_factory, who):
    db = db_factory()
    try:
        fid = _finding(db)
        if who == "oauth":
            uid = db.query(User).filter(User.email == "admin@acme.com").one().id
            call = lambda: _as(mcp_remote._OAUTH_USER, uid,
                               lambda: mcp_remote.investigate_finding(fid))
        else:
            kid = _key_id(client, db, "console_read")
            call = lambda: _as(mcp_remote._CALLER, kid, lambda: mcp_remote.investigate_finding(fid))
        with pytest.raises(HTTPException) as e:
            call()
        assert e.value.status_code == 403 and "read-only" in e.value.detail
        db.expire_all()
        assert db.get(Finding, fid).investigation in (None, {})
        assert not db.query(AuditLog).filter(AuditLog.action == "finding.investigated").count()
    finally:
        db.close()


@pytest.mark.parametrize("who", ["console_write", "oauth_triage"])
def test_a_connection_allowed_to_triage_gets_past_the_gate(client, db_factory, who):
    db = db_factory()
    try:
        fid = _finding(db)
        if who == "oauth_triage":
            uid = db.query(User).filter(User.email == "admin@acme.com").one().id
            var, value = mcp_remote._OAUTH_USER, uid
        else:
            var, value = mcp_remote._CALLER, _key_id(client, db, "console_write")
        with pytest.raises(HTTPException) as e:     # no BYOK LLM key in tests: the next check
            _as(mcp_remote._CAN_TRIAGE, True,
                lambda: _as(var, value, lambda: mcp_remote.investigate_finding(fid)))
        assert "read-only" not in str(e.value.detail)
    finally:
        db.close()


def test_the_wrapper_decides_from_the_credential():
    from app.oauth_provider import READ_SCOPE, TRIAGE_SCOPE
    assert mcp_remote.triage_allowed(oauth_scopes=[READ_SCOPE, TRIAGE_SCOPE]) is True
    assert mcp_remote.triage_allowed(oauth_scopes=[READ_SCOPE]) is False
    assert mcp_remote.triage_allowed(key_scope="console_write") is True
    assert mcp_remote.triage_allowed(key_scope="console_read") is False


def test_the_consent_text_says_triage_runs_the_analyst():
    from app.oauth_provider import TRIAGE_SCOPE
    from app.oauth_routes import SCOPE_TEXT
    assert "AI analyst" in SCOPE_TEXT[TRIAGE_SCOPE]
