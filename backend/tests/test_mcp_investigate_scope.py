"""investigate_finding over the hosted MCP needs what its REST route needs: a console_write key.

QA (H6): it ran on any connection, so a console_read key or a palivane:read OAuth token (whose
consent screen says it "cannot change anything") stored a report on the finding, wrote an
audit entry and sent the finding to the org's LLM. REST refuses POST /investigate to both.
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


def test_a_console_write_key_gets_past_the_gate(client, db_factory):
    db = db_factory()
    try:
        fid = _finding(db)
        kid = _key_id(client, db, "console_write")
        with pytest.raises(HTTPException) as e:     # no BYOK LLM key in tests: the next check
            _as(mcp_remote._CALLER, kid, lambda: mcp_remote.investigate_finding(fid))
        assert "read-only" not in str(e.value.detail)
    finally:
        db.close()
