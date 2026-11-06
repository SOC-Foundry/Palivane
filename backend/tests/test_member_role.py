"""The "member" role (security review M4): auto-provisioned users start here and see only their
own findings. Org-wide reads — every finding, stats, the corpus, the MCP tools — refuse them."""
from __future__ import annotations

from app.models import User


def _member_client(client, raw_client, db_factory):
    r = client.post("/api/users", json={"email": "m@acme.com", "password": "password123456",
                                        "role": "member"})
    assert r.status_code in (200, 201), r.text
    tok = raw_client.post("/api/auth/login", json={"email": "m@acme.com",
                                                   "password": "password123456"}).json()
    raw_client.headers.update({"Authorization": f"Bearer {tok['access_token']}"})
    return raw_client


def test_member_sees_only_their_own_findings(client, raw_client, db_factory):
    m = _member_client(client, raw_client, db_factory)
    for path in ("/api/findings", "/api/stats", "/api/ml/corpus", "/api/setup-status",
                 "/api/agents/a2a-graph"):
        assert m.get(path).status_code == 403, path
    assert m.get("/api/findings/1").status_code == 403
    assert m.post("/api/analyze", json={"content": "x"}).status_code == 403
    assert m.get("/api/my/findings").status_code == 200
    assert m.get("/api/auth/me").json()["user"]["role"] == "member"


def test_admin_can_promote_a_member(client, raw_client, db_factory):
    _member_client(client, raw_client, db_factory)
    db = db_factory()
    uid = db.query(User).filter(User.email == "m@acme.com").one().id
    db.close()
    assert client.patch(f"/api/users/{uid}", json={"role": "analyst"}).json()["role"] == "analyst"
    assert raw_client.get("/api/findings").status_code == 200


def test_mcp_tools_refuse_members(client, raw_client, db_factory, monkeypatch):
    import pytest
    from fastapi import HTTPException
    from app import mcp_remote
    _member_client(client, raw_client, db_factory)
    db = db_factory()
    user = db.query(User).filter(User.email == "m@acme.com").one()
    monkeypatch.setattr(mcp_remote, "_caller_and_db", lambda: (user, db, None))
    monkeypatch.setattr(mcp_remote, "_close", lambda db, gen: None)
    with pytest.raises(HTTPException) as e:
        mcp_remote._read(lambda **k: {"ok": True}, admin=False)
    assert e.value.status_code == 403
    db.close()
