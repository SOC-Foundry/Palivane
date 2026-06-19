"""Coverage reconciliation: find AI usage Warden never captured."""

from __future__ import annotations

from dataclasses import dataclass

from app.coverage import reconcile
from app.models import Finding


@dataclass
class Ev:
    actor: str
    tool: str = ""
    last_seen: str = ""


def test_reconcile_basic():
    events = [Ev("Alice@acme.com", "chatgpt", "2026-06-01"),
              Ev("bob@acme.com", "claude"),
              Ev("carol@acme.com", "chatgpt", "2026-06-02")]
    covered = {"alice@acme.com", "bob@acme.com"}   # carol is missing
    rep = reconcile(events, covered)
    assert rep["total_actors"] == 3
    assert rep["covered"] == 2
    assert rep["uncovered_count"] == 1
    assert rep["uncovered"][0]["actor"] == "carol@acme.com"
    assert rep["coverage_rate"] == round(2 / 3, 4)


def test_reconcile_normalizes_and_aggregates_tools():
    events = [Ev("Dave@acme.com", "chatgpt", "2026-06-01"),
              Ev("dave@acme.com", "gemini", "2026-06-03")]   # same actor, 2 tools
    rep = reconcile(events, set())
    assert rep["total_actors"] == 1                # case-folded to one
    u = rep["uncovered"][0]
    assert u["tools"] == ["chatgpt", "gemini"]
    assert u["last_seen"] == "2026-06-03"          # max timestamp


def test_reconcile_empty():
    assert reconcile([], set())["coverage_rate"] is None


def _finding(**kw):
    base = dict(tenant_id=1, surface="llm_io", sender="alice@acme.com", channel="llm",
                content="hi", risk_score=10, severity="low", signals=[])
    base.update(kw)
    return Finding(**base)


def test_endpoint_reports_uncovered(client, db_factory):
    # The 'client' fixture is admin for tenant acme (id 1). Seed captured actors.
    db = db_factory()
    db.add_all([
        _finding(sender="alice@acme.com", surface="llm_io"),
        _finding(sender="bob@acme.com", surface="ai_usage"),
        _finding(sender="eve@other.com", tenant_id=2, surface="llm_io"),  # other tenant
    ])
    db.commit()
    db.close()

    r = client.post("/api/coverage/reconcile", json={"events": [
        {"actor": "alice@acme.com", "tool": "chatgpt"},
        {"actor": "bob@acme.com", "tool": "claude"},
        {"actor": "mallory@acme.com", "tool": "chatgpt", "last_seen": "2026-06-10"},
    ]})
    body = r.json()
    assert r.status_code == 200
    assert body["total_actors"] == 3
    assert body["covered"] == 2                     # alice + bob captured
    assert body["uncovered_count"] == 1
    assert body["uncovered"][0]["actor"] == "mallory@acme.com"


def test_endpoint_admin_only(client, db_factory):
    from app import users as users_cli
    db = db_factory()
    users_cli.create_user(db, "acme", "analyst@acme.com", "password123", "analyst")
    db.close()
    at = client.post("/api/auth/login", json={"email": "analyst@acme.com", "password": "password123"}).json()["access_token"]
    r = client.post("/api/coverage/reconcile", json={"events": [{"actor": "x@acme.com"}]},
                    headers={"Authorization": f"Bearer {at}"})
    assert r.status_code == 403
