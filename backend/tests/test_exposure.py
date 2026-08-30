"""Blast-radius / exposure view: findings inverted to per-source-document leak summaries."""

from __future__ import annotations

from app.models import Finding, Tenant


def _tid(db_factory):
    db = db_factory()
    try:
        return db.query(Tenant).filter(Tenant.slug == "acme").first().id
    finally:
        db.close()


def _leak(db, tid, *, ref, title, owner, source, tool, sender, severity, seen=1, cont=0.9):
    db.add(Finding(
        tenant_id=tid, channel=tool, surface="ai_usage", sender=sender,
        subject="paste", severity=severity, risk_score=90, seen_count=seen,
        origin={"source": source, "ref": ref, "title": title, "owner": owner,
                "containment": cont}))


def test_empty_when_no_origins(client):
    assert client.get("/api/exposure").json()["documents"] == []


def test_groups_leaks_by_source_document(client, db_factory):
    tid = _tid(db_factory)
    db = db_factory()
    _leak(db, tid, ref="sp:1", title="Q3-forecast.xlsx", owner="finance@acme.com",
          source="sharepoint", tool="chatgpt.com", sender="alice@acme.com",
          severity="critical", seen=2)
    _leak(db, tid, ref="sp:1", title="Q3-forecast.xlsx", owner="finance@acme.com",
          source="sharepoint", tool="claude.ai", sender="bob@acme.com", severity="high")
    _leak(db, tid, ref="gd:9", title="roadmap.doc", owner="pm@acme.com",
          source="gdrive", tool="chatgpt.com", sender="alice@acme.com", severity="low")
    db.commit(); db.close()

    docs = client.get("/api/exposure").json()["documents"]
    assert len(docs) == 2
    top = docs[0]                                   # critical sorts first
    assert top["title"] == "Q3-forecast.xlsx" and top["source"] == "sharepoint"
    assert top["leaks"] == 3                         # 2 (seen_count) + 1
    assert top["max_severity"] == "critical"
    assert top["user_count"] == 2 and set(top["users"]) == {"alice@acme.com", "bob@acme.com"}
    tools = {t["tool"]: t["count"] for t in top["tools"]}
    assert tools == {"chatgpt.com": 2, "claude.ai": 1}


def test_findings_without_origin_are_excluded(client, db_factory):
    tid = _tid(db_factory)
    db = db_factory()
    db.add(Finding(tenant_id=tid, channel="chatgpt.com", surface="ai_usage",
                   sender="x@acme.com", severity="high", origin=None))
    _leak(db, tid, ref="sp:1", title="doc", owner="o@acme.com", source="sharepoint",
          tool="chatgpt.com", sender="y@acme.com", severity="high")
    db.commit(); db.close()
    docs = client.get("/api/exposure").json()["documents"]
    assert len(docs) == 1 and docs[0]["ref"] == "sp:1"


def test_exposure_is_admin_only(raw_client):
    assert raw_client.get("/api/exposure").status_code == 401
