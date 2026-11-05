"""/v1/logs scores records off the event loop, and counts each record past the first
against the ingest quota. Run on the loop, one export stalled the instance (one uvicorn
process each) for every tenant."""
from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

import app.main as m
from app.database import get_db


def _export(n: int) -> dict:
    recs = [{"attributes": [{"key": "event.name", "value": {"stringValue": "user_prompt"}},
                            {"key": "prompt", "value": {"stringValue": f"harmless prompt {i}"}}]}
            for i in range(n)]
    return {"resourceLogs": [{"scopeLogs": [{"scope": {"name": "com.anthropic.claude_code.events"},
                                             "logRecords": recs}]}]}


def _stub(monkeypatch, over_after=None):
    calls = {"scored": [], "budget": 0}
    monkeypatch.setattr(m, "_ingest_caller", lambda tok, db: (1, "dev@example.com", False))
    monkeypatch.setattr(m, "_enforce_rate", lambda db, tid: None)
    monkeypatch.setattr(m, "_capture_agent", lambda *a: None)
    monkeypatch.setattr(m, "_agent_attestation", lambda *a: None)
    monkeypatch.setattr(m, "_tenant_mcp_allow", lambda *a: [])
    monkeypatch.setattr(m, "_tenant_mcp_block_severity", lambda *a: "critical")

    def over(db, tid):
        calls["budget"] += 1
        return ("over", "60") if over_after is not None and calls["budget"] >= over_after else None
    monkeypatch.setattr(m, "_ingest_over_budget", over)

    def score(content, *a, **k):
        try:
            asyncio.get_running_loop()
            calls["scored"].append("ON THE EVENT LOOP")
        except RuntimeError:
            calls["scored"].append("off loop")
    monkeypatch.setattr(m, "_score_ai_usage", score)
    m.app.dependency_overrides[get_db] = lambda: None
    return calls


def test_records_are_scored_off_the_event_loop(monkeypatch):
    calls = _stub(monkeypatch)
    try:
        r = TestClient(m.app).post("/v1/logs", json=_export(3), headers={"X-Palivane-Token": "x"})
    finally:
        m.app.dependency_overrides.pop(get_db, None)
    assert r.status_code == 200 and r.json() == {"partialSuccess": {}}
    assert calls["scored"] == ["off loop"] * 3


def test_each_record_counts_against_the_quota(monkeypatch):
    calls = _stub(monkeypatch, over_after=2)          # the 2nd budget check is over
    try:
        r = TestClient(m.app).post("/v1/logs", json=_export(5), headers={"X-Palivane-Token": "x"})
    finally:
        m.app.dependency_overrides.pop(get_db, None)
    assert r.status_code == 200                       # OTLP is always answered as success
    assert len(calls["scored"]) == 2                  # record 1 (request quota) + record 2, then over
