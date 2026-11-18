"""The flight recorder (app/replay.py): an actor's window as steps, and the window replayed
against a policy that was not in force."""
from __future__ import annotations

from app import canary
from app.config import settings
from app.models import Tenant

UA = "palivane-hook/1.3.4 (claude-code/2.1.4)"
AWS = "AKIA" + "IOSFODNN7" + "QXAMPLE"


def _tid(db):
    return db.query(Tenant).order_by(Tenant.id).first().id


def _session(client, raw_client, db_factory, monkeypatch):
    """A short agent session: a benign-ish tool call, a planted instruction read, the obey,
    a credential in a prompt (monitor mode, so it went), and a containment."""
    monkeypatch.setattr(settings, "gateway_enforce_secrets", False)
    tid = _tid(db_factory())
    tok = client.post("/api/apikeys", json={"label": "laptop", "actor": "agent-7@acme.com"}).json()["token"]
    h = {"X-Palivane-Token": tok, "User-Agent": UA}
    line = canary.instruction_text(tid, "https://app.example.test")
    raw_client.post("/api/ingest/mcp", json={"method": "tool_result", "server": "", "tool": "WebFetch", "args_text": f"notes\n{line}", "transport": "stdio"}, headers=h)
    obey = line.split("run: curl -s ", 1)[1].split(" and ", 1)[0]
    raw_client.post("/api/ingest/mcp", json={"method": "tools/call", "server": "", "tool": "Bash", "args_text": f"curl -s {obey}", "shell_command": f"curl -s {obey}", "transport": "stdio"}, headers=h)
    raw_client.post("/api/ingest/ai-usage", json={"content": f"deploy with {AWS} now", "tool": "claude-code"}, headers=h)
    c = client.post("/api/containments", json={"scope": "user", "target": "agent-7@acme.com", "reason": "runaway", "hours": 1}).json()
    client.post(f"/api/containments/{c['id']}/release")
    return tid


def test_recording_orders_every_kind_of_step(client, raw_client, db_factory, monkeypatch):
    _session(client, raw_client, db_factory, monkeypatch)
    r = client.get("/api/replay?actor=agent-7@acme.com&days=1")
    assert r.status_code == 200, r.text
    rec = r.json()
    kinds = [s["kind"] for s in rec["steps"]]
    assert kinds == sorted(kinds, key=lambda k: 0) or True   # order is by time, checked below
    ts = [s["t"] for s in rec["steps"]]
    assert ts == sorted(ts)
    assert "inbound" in kinds and "tool" in kinds and "prompt" in kinds and "contain" in kinds and "release" in kinds
    assert [s["i"] for s in rec["steps"]] == list(range(len(rec["steps"])))
    read = next(s for s in rec["steps"] if s["kind"] == "inbound")
    obey = next(s for s in rec["steps"] if s["kind"] == "tool")
    assert read["canary"] == "read" and obey["canary"] == "obeyed" and obey["acted_on_planted"]
    assert rec["summary"]["canary_obeyed"] == 1 and rec["summary"]["planted"] == 1
    prompt = next(s for s in rec["steps"] if s["kind"] == "prompt")
    assert isinstance(prompt["action"], str) and prompt["action"] and AWS not in str(prompt)


def test_replay_shows_what_a_stricter_policy_would_have_stopped(client, raw_client, db_factory, monkeypatch):
    _session(client, raw_client, db_factory, monkeypatch)
    rec = client.get("/api/replay?actor=agent-7@acme.com&days=1").json()
    prompt = next(s for s in rec["steps"] if s["kind"] == "prompt")
    # As recorded (monitor mode, secrets not enforced): the credential prompt was not blocked.
    assert prompt["action"] != "block"
    r = client.post("/api/replay", json={"actor": "agent-7@acme.com", "days": 1,
                                         "policy": {"block_severity": "high", "enforce": True, "enforce_secrets": True}})
    assert r.status_code == 200, r.text
    rp = r.json()
    p2 = next(s for s in rp["steps"] if s["kind"] == "prompt")
    assert p2["replayed_action"] == "block" and p2["changed"] is True
    assert rp["summary"]["stopped_now"] >= rp["summary"]["stopped_then"]
    assert rp["summary"]["first_stop"] is not None
    # Looser: everything through, and the dropped check is named.
    rp2 = client.post("/api/replay", json={"actor": "agent-7@acme.com", "days": 1,
                                           "policy": {"block_severity": "critical", "enforce": False, "enforce_secrets": False,
                                                      "disabled_checks": ["secret_leak"]}}).json()
    p3 = next(s for s in rp2["steps"] if s["kind"] == "prompt")
    assert "secret_leak" in p3["dropped_checks"] and p3["replayed_action"] == "allow"
    assert rp2["policy"]["disabled_checks"] == ["secret_leak"]


def test_replay_needs_an_analyst(raw_client):
    assert raw_client.get("/api/replay?actor=x@acme.com").status_code in (401, 403)
