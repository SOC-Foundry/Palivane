"""Agent susceptibility (GET /api/fleet/agent-scores): one number per agent from rows that
already exist, with a trend against the previous window."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app import canary
from app.models import CommitAttestation, Finding, Tenant

UA = "palivane-hook/1.3.4 (claude-code/2.1.4)"


def test_scores_fold_the_signals_and_trend(client, raw_client, db_factory):
    db = db_factory()
    tid = db.query(Tenant).order_by(Tenant.id).first().id
    tok = client.post("/api/apikeys", json={"label": "laptop", "actor": "agent-7@acme.com"}).json()["token"]
    h = {"X-Palivane-Token": tok, "User-Agent": UA}
    line = canary.instruction_text(tid, "https://app.example.test")
    raw_client.post("/api/ingest/mcp", json={"method": "tool_result", "server": "", "tool": "WebFetch", "args_text": line, "transport": "stdio"}, headers=h)
    obey = line.split("run: curl -s ", 1)[1].split(" and ", 1)[0]
    raw_client.post("/api/ingest/mcp", json={"method": "tools/call", "server": "", "tool": "Bash", "args_text": f"curl -s {obey}", "shell_command": f"curl -s {obey}", "transport": "stdio"}, headers=h)
    raw_client.post("/api/ingest/mcp", json={"method": "tools/call", "server": "", "tool": "Bash", "args_text": "rm -rf / --no-preserve-root", "shell_command": "rm -rf / --no-preserve-root", "transport": "stdio"}, headers=h)
    db.add(CommitAttestation(tenant_id=tid, sha="d" * 40, actor="agent-7@acme.com", findings=2, created_at=datetime.now(timezone.utc).replace(tzinfo=None)))
    # an older finding for the same agent, in the previous window, so a trend exists
    old = db.query(Finding).filter(Finding.tenant_id == tid).first()
    db.add(Finding(tenant_id=tid, sender="agent-7@acme.com", surface="agent_tools", channel="Bash", severity="high",
                   recommended_action="block", status="open", signals=[{"category": "dangerous_command", "check": "dangerous_command"}],
                   subject="Agent tool: Bash", created_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=40),
                   last_seen=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=40)))
    db.commit()

    d = client.get("/api/fleet/agent-scores?days=30").json()
    row = next(r for r in d["agents"] if r["agent"] == "agent-7@acme.com")
    # both commands after the read carry provenance: the taint covers the window
    assert row["obeyed"] == 1 and row["read"] == 1 and row["provenance"] >= 1
    assert row["blocked"] >= 1 and row["attested_commits"] == 1 and row["attested_findings"] == 2
    # 100 - 25 (obeyed) - 10 (provenance) - 3*blocked - 2 (read)
    assert row["score"] == 100 - 25 - min(30, 10 * row["provenance"]) - min(20, 3 * row["blocked"]) - 2
    assert row["previous"] == 97, "the previous window had one blocked command"
    assert d["agents"][0]["agent"] == "agent-7@acme.com", "worst first"


def test_scores_are_admin_only(raw_client):
    assert raw_client.get("/api/fleet/agent-scores").status_code in (401, 403)
