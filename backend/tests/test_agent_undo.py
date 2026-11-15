"""Undo for agents: the hook's journal and `palivane-hook undo` (cli/palivane-hook), and the
containment-driven revert (app/containment.py request_revert / record_revert)."""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sys
import time
from importlib.machinery import SourceFileLoader

from app import containment
from app.models import Containment

_CLI = pathlib.Path(__file__).resolve().parents[2] / "cli"


def _hook():
    name = "palivane_hook_undo"
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(_CLI / "palivane-hook")))
    mod = importlib.util.module_from_spec(spec); sys.modules[name] = mod; spec.loader.exec_module(mod)
    return mod


def _agent_edits(hook, cwd: pathlib.Path):
    """What the hook sees when an agent edits a.py twice, creates b.py, and edits elsewhere."""
    a, b = cwd / "a.py", cwd / "b.py"
    a.write_text("v1\n")
    j = hook.journal_snapshot("Edit", {"file_path": str(a), "old_string": "v1", "new_string": "v2"})
    hook.ledger_append(str(cwd), "Edit", str(a), journal=j); a.write_text("v2\n")
    j = hook.journal_snapshot("Write", {"file_path": str(a), "content": "v3"})
    hook.ledger_append(str(cwd), "Write", str(a), journal=j); a.write_text("v3\n")
    j = hook.journal_snapshot("Write", {"file_path": str(b), "content": "new"})
    hook.ledger_append(str(cwd), "Write", str(b), journal=j); b.write_text("new\n")
    other = cwd.parent / "other"; other.mkdir(exist_ok=True); (other / "x.py").write_text("keep\n")
    j = hook.journal_snapshot("Edit", {"file_path": str(other / "x.py")})
    hook.ledger_append(str(other), "Edit", str(other / "x.py"), journal=j); (other / "x.py").write_text("changed\n")
    return a, b, other / "x.py"


def test_journal_then_undo_restores_first_pre_state_and_removes_created_files(tmp_path, monkeypatch):
    monkeypatch.setenv("PALIVANE_STATE_DIR", str(tmp_path / "state"))
    hook = _hook()
    cwd = tmp_path / "repo"; cwd.mkdir()
    t0 = time.time() - 1
    a, b, x = _agent_edits(hook, cwd)
    assert a.read_text() == "v3\n" and b.exists()
    plan = hook.undo_plan(str(cwd), t0)
    assert set(plan["restore"]) == {str(a.resolve())} and plan["delete"] == [str(b.resolve())]
    monkeypatch.chdir(cwd)
    assert hook.cmd_undo(["--since", str(t0), "--dry-run"]) == 0
    assert a.read_text() == "v3\n", "dry run changes nothing"
    assert hook.cmd_undo(["--since", str(t0)]) == 0
    assert a.read_text() == "v1\n" and not b.exists()
    assert x.read_text() == "changed\n", "another directory is untouched"
    # idempotent: nothing more to do once restored (the pre-state is still v1)
    assert hook.cmd_undo(["--since", str(t0)]) == 0 and a.read_text() == "v1\n"


def test_undo_since_parses_relative_and_iso(tmp_path, monkeypatch):
    monkeypatch.setenv("PALIVANE_STATE_DIR", str(tmp_path / "state"))
    hook = _hook()
    now = time.time()
    assert abs(hook._parse_since("30m", str(tmp_path)) - (now - 1800)) < 5
    assert abs(hook._parse_since("2h", str(tmp_path)) - (now - 7200)) < 5
    import calendar
    assert hook._parse_since("2026-11-15T03:00:00Z", str(tmp_path)) == calendar.timegm((2026, 11, 15, 3, 0, 0, 0, 0, 0))
    try:
        hook._parse_since("yesterday", str(tmp_path)); assert False
    except ValueError:
        pass


def test_large_files_are_skipped_not_lost(tmp_path, monkeypatch):
    monkeypatch.setenv("PALIVANE_STATE_DIR", str(tmp_path / "state"))
    hook = _hook()
    big = tmp_path / "big.bin"; big.write_bytes(b"x" * (hook._JOURNAL_MAX_FILE + 1))
    j = hook.journal_snapshot("Write", {"file_path": str(big)})
    assert j["skipped"] == "too large" and j["snapshot"] == ""
    hook.ledger_append(str(tmp_path), "Write", str(big), journal=j)
    plan = hook.undo_plan(str(tmp_path), time.time() - 5)
    assert plan["skipped"] == [str(big.resolve())] and not plan["restore"]


def test_containment_answer_with_revert_since_reverts_once_and_reports(tmp_path, monkeypatch):
    monkeypatch.setenv("PALIVANE_STATE_DIR", str(tmp_path / "state"))
    hook = _hook()
    cwd = tmp_path / "repo"; cwd.mkdir()
    t0 = time.time() - 1
    a, b, _ = _agent_edits(hook, cwd)
    sent = []

    class _R:
        def read(self): return b"{}"
    monkeypatch.setattr(hook.urllib.request, "urlopen", lambda req, timeout=5: sent.append(json.loads(req.data)) or _R())
    verdict = {"action": "block", "contained": {"until": int(time.time()) + 3600, "id": 7, "revert_since": t0, "message": "Paused"}}
    cfg = {"url": "https://app.example.test", "token": "ak_x", "timeout": 5}
    hook.auto_revert(verdict, cfg, str(cwd))
    assert a.read_text() == "v1\n" and not b.exists()
    assert len(sent) == 1 and sent[0]["containment_id"] == 7 and sent[0]["restored"] == 1 and sent[0]["deleted"] == 1
    # The same answer again does nothing more (and reports nothing more).
    a.write_text("edited by hand\n")
    hook.auto_revert(verdict, cfg, str(cwd))
    assert a.read_text() == "edited by hand\n" and len(sent) == 1
    # The offline containment record carries the revert so a device cut off still complies.
    hook.contained_note(verdict)
    off = hook.contained_offline()
    assert off["contained"]["revert_since"] == t0 and off["contained"]["id"] == 7


# --- server side ---------------------------------------------------------------------------------

def test_revert_request_rides_the_containment_answer_and_reports_land(client, raw_client, db_factory):
    tok = client.post("/api/apikeys", json={"label": "laptop", "actor": "dev@acme.com"}).json()["token"]
    c = client.post("/api/containments", json={"scope": "user", "target": "dev@acme.com", "reason": "runaway agent", "hours": 2}).json()
    # Before the revert request the containment answer has no revert_since.
    v = raw_client.post("/api/ingest/mcp", json={"method": "tools/call", "server": "", "tool": "Bash", "args_text": "ls", "transport": "stdio"},
                        headers={"X-Palivane-Token": tok, "User-Agent": "palivane-hook/1.3.4"}).json()
    assert v["action"] == "block" and v["contained"]["id"] == c["id"] and "revert_since" not in v["contained"]

    r = client.post(f"/api/containments/{c['id']}/revert", json={})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["revert_since"] == c["created_at"] and d["revert_by"] == "admin@acme.com"
    v2 = raw_client.post("/api/ingest/mcp", json={"method": "tools/call", "server": "", "tool": "Bash", "args_text": "ls", "transport": "stdio"},
                         headers={"X-Palivane-Token": tok, "User-Agent": "palivane-hook/1.3.4"}).json()
    assert isinstance(v2["contained"]["revert_since"], int) and v2["contained"]["id"] == c["id"]

    rep = raw_client.post("/api/containments/revert-report",
                          json={"containment_id": c["id"], "host": "laptop-7", "cwd": "/home/dev/app", "restored": 3, "deleted": 1, "failed": 0, "files": ["/home/dev/app/a.py"]},
                          headers={"X-Palivane-Token": tok})
    assert rep.status_code == 200 and rep.json()["recorded"] is True
    row = next(x for x in client.get("/api/containments").json()["containments"] if x["id"] == c["id"])
    assert row["reverts"][0]["host"] == "laptop-7" and row["reverts"][0]["restored"] == 3

    # Org-wide containments cannot be reverted (no single target to put back).
    o = client.post("/api/containments", json={"scope": "org", "target": "", "reason": "drill", "hours": 1}).json()
    assert client.post(f"/api/containments/{o['id']}/revert", json={}).status_code == 400
    acts = [a for a in db_factory().query(__import__("app.models", fromlist=["AuditLog"]).AuditLog).all() if a.action == "containment.revert"]
    assert len(acts) == 1
