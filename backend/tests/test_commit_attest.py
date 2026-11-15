"""Commit attestations: the hook's session ledger and git trailers (cli/palivane-hook), and
the server record (app/attest.py)."""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import time
from importlib.machinery import SourceFileLoader

from app import attest
from app.detectors.base import AnalysisInput, Surface
from app.models import CommitAttestation, Tenant
from app.service import run_analysis

_CLI = pathlib.Path(__file__).resolve().parents[2] / "cli"
AWS = "AKIA" + "IOSFODNN7" + "QXAMPLE"


def _hook():
    name = "palivane_hook_attest"
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(_CLI / "palivane-hook")))
    mod = importlib.util.module_from_spec(spec); sys.modules[name] = mod; spec.loader.exec_module(mod)
    return mod


def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()


def _repo(tmp_path):
    repo = tmp_path / "repo"; repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "dev@acme.com"); _git(repo, "config", "user.name", "Dev")
    (repo / "a.py").write_text("print(1)\n"); _git(repo, "add", "."); _git(repo, "commit", "-q", "-m", "first")
    return repo


# --- hook side -----------------------------------------------------------------------------------

def test_ledger_and_trailer(tmp_path, monkeypatch):
    monkeypatch.setenv("PALIVANE_STATE_DIR", str(tmp_path / "state"))
    hook = _hook()
    repo = _repo(tmp_path)
    time.sleep(1.1)   # git's commit time is whole seconds; the ledger must be after it
    hook.ledger_append(str(repo), "Edit", "a.py")
    hook.ledger_append(str(repo), "Bash", "pytest -q", {"action": "allow", "severity": "low"})
    hook.ledger_append(str(repo), "Write", "b.py", {"action": "block", "severity": "high", "finding_id": 7})
    hook.ledger_append(str(tmp_path / "elsewhere"), "Edit", "x.py")
    rows = hook.ledger_since(str(repo), hook._last_commit_ts(str(repo)))
    assert len(rows) == 3
    s = hook.trailer_summary(str(repo), rows)
    assert s["tool_calls"] == 3 and s["files"] == 2 and s["blocked"] == 1 and s["agent"] == "claude-code"

    msg = tmp_path / "COMMIT_EDITMSG"; msg.write_text("fix the thing\n\n# Please enter the commit message\n#\n")
    monkeypatch.chdir(repo)
    assert hook.cmd_git_trailer(str(msg)) == 0
    text = msg.read_text()
    assert "Palivane-AI-Assisted: yes" in text and "Palivane-Scan: agent=claude-code; tool-calls=3; files=2; blocked=1; window=" in text
    assert text.index("Palivane-Scan") < text.index("# Please"), "trailers stay above git's comment lines"
    # idempotent
    hook.cmd_git_trailer(str(msg)); assert msg.read_text().count("Palivane-AI-Assisted") == 1


def test_no_agent_activity_no_trailer(tmp_path, monkeypatch):
    monkeypatch.setenv("PALIVANE_STATE_DIR", str(tmp_path / "state"))
    hook = _hook(); repo = _repo(tmp_path)
    msg = tmp_path / "MSG"; msg.write_text("plain human commit\n")
    monkeypatch.chdir(repo); hook.cmd_git_trailer(str(msg))
    assert msg.read_text() == "plain human commit\n"


def test_git_install_writes_both_hooks_and_a_commit_carries_trailers(tmp_path, monkeypatch):
    monkeypatch.setenv("PALIVANE_STATE_DIR", str(tmp_path / "state"))
    hook = _hook(); repo = _repo(tmp_path)
    monkeypatch.chdir(repo)
    monkeypatch.setattr(sys, "argv", [str(_CLI / "palivane-hook")])
    assert hook.cmd_git_install() == 0
    hooks = pathlib.Path(_git(repo, "rev-parse", "--git-path", "hooks"))
    hooks = hooks if hooks.is_absolute() else repo / hooks
    for n in ("prepare-commit-msg", "post-commit"):
        p = hooks / n
        assert p.exists() and os.access(p, os.X_OK) and "palivane-hook" in p.read_text()
    # second install leaves them alone
    before = (hooks / "post-commit").read_text(); hook.cmd_git_install(); assert (hooks / "post-commit").read_text() == before

    time.sleep(1.1)
    hook.ledger_append(str(repo), "Edit", "a.py")
    (repo / "a.py").write_text("print(2)\n")
    env = {**os.environ, "PALIVANE_STATE_DIR": str(tmp_path / "state"), "PALIVANE_URL": "", "PALIVANE_TOKEN": ""}
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "agent change"], cwd=repo, check=True, env=env)
    body = _git(repo, "log", "-1", "--format=%B")
    assert "Palivane-AI-Assisted: yes" in body and "tool-calls=1" in body
    assert _git(repo, "log", "-1", "--format=%(trailers:key=Palivane-AI-Assisted,valueonly)") == "yes"


def test_git_report_posts_the_commit(tmp_path, monkeypatch):
    monkeypatch.setenv("PALIVANE_STATE_DIR", str(tmp_path / "state"))
    hook = _hook(); repo = _repo(tmp_path)
    (repo / "a.py").write_text("print(3)\n"); _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "agent change\n\nPalivane-AI-Assisted: yes\nPalivane-Scan: agent=claude-code; tool-calls=4; files=1; blocked=0; window=2026-11-15T03:00:00Z..2026-11-15T03:10:00Z")
    sent = {}

    class _R:
        def __init__(self, data): self._d = data
        def read(self): return self._d
        def __enter__(self): return self
        def __exit__(self, *a): pass

    def fake_urlopen(req, timeout=5.0):
        sent["url"] = req.full_url; sent["body"] = json.loads(req.data); sent["tok"] = req.get_header("X-palivane-token")
        return _R(json.dumps({"id": 9, "findings": 2}).encode())
    monkeypatch.setattr(hook.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.chdir(repo)
    assert hook.cmd_git_report({"url": "https://app.example.test/", "token": "ak_x", "timeout": 5.0}) == 0
    assert sent["url"] == "https://app.example.test/api/attest/commit" and sent["tok"] == "ak_x"
    b = sent["body"]
    assert b["sha"] == _git(repo, "rev-parse", "HEAD") and b["tool_calls"] == 4 and b["agent"] == "claude-code"
    assert b["window_start"] == "2026-11-15T03:00:00Z" and b["subject"] == "agent change"


# --- server side ---------------------------------------------------------------------------------

def _tid(db): return db.query(Tenant).order_by(Tenant.id).first().id


def test_register_counts_the_persons_findings_in_the_window_and_signs(client, raw_client, db_factory, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "gateway_enforce_secrets", False)
    db = db_factory(); tid = _tid(db)
    tok = client.post("/api/apikeys", json={"label": "laptop", "actor": "dev@acme.com"}).json()["token"]
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    inside = run_analysis(AnalysisInput(content=f"deploy with {AWS}", sender="dev@acme.com", channel="claude-code",
                                        surface=Surface.AGENT_TOOLS, subject="Agent tool: Bash"), persist=True, db=db, tenant_id=tid)
    run_analysis(AnalysisInput(content=f"other {AWS}", sender="other@acme.com", channel="claude-code",
                               surface=Surface.AGENT_TOOLS, subject="Agent tool: Bash"), persist=True, db=db, tenant_id=tid)
    body = {"sha": "a" * 40, "repo": "git@github.com:acme/app.git", "branch": "main", "author": "Dev <dev@acme.com>",
            "subject": "agent change", "agent": "claude-code", "tool_calls": 5, "files": 2, "blocked": 0,
            "window_start": (now.replace(microsecond=0)).isoformat() + "Z", "window_end": now.isoformat() + "Z"}
    r = raw_client.post("/api/attest/commit", json=body, headers={"X-Palivane-Token": tok})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["findings"] == 1 and len(out["token"]) == 24
    rows = client.get("/api/attestations").json()["attestations"]
    assert len(rows) == 1 and rows[0]["finding_ids"] == [inside["finding_id"]] and rows[0]["actor"] == "dev@acme.com"
    v = client.get("/api/attest/verify?sha=" + "a" * 12).json()
    assert v["attested"] is True and v["valid"] is True and v["sha"] == "a" * 40
    assert client.get("/api/attest/verify?sha=" + "b" * 40).json() == {"sha": "b" * 40, "attested": False}
    # re-registering the same sha refreshes, never duplicates
    raw_client.post("/api/attest/commit", json={**body, "tool_calls": 6}, headers={"X-Palivane-Token": tok})
    assert db_factory().query(CommitAttestation).count() == 1


def test_attest_needs_a_capture_key(raw_client):
    r = raw_client.post("/api/attest/commit", json={"sha": "c" * 40}, headers={"X-Palivane-Token": "ak_nope"})
    assert r.status_code in (401, 403)
