"""The canary self-test (app/canary.py, `palivane-hook selftest`, GET /api/selftest)."""
from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import sys
from contextlib import redirect_stdout
from importlib.machinery import SourceFileLoader

from app import canary
from app.models import Finding, Tenant

_CLI = pathlib.Path(__file__).resolve().parents[2] / "cli"
UA = "palivane-hook/1.3.4 (claude-code/2.1.4)"


def _tenant(db) -> Tenant:
    return db.query(Tenant).order_by(Tenant.id).first()


def _key(client) -> str:
    return client.post("/api/apikeys", json={"label": "laptop", "actor": "dev@acme.com"}).json()["token"]


def test_canary_is_per_tenant_and_stable():
    a, b = canary.value(1), canary.value(2)
    assert a != b and a == canary.value(1) and canary.RE.fullmatch(a)
    assert canary.contains(1, f"deploy with {a} now") and not canary.contains(2, a)
    assert not canary.contains(1, "nothing here") and not canary.contains(None, a)


def test_any_capture_key_can_fetch_the_canary(client, raw_client, db_factory):
    tok = _key(client)
    r = raw_client.get("/api/capture/canary", headers={"X-Palivane-Token": tok})
    assert r.status_code == 200
    assert r.json()["canary"] == canary.value(_tenant(db_factory()).id)
    assert raw_client.get("/api/capture/canary", headers={"X-Palivane-Token": "ak_nope"}).status_code in (401, 403)


def test_canary_prompt_is_a_finding_reviewed_on_arrival(client, raw_client, db_factory):
    tok = _key(client)
    value = raw_client.get("/api/capture/canary", headers={"X-Palivane-Token": tok}).json()["canary"]
    r = raw_client.post("/api/ingest/ai-usage",
                        json={"content": f"Palivane self-test: deploy with {value}", "tool": "claude-code"},
                        headers={"X-Palivane-Token": tok, "User-Agent": UA})
    assert r.status_code == 200, r.text
    v = r.json()
    assert v["severity"] in ("high", "critical") and v.get("finding_id")
    assert any(s.get("category") == "secret_leak" for s in v["signals"])

    f = db_factory().get(Finding, v["finding_id"])
    assert f.status == "dismissed" and f.reviewed_by == canary.BY
    assert f.review_reason == "expected" and f.review_via == "bulk"
    # Out of the queue, still on the record.
    assert all(x["id"] != f.id for x in client.get("/api/findings?status=open").json()["findings"])
    assert client.get(f"/api/findings/{f.id}").status_code == 200


def test_repeated_canary_stays_dismissed(client, raw_client, db_factory):
    tok = _key(client)
    value = raw_client.get("/api/capture/canary", headers={"X-Palivane-Token": tok}).json()["canary"]
    body = {"content": f"deploy with {value}", "tool": "claude-code"}
    h = {"X-Palivane-Token": tok, "User-Agent": UA}
    a = raw_client.post("/api/ingest/ai-usage", json=body, headers=h).json()
    b = raw_client.post("/api/ingest/ai-usage", json=body, headers=h).json()
    assert a["finding_id"] == b["finding_id"]
    assert db_factory().get(Finding, a["finding_id"]).status == "dismissed"


def test_selftest_status_counts_and_times_it(client, raw_client, db_factory):
    s0 = client.get("/api/selftest").json()
    assert s0["count"] == 0 and s0["first"] is None and "canary" in s0   # admin sees the value
    tok = _key(client)
    value = s0["canary"]
    raw_client.post("/api/ingest/ai-usage", json={"content": f"try {value}", "tool": "claude-code"},
                    headers={"X-Palivane-Token": tok, "User-Agent": UA})
    s = client.get("/api/selftest").json()
    assert s["count"] == 1 and s["first"]["finding_id"] == s["last"]["finding_id"]
    assert s["first"]["sender"] == "dev@acme.com" and s["first"]["severity"] in ("high", "critical")
    assert s["first_key_at"] and s["minutes_to_first_finding"] is not None
    assert 0 <= s["minutes_to_first_finding"] < 5


def test_canary_never_counts_as_a_false_positive(client, raw_client, db_factory):
    tok = _key(client)
    value = raw_client.get("/api/capture/canary", headers={"X-Palivane-Token": tok}).json()["canary"]
    raw_client.post("/api/ingest/ai-usage", json={"content": f"use {value}", "tool": "claude-code"},
                    headers={"X-Palivane-Token": tok, "User-Agent": UA})
    pr = client.get("/api/precision?days=7").json()
    r = pr.get("reviewed") or {}
    assert (r.get("false_positive") or 0) == 0


# --- the hook subcommand -------------------------------------------------------------------

def _load_hook():
    name = "palivane_hook_selftest"
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(_CLI / "palivane-hook")))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_hook_selftest_prints_the_verdict(monkeypatch):
    hook = _load_hook()
    cfg = {"url": "https://app.example.test", "token": "ak_x", "user": "dev@acme.com",
           "timeout": 5.0, "enforce": False, "exclude": []}
    sent = {}
    monkeypatch.setattr(hook, "fetch_canary", lambda url, token, timeout=5.0: "pvcanary_" + "a" * 24)

    def fake_scan(endpoint, payload, url, token, user="", timeout=5.0, ua=""):
        sent.update(endpoint=endpoint, payload=payload, url=url, token=token, user=user)
        return {"severity": "critical", "action": "block", "finding_id": 42, "signals": []}
    monkeypatch.setattr(hook, "scan", fake_scan)
    out = io.StringIO()
    with redirect_stdout(out):
        rc = hook.cmd_selftest(cfg)
    assert rc == 0
    assert sent["endpoint"] == "/api/ingest/ai-usage" and "pvcanary_" in sent["payload"]["content"]
    assert sent["payload"]["tool"] == "claude-code" and sent["user"] == "dev@acme.com"
    text = out.getvalue()
    assert "OK" in text and "finding #42" in text and "Connect" in text


def test_hook_selftest_reports_an_unreachable_console(monkeypatch):
    hook = _load_hook()
    cfg = {"url": "https://app.example.test", "token": "ak_x", "user": "", "timeout": 5.0,
           "enforce": False, "exclude": []}
    monkeypatch.setattr(hook, "fetch_canary", lambda url, token, timeout=5.0: "pvcanary_" + "b" * 24)
    monkeypatch.setattr(hook, "scan", lambda *a, **k: {"action": "allow", "reason": "scan-failed"})
    out = io.StringIO()
    with redirect_stdout(out):
        rc = hook.cmd_selftest(cfg)
    assert rc == 1 and "FAILED" in out.getvalue()


def test_hook_selftest_without_config(capsys):
    hook = _load_hook()
    rc = hook.cmd_selftest({"url": "", "token": "", "user": "", "timeout": 5.0, "enforce": False, "exclude": []})
    assert rc == 2 and "palivane-connect" in capsys.readouterr().err
