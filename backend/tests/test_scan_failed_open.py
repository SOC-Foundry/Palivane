"""Scans that fail open are counted and reported, not folded silently into allow (SEC-01).

Every capture client fails open when a scan cannot complete (timeout, network error, 5xx,
rejected key, circuit breaker open). That stays: Palivane being unreachable must never block
the user. The gap was that the sensor then stopped being a sensor and nobody was told. Each
hook and the proxy now keep a small local tally (~/.palivane/scan-failed-<plane>.json:
counts, reasons, first/last time, never content) and attach it to the next request that
reaches the backend, which adds it to that sensor's heartbeat for the Fleet view.

These tests drive the REAL request path of each client (urlopen stubbed, or routed into the
real backend), so they check the user-facing outcome is unchanged, what goes on the wire,
and what the console gets back."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import socket
import sys
import time
import urllib.error
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


claude = _load("pv_hook_failopen", _ROOT / "cli" / "palivane-hook")
cursor = _load("pv_cursor_failopen", _ROOT / "cli" / "palivane-cursor-hook")
codex = _load("pv_codex_failopen", _ROOT / "cli" / "palivane-codex-hook")
gemini = _load("pv_gemini_failopen", _ROOT / "cli" / "palivane-gemini-hook")
copilot = _load("pv_copilot_failopen", _ROOT / "cli" / "palivane-copilot-hook")
sys.path.insert(0, str(_ROOT / "proxy"))
import palivane_addon as proxy  # noqa: E402

_SECRET = "please refactor; my key is AKIAIOSFODNN7EXAMPLE"

# Per hook: (module, an event that is scanned INLINE, the endpoint it goes to, tool row).
_HOOKS = {
    "claude": (claude, {"hook_event_name": "UserPromptSubmit", "prompt": _SECRET, "cwd": "/w"},
               "/api/ingest/ai-usage"),
    "cursor": (cursor, {"hook_event_name": "beforeSubmitPrompt", "prompt": _SECRET, "cwd": "/w"},
               "/api/ingest/ai-usage"),
    "codex": (codex, {"hook_event_name": "UserPromptSubmit", "prompt": _SECRET, "cwd": "/w"},
              "/api/ingest/ai-usage"),
    "gemini": (gemini, {"hook_event_name": "BeforeAgent", "prompt": _SECRET, "cwd": "/w"},
               "/api/ingest/ai-usage"),
    # Copilot prompts are observe-only (detached); its tool calls are the inline scan.
    "copilot": (copilot, {"toolName": "bash", "toolArgs": {"command": "echo " + _SECRET},
                          "cwd": "/w"}, "/api/ingest/mcp"),
}
_MODS = [claude, cursor, codex, gemini, copilot, proxy]
_CFG = {"url": "https://palivane.example", "token": "ak_test", "enforce": False,
        "timeout": 1.0, "user": "dev@acme.com", "exclude": []}


class _Resp:
    def __init__(self, body: bytes):
        self._b = body

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _wire(mod, monkeypatch, outcome):
    """Stub the network under the client's real request code. `outcome` is an exception
    instance to raise, or a dict to answer with. Returns the list of request bodies sent."""
    sent = []

    def urlopen(req, timeout=None):
        sent.append(json.loads(req.data))
        if isinstance(outcome, BaseException):
            raise outcome
        return _Resp(json.dumps(outcome).encode())

    monkeypatch.setattr(mod.urllib.request, "urlopen", urlopen)
    return sent


def _drive(mod, monkeypatch, capsys, event):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(event)))
    monkeypatch.setattr(mod, "read_config", lambda: dict(_CFG))
    monkeypatch.setattr(mod, "_send_detached", lambda *a, **k: None)
    rc = mod.main()
    return rc, capsys.readouterr().out.strip()


def _pending(mod) -> dict:
    try:
        with open(mod._failopen_path()) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {}


def _claims(mod) -> list:
    d = os.path.dirname(mod._failopen_path())
    return [n for n in os.listdir(d) if ".claim." in n] if os.path.isdir(d) else []


_ALLOW = {"action": "allow", "risk_score": 0, "severity": "benign", "signals": []}


# --- each hook: a failed scan is recorded, the user sees nothing new, the next good
# --- request carries the tally, and the tally is then gone ---------------------------

@pytest.mark.parametrize("name", list(_HOOKS))
def test_a_failed_scan_is_recorded_and_reported_on_the_next_success(name, monkeypatch, capsys):
    mod, event, endpoint = _HOOKS[name]
    _wire(mod, monkeypatch, urllib.error.URLError(socket.timeout("timed out")))
    rc, out = _drive(mod, monkeypatch, capsys, event)
    # Nothing changes for the user: exit 0, nothing denied.
    assert rc == 0
    assert "deny" not in out and "block" not in out
    st = _pending(mod)
    assert st["count"] == 1 and st["reasons"] == {"timeout": 1}
    assert st["first"] <= st["last"] <= time.time() + 1

    sent = _wire(mod, monkeypatch, _ALLOW)
    rc, _ = _drive(mod, monkeypatch, capsys, event)
    assert rc == 0 and len(sent) == 1
    report = sent[0]["scan_failed"]
    assert report["count"] == 1 and report["reasons"] == {"timeout": 1}
    # The report is counts and times. No content, no URL, no error text.
    assert set(report) <= {"count", "reasons", "first", "last"}
    assert "AKIA" not in json.dumps(report)
    assert _pending(mod) == {} and _claims(mod) == []

    sent = _wire(mod, monkeypatch, _ALLOW)
    _drive(mod, monkeypatch, capsys, event)
    assert "scan_failed" not in sent[0]                     # delivered once, not again


@pytest.mark.parametrize("name", list(_HOOKS))
def test_the_happy_path_sends_nothing_extra(name, monkeypatch, capsys):
    mod, event, _ = _HOOKS[name]
    sent = _wire(mod, monkeypatch, _ALLOW)
    _drive(mod, monkeypatch, capsys, event)
    assert len(sent) == 1 and "scan_failed" not in sent[0]
    assert not os.path.exists(mod._failopen_path())


@pytest.mark.parametrize("name", list(_HOOKS))
def test_a_failed_delivery_keeps_the_tally_and_adds_to_it(name, monkeypatch, capsys):
    mod, event, _ = _HOOKS[name]
    _wire(mod, monkeypatch, urllib.error.URLError(ConnectionRefusedError()))
    _drive(mod, monkeypatch, capsys, event)
    sent = _wire(mod, monkeypatch, urllib.error.HTTPError("u", 503, "down", {}, None))
    _drive(mod, monkeypatch, capsys, event)
    assert sent[0]["scan_failed"]["reasons"] == {"network": 1}        # it was attached...
    st = _pending(mod)                                                # ...and folded back
    assert st["count"] == 2 and st["reasons"] == {"network": 1, "server-error": 1}
    assert _claims(mod) == []


@pytest.mark.parametrize("name", list(_HOOKS))
def test_a_rejected_key_is_its_own_reason(name, monkeypatch, capsys):
    mod, event, _ = _HOOKS[name]
    _wire(mod, monkeypatch, urllib.error.HTTPError("u", 401, "no", {}, None))
    rc, out = _drive(mod, monkeypatch, capsys, event)
    # Unchanged behavior: Claude Code surfaces a rejected key as a NON-blocking hook error
    # (exit 1, #rejected-key); every other host exits 0. Nobody is blocked.
    assert rc == (1 if mod is claude else 0)
    assert "deny" not in out
    assert _pending(mod)["reasons"] == {"auth-rejected": 1}


@pytest.mark.parametrize("name", list(_HOOKS))
def test_an_unreadable_answer_counts_but_the_tally_was_delivered(name, monkeypatch, capsys):
    mod, event, _ = _HOOKS[name]
    _wire(mod, monkeypatch, urllib.error.URLError(socket.timeout()))
    _drive(mod, monkeypatch, capsys, event)

    def garbage(req, timeout=None):
        return _Resp(b"<html>proxy login</html>")

    monkeypatch.setattr(mod.urllib.request, "urlopen", garbage)
    rc, _ = _drive(mod, monkeypatch, capsys, event)
    assert rc == 0
    # The server took the request, so the timeout was delivered; the garbage is new.
    assert _pending(mod)["reasons"] == {"bad-response": 1}


def test_claude_breaker_skips_are_counted_without_touching_the_network(monkeypatch, capsys):
    event = _HOOKS["claude"][1]
    _wire(claude, monkeypatch, urllib.error.URLError(socket.timeout()))
    for _ in range(claude._FAIL_THRESHOLD):                 # trip the transient cooldown
        _drive(claude, monkeypatch, capsys, event)
    sent = _wire(claude, monkeypatch, _ALLOW)
    rc, _ = _drive(claude, monkeypatch, capsys, event)
    assert rc == 0 and sent == []                           # breaker open: no request
    assert _pending(claude)["reasons"] == {"timeout": 3, "breaker-open": 1}


def test_claude_monitor_mode_tool_call_worker_counts_its_failure(monkeypatch):
    # Monitor-mode tool calls are posted by a detached `--send` child; its failure counts.
    job = {"endpoint": "/api/ingest/mcp", "payload": {"method": "tools/call", "tool": "Bash"},
           "url": _CFG["url"], "token": "ak_test", "user": "", "timeout": 1}
    _wire(claude, monkeypatch, urllib.error.HTTPError("u", 500, "boom", {}, None))
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(job)))
    monkeypatch.setattr("sys.argv", ["palivane-hook", "--send"])
    assert claude.main() == 0
    assert _pending(claude)["reasons"] == {"server-error": 1}


def test_copilot_still_exits_zero_when_every_scan_fails(monkeypatch, capsys):
    # Copilot treats a non-zero exit as DENY, so this is the fail-open guarantee there.
    mod, event, _ = _HOOKS["copilot"]
    _wire(mod, monkeypatch, urllib.error.HTTPError("u", 401, "no", {}, None))
    rc, out = _drive(mod, monkeypatch, capsys, event)
    assert rc == 0 and out == ""


# --- the ledger itself ------------------------------------------------------------------

@pytest.mark.parametrize("mod", _MODS, ids=lambda m: m._FAILOPEN_FILE)
def test_an_orphaned_claim_is_folded_back(mod):
    mod.record_scan_failure("timeout")
    claim, report = mod.claim_scan_failures()
    assert claim and report["count"] == 1
    old = time.time() - mod._FAILOPEN_ORPHAN_SECS - 5
    os.utime(claim, (old, old))                             # the sender was killed mid-flight
    mod.record_scan_failure("network")
    assert _pending(mod)["reasons"] == {"timeout": 1, "network": 1}
    assert _claims(mod) == []


@pytest.mark.parametrize("mod", _MODS, ids=lambda m: m._FAILOPEN_FILE)
def test_a_fresh_claim_in_flight_is_left_alone(mod):
    mod.record_scan_failure("timeout")
    claim, _ = mod.claim_scan_failures()
    mod.record_scan_failure("network")                      # a concurrent failure
    assert _pending(mod)["reasons"] == {"network": 1}       # not double-counted
    mod.scan_failures_delivered(claim)
    assert _claims(mod) == []


@pytest.mark.parametrize("mod", _MODS, ids=lambda m: m._FAILOPEN_FILE)
def test_a_tampered_ledger_reports_only_well_formed_counts(mod):
    path = mod._failopen_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        json.dump({"count": 10**12, "first": float("inf"), "last": "soon", "prompt": _SECRET,
                   "reasons": {"timeout": 2, "stolen": 9, "network": -4, "error": True,
                               "server-error": 10**9}}, fh, allow_nan=True)
    claim, report = mod.claim_scan_failures()
    # Unknown reasons, non-positive or non-int counts, bad timestamps and extra keys are
    # dropped; counts are capped; the total is recomputed, never trusted.
    assert report == {"count": mod._FAILOPEN_MAX,
                      "reasons": {"timeout": 2, "server-error": mod._FAILOPEN_MAX}}
    assert "AKIA" not in json.dumps(report)
    mod.scan_failures_delivered(claim)
    with open(path, "w") as fh:
        fh.write("{not json")
    assert mod.claim_scan_failures() == ("", {})
    assert _claims(mod) == []


@pytest.mark.parametrize("mod", _MODS, ids=lambda m: m._FAILOPEN_FILE)
def test_an_unwritable_state_dir_never_raises(mod, monkeypatch, tmp_path):
    blocker = tmp_path / "file-not-dir"
    blocker.write_text("x")
    monkeypatch.setenv("PALIVANE_STATE_DIR", str(blocker))
    mod.record_scan_failure("timeout")
    assert mod.claim_scan_failures() == ("", {})
    mod.scan_failures_delivered("")


@pytest.mark.parametrize("mod", _MODS, ids=lambda m: m._FAILOPEN_FILE)
def test_reasons_are_a_fixed_vocabulary(mod):
    r = mod.failure_reason
    assert r(urllib.error.HTTPError("u", 403, "x", {}, None)) == "auth-rejected"
    assert r(urllib.error.HTTPError("u", 429, "x", {}, None)) == "rate-limited"
    assert r(urllib.error.HTTPError("u", 502, "x", {}, None)) == "server-error"
    assert r(urllib.error.HTTPError("u", 404, "x", {}, None)) == "http-error"
    assert r(urllib.error.URLError(socket.timeout())) == "timeout"
    assert r(TimeoutError()) == "timeout"
    assert r(urllib.error.URLError(ConnectionRefusedError())) == "network"
    assert r(json.JSONDecodeError("x", "", 0)) == "bad-response"
    assert r(KeyError("url")) == "error"
    assert r("breaker-open") == "breaker-open" and r("api.example.com refused") == "error"


def test_the_copies_have_not_drifted():
    """The ledger is copied into each standalone hook and the proxy; keep it identical
    apart from _FAILOPEN_FILE, and keep its vocabulary the backend's."""
    import ast
    import inspect

    from app.main import _SCAN_FAIL_REASONS

    def body(f):
        node = ast.parse(inspect.getsource(f)).body[0]
        if ast.get_docstring(node) is not None:
            node.body = node.body[1:]
        return ast.dump(node)

    for fn in ("_failopen_path", "failure_reason", "_failopen_clean", "_failopen_merge",
               "_failopen_read", "_failopen_write", "record_scan_failure",
               "claim_scan_failures", "scan_failures_delivered"):
        assert len({body(getattr(m, fn)) for m in _MODS}) == 1, fn
    for const in ("_FAILOPEN_REASONS", "_FAILOPEN_MAX", "_FAILOPEN_ORPHAN_SECS"):
        assert len({repr(getattr(m, const)) for m in _MODS}) == 1, const
    assert set(claude._FAILOPEN_REASONS) == set(_SCAN_FAIL_REASONS)
    # One ledger per client, so a tally lands on the sensor that failed.
    assert len({m._FAILOPEN_FILE for m in _MODS}) == len(_MODS)


# --- the proxy ----------------------------------------------------------------------------

def test_proxy_scan_failure_is_allowed_recorded_and_reported(monkeypatch):
    monkeypatch.setenv("PALIVANE_TOKEN", "ak_proxy")
    _wire(proxy, monkeypatch, urllib.error.URLError(socket.timeout()))
    v = proxy.scan(_SECRET, "chatgpt.com", url="https://palivane.example")
    assert v["action"] == "allow"                            # unchanged: fail open
    v = proxy.scan_mcp({"method": "tools/call", "tool": "x"}, url="https://palivane.example")
    assert v["action"] == "allow"
    assert _pending(proxy)["reasons"] == {"timeout": 2}

    sent = _wire(proxy, monkeypatch, _ALLOW)
    proxy.scan_mcp({"method": "tools/call", "tool": "x"}, url="https://palivane.example")
    assert sent[0]["scan_failed"]["reasons"] == {"timeout": 2}
    assert "AKIA" not in json.dumps(sent[0]["scan_failed"])
    proxy.scan("hello", "chatgpt.com", url="https://palivane.example")
    assert "scan_failed" not in sent[1]
    assert _pending(proxy) == {} and _claims(proxy) == []


def test_proxy_breaker_open_is_counted(monkeypatch):
    monkeypatch.setenv("PALIVANE_TOKEN", "ak_proxy")
    _wire(proxy, monkeypatch, urllib.error.HTTPError("u", 401, "no", {}, None))
    assert proxy.scan("hi", "chatgpt.com", url="https://p.example")["action"] == "allow"
    sent = _wire(proxy, monkeypatch, _ALLOW)
    assert proxy.scan("hi", "chatgpt.com", url="https://p.example")["action"] == "allow"
    assert sent == []                                         # deauthorized: no request
    assert _pending(proxy)["reasons"] == {"auth-rejected": 2}


# --- the backend: stored on the heartbeat, exposed on /api/fleet --------------------------

def _sensor(client, actor, plane):
    for row in client.get("/api/fleet").json()["sensors"]:
        if row["actor"] == actor and row["plane"] == plane:
            return row
    return None


def _key(client):
    return client.post("/api/apikeys", json={"label": "hook"}).json()["token"]


def test_backend_accumulates_the_tally_on_the_sensor(client, raw_client):
    key, now = _key(client), int(time.time())
    hdr = {"X-Palivane-Token": key, "User-Agent": "palivane-cursor-hook/1.3.0 (cursor/1.5.2)"}
    body = {"content": "hello", "tool": "cursor", "destination": "cursor", "user": "sam@acme.com"}
    r = raw_client.post("/api/ingest/ai-usage", headers=hdr, json={
        **body, "scan_failed": {"count": 3, "reasons": {"timeout": 2, "network": 1},
                                "first": now - 3600, "last": now - 60}})
    assert r.status_code == 200 and r.json()["action"] in ("allow", "warn", "block")
    r = raw_client.post("/api/ingest/ai-usage", headers=hdr, json={
        **body, "scan_failed": {"count": 1, "reasons": {"auth-rejected": 1},
                                "first": now - 30, "last": now - 30}})
    assert r.status_code == 200
    row = _sensor(client, "sam@acme.com", "ai-usage")
    assert row["scan_fail_count"] == 4
    assert row["scan_fail_reasons"] == {"timeout": 2, "network": 1, "auth-rejected": 1}
    assert row["first_scan_fail"] < row["last_scan_fail"]
    assert row["client"] == "palivane-cursor-hook"
    fleet = client.get("/api/fleet").json()
    assert fleet["summary"]["failed_open"] == 1


def test_backend_takes_it_on_the_parse_miss_and_mcp_paths(client, raw_client):
    key = _key(client)
    rep = {"count": 1, "reasons": {"server-error": 1}, "first": int(time.time())}
    raw_client.post("/api/ingest/ai-usage", headers={"X-Palivane-Token": key}, json={
        "content": "[palivane parse-miss]", "tool": "codex-cli", "parse_miss": True,
        "user": "d@acme.com", "scan_failed": rep})
    raw_client.post("/api/ingest/mcp", headers={"X-Palivane-Token": key}, json={
        "method": "tools/call", "tool": "Bash", "user": "d@acme.com", "scan_failed": rep})
    assert _sensor(client, "d@acme.com", "ai-usage")["scan_fail_count"] == 1
    assert _sensor(client, "d@acme.com", "mcp")["scan_fail_count"] == 1


@pytest.mark.parametrize("junk", [
    [1, 2], "lots", 7, {"count": 99}, {"reasons": "timeout"},
    {"reasons": {"timeout": -1, "nope": 5, "error": True, "network": 1.5}},
])
def test_a_malformed_report_is_ignored_never_rejected(client, raw_client, junk):
    # A 422 here would be counted by the client as one more failure, forever.
    key = _key(client)
    r = raw_client.post("/api/ingest/ai-usage", headers={"X-Palivane-Token": key}, json={
        "content": "hello", "tool": "x", "user": "j@acme.com", "scan_failed": junk})
    assert r.status_code == 200
    assert _sensor(client, "j@acme.com", "ai-usage")["scan_fail_count"] == 0


def test_client_clocks_are_clamped(client, raw_client):
    key = _key(client)
    raw_client.post("/api/ingest/ai-usage", headers={"X-Palivane-Token": key}, json={
        "content": "hello", "tool": "x", "user": "c@acme.com",
        "scan_failed": {"reasons": {"timeout": 1}, "first": 1, "last": 9e15}})
    row = _sensor(client, "c@acme.com", "ai-usage")
    from datetime import datetime, timedelta
    first, last = (datetime.fromisoformat(row[k]) for k in ("first_scan_fail", "last_scan_fail"))
    assert last <= datetime.utcnow() + timedelta(seconds=5)
    assert first >= datetime.utcnow() - timedelta(days=31)


# --- end to end: a real hook against the real backend ------------------------------------

def test_end_to_end_the_console_shows_what_the_hook_could_not_scan(
        client, raw_client, monkeypatch, capsys):
    key = client.post("/api/apikeys", json={"label": "laptop"}).json()["token"]
    cfg = {**_CFG, "token": key, "user": "pilot@acme.com"}
    monkeypatch.setattr(claude, "read_config", lambda: dict(cfg))
    event = {"hook_event_name": "UserPromptSubmit", "prompt": "tidy the build dir", "cwd": "/w"}
    down = {"on": True}

    def urlopen(req, timeout=None):
        if down["on"]:
            raise urllib.error.URLError(ConnectionRefusedError())
        path = req.full_url.split("palivane.example", 1)[1]
        r = raw_client.post(path, content=req.data, headers=dict(req.header_items()))
        if r.status_code >= 400:
            raise urllib.error.HTTPError(req.full_url, r.status_code, "", {}, None)
        return _Resp(r.content)

    monkeypatch.setattr(claude.urllib.request, "urlopen", urlopen)

    def drive():
        monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(event)))
        return claude.main()

    assert drive() == 0 and drive() == 0                     # backend down: let through
    capsys.readouterr()
    assert _sensor(client, "pilot@acme.com", "ai-usage") is None
    down["on"] = False
    assert drive() == 0                                       # back: the tally rides along
    row = _sensor(client, "pilot@acme.com", "ai-usage")
    assert row["scan_fail_count"] == 2 and row["scan_fail_reasons"] == {"network": 2}
    assert row["client"] == "palivane-hook" and row["client_version"] == claude.VERSION
    assert row["health"] == "fresh"
    assert _pending(claude) == {}


def test_a_sensor_that_never_gets_through_ages_into_stale_and_dark(client, db_factory):
    """If the backend stays unreachable the tally is never delivered: the console's
    existing last-seen buckets and the gone-dark alert are what cover that case."""
    from datetime import datetime, timedelta

    from app.alerts import _DARK_AFTER_HOURS
    from app.models import SensorHeartbeat, Tenant
    db = db_factory()
    t = db.query(Tenant).filter(Tenant.slug == "acme").one()
    now = datetime.utcnow()
    for actor, h in (("a@acme.com", 30), ("b@acme.com", _DARK_AFTER_HOURS + 1)):
        db.add(SensorHeartbeat(tenant_id=t.id, actor=actor, plane="ai-usage", tool="claude-code",
                               first_seen=now - timedelta(days=9), last_seen=now - timedelta(hours=h),
                               count=1))
    db.commit()
    db.close()
    health = {r["actor"]: r["health"] for r in client.get("/api/fleet").json()["sensors"]}
    assert health == {"a@acme.com": "stale", "b@acme.com": "dark"}
