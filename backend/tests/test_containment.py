"""Containment (app/containment.py): an admin stops a person, a device, an agent or the org.

Backend: every capture decision for the target answers a block that clients enforce in any mode,
the gateway refuses its model calls, it ends at its expiry or on release, and both ends are
audited. Clients: each hook and the proxy remember the containment from a real answer and fail
CLOSED while Palivane is unreachable, fail open again once an answer no longer carries it, and
never trust a stale or absurd expiry. Content here is deliberately harmless: containment blocks
regardless of what is sent.
"""
from __future__ import annotations

import io
import json
import time
import urllib.error
from datetime import timedelta

import pytest

from app import containment

_BENIGN = "please summarize the meeting notes in three bullet points"


@pytest.fixture(autouse=True)
def _fresh_cache():
    # Tests reuse tenant ids across their own databases; the cache is per process.
    containment.invalidate()
    yield
    containment.invalidate()


def _key(client, actor="dev@acme.com", label="laptop"):
    r = client.post("/api/apikeys", json={"label": label, "actor": actor})
    assert r.status_code == 200, r.text
    return r.json()


def _prompt(raw_client, token, user=""):
    return raw_client.post("/api/ingest/ai-usage", headers={"X-Palivane-Token": token},
                           json={"content": _BENIGN, "tool": "claude-code",
                                 "destination": "claude-code", "user": user}).json()


def _tool(raw_client, token, user=""):
    return raw_client.post("/api/ingest/mcp", headers={"X-Palivane-Token": token},
                           json={"method": "tools/call", "tool": "Bash",
                                 "args_text": "ls -la", "user": user}).json()


def _contain(client, scope, target="", hours=None, reason="investigating"):
    body = {"scope": scope, "target": target, "reason": reason}
    if hours is not None:
        body["hours"] = hours
    return client.post("/api/containments", json=body)


def test_a_contained_user_is_blocked_on_every_capture_plane_until_released(client, raw_client):
    tok = _key(client)["token"]
    assert _prompt(raw_client, tok)["action"] == "allow"

    r = _contain(client, "user", "Dev@Acme.com")
    assert r.status_code == 200, r.text
    cid = r.json()["id"]

    for v in (_prompt(raw_client, tok), _tool(raw_client, tok)):
        assert v["action"] == "block" and v["force_block"] is True and v["enforce"] is True
        assert v["contained"]["scope"] == "user" and v["contained"]["until"] > time.time()
        # The person is told they were paused, not the security team's reason.
        assert "investigating" not in v["contained"]["message"]

    rows = client.get("/api/containments").json()["containments"]
    assert [c["id"] for c in rows] == [cid] and rows[0]["blocked"] == 2 and rows[0]["active"]

    assert client.post(f"/api/containments/{cid}/release").status_code == 200
    assert _prompt(raw_client, tok)["action"] == "allow"
    assert client.get("/api/containments").json()["containments"] == []
    ended = client.get("/api/containments?all=true").json()["containments"]
    assert ended[0]["released_by"] == "admin@acme.com" and not ended[0]["active"]

    acts = [e["action"] for e in client.get("/api/audit").json()["entries"]]
    assert "containment.create" in acts and "containment.release" in acts


def test_a_shared_key_contains_only_the_person_it_names(client, raw_client):
    tok = _key(client, actor="", label="fleet")["token"]
    _contain(client, "user", "dev@acme.com")
    assert _prompt(raw_client, tok, user="dev@acme.com")["action"] == "block"
    assert _prompt(raw_client, tok, user="other@acme.com")["action"] == "allow"


def test_a_contained_device_is_that_key_only(client, raw_client):
    lap = _key(client, actor="dev@acme.com", label="laptop")
    desk = _key(client, actor="dev@acme.com", label="desktop")
    r = _contain(client, "device", str(lap["id"]))
    assert r.status_code == 200 and r.json()["label"] == "laptop"
    assert _tool(raw_client, lap["token"])["action"] == "block"
    assert _tool(raw_client, desk["token"])["action"] == "allow"


def test_the_org_switch_stops_everything_including_the_gateway(client, raw_client):
    tok = _key(client)["token"]
    assert _contain(client, "org").status_code == 200
    assert _prompt(raw_client, tok)["action"] == "block"
    g = raw_client.post("/v1/messages", headers={"x-api-key": tok},
                        json={"model": "claude-sonnet-4-6", "max_tokens": 16,
                              "messages": [{"role": "user", "content": _BENIGN}]})
    assert g.status_code == 403
    assert g.json()["error"]["type"] == "permission_error"
    assert "Paused by your security team" in g.json()["error"]["message"]


def test_a_contained_user_gets_a_gateway_error_in_each_providers_shape(client, raw_client):
    tok = _key(client)["token"]
    _contain(client, "user", "dev@acme.com")
    oai = raw_client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {tok}"},
                          json={"model": "gpt-4o", "messages": [{"role": "user", "content": _BENIGN}]})
    assert oai.status_code == 403 and oai.json()["error"]["code"] == "contained"
    gem = raw_client.post("/v1beta/models/gemini-2.5-flash:generateContent",
                          headers={"x-goog-api-key": tok},
                          json={"contents": [{"parts": [{"text": _BENIGN}]}]})
    assert gem.status_code == 403 and gem.json()["error"]["status"] == "PERMISSION_DENIED"


def test_a_contained_agent_is_stopped_and_others_are_not(client, raw_client):
    ag = client.post("/api/agents", json={"name": "billing-bot", "kind": "service"}).json()
    other = client.post("/api/agents", json={"name": "support-bot", "kind": "service"}).json()
    assert _contain(client, "agent", "billing-bot").status_code == 200
    assert _tool(raw_client, ag["token"])["action"] == "block"
    assert _tool(raw_client, other["token"])["action"] == "allow"


def test_a_parse_miss_or_batch_from_a_contained_caller_still_answers_block(client, raw_client):
    """The parse-miss and batch shortcuts answer allow; a contained caller must not reach them,
    or the client would read the allow as 'released' and forget the containment."""
    tok = _key(client)["token"]
    _contain(client, "user", "dev@acme.com")
    pm = raw_client.post("/api/ingest/mcp", headers={"X-Palivane-Token": tok},
                         json={"method": "tools/call", "tool": "Bash", "parse_miss": True})
    assert pm.json()["action"] == "block"
    b = raw_client.post("/api/ingest/mcp/batch", headers={"X-Palivane-Token": tok},
                        json={"items": [{"method": "tools/call", "tool": "Bash", "args_text": "ls"},
                                        {"method": "tools/call", "tool": "Read", "args_text": "a"}]})
    assert [r["action"] for r in b.json()["results"]] == ["block", "block"]


def test_a_containment_ends_on_its_own(client, raw_client, db_factory):
    tok = _key(client)["token"]
    cid = _contain(client, "user", "dev@acme.com", hours=1).json()["id"]
    assert _prompt(raw_client, tok)["action"] == "block"
    db = db_factory()
    from app.models import Containment
    row = db.get(Containment, cid)
    row.expires_at = row.created_at - timedelta(seconds=1)
    db.commit()
    db.close()
    containment.invalidate()
    assert _prompt(raw_client, tok)["action"] == "allow"


@pytest.mark.parametrize("body, why", [
    ({"scope": "user", "target": "not-an-email"}, "email"),
    ({"scope": "device", "target": "999999"}, "device"),
    ({"scope": "agent", "target": "no-such-bot"}, "agent"),
])
def test_bad_targets_are_refused(client, body, why):
    r = client.post("/api/containments", json=body)
    assert r.status_code == 400 and why in r.json()["detail"]


def test_duration_is_bounded(client):
    assert _contain(client, "org", hours=0).status_code == 422
    assert _contain(client, "org", hours=721).status_code == 422
    r = _contain(client, "org")
    created, expires = r.json()["created_at"], r.json()["expires_at"]
    from datetime import datetime
    span = datetime.fromisoformat(expires) - datetime.fromisoformat(created)
    assert span == timedelta(hours=containment.DEFAULT_HOURS)


def test_only_an_admin_contains(client, raw_client, db_factory):
    from app import users as users_cli
    db = db_factory()
    users_cli.create_user(db, "acme", "analyst@acme.com", "password123", "analyst")
    db.close()
    tok = raw_client.post("/api/auth/login", json={"email": "analyst@acme.com",
                                                   "password": "password123"}).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    assert raw_client.post("/api/containments", json={"scope": "org"}, headers=h).status_code == 403
    assert raw_client.get("/api/containments", headers=h).status_code == 403


def test_another_orgs_device_cannot_be_contained(client, raw_client, db_factory):
    from app import users as users_cli
    db = db_factory()
    users_cli.create_tenant(db, "globex", "Globex", plan="enterprise")
    users_cli.create_user(db, "globex", "admin@globex.com", "password123", "admin")
    db.close()
    theirs = _key(client)["id"]
    tok = raw_client.post("/api/auth/login", json={"email": "admin@globex.com",
                                                   "password": "password123"}).json()["access_token"]
    r = raw_client.post("/api/containments", json={"scope": "device", "target": str(theirs)},
                        headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 400


# --- clients: fail closed while contained ---------------------------------------------------

from importlib.machinery import SourceFileLoader  # noqa: E402
import importlib.util  # noqa: E402
import sys  # noqa: E402
from pathlib import Path  # noqa: E402

_ROOT = Path(__file__).resolve().parents[2]


def _load(name, path):
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


claude = _load("pv_hook_contain", _ROOT / "cli" / "palivane-hook")
cursor = _load("pv_cursor_contain", _ROOT / "cli" / "palivane-cursor-hook")
codex = _load("pv_codex_contain", _ROOT / "cli" / "palivane-codex-hook")
gemini = _load("pv_gemini_contain", _ROOT / "cli" / "palivane-gemini-hook")
copilot = _load("pv_copilot_contain", _ROOT / "cli" / "palivane-copilot-hook")
sys.path.insert(0, str(_ROOT / "proxy"))
import palivane_addon as proxy  # noqa: E402

# Per hook: an event it checks inline, and how its output says "blocked".
_HOOKS = {
    "claude": (claude, {"hook_event_name": "UserPromptSubmit", "prompt": _BENIGN, "cwd": "/w"}),
    "cursor": (cursor, {"hook_event_name": "beforeSubmitPrompt", "prompt": _BENIGN, "cwd": "/w"}),
    "codex": (codex, {"hook_event_name": "UserPromptSubmit", "prompt": _BENIGN, "cwd": "/w"}),
    "gemini": (gemini, {"hook_event_name": "BeforeAgent", "prompt": _BENIGN, "cwd": "/w"}),
    "copilot": (copilot, {"toolName": "bash", "toolArgs": {"command": "ls -la"}, "cwd": "/w"}),
}
_MODS = [claude, cursor, codex, gemini, copilot, proxy]
# Monitor mode on purpose: containment must block without the device enforcing anything.
_CFG = {"url": "https://palivane.example", "token": "ak_test", "enforce": False,
        "timeout": 1.0, "user": "dev@acme.com", "exclude": []}
_ALLOW = {"action": "allow", "risk_score": 0, "severity": "benign", "signals": []}


class _Resp:
    def __init__(self, body):
        self._b = body

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _wire(mod, monkeypatch, outcome):
    def urlopen(req, timeout=None):
        if isinstance(outcome, BaseException):
            raise outcome
        return _Resp(json.dumps(outcome).encode())
    monkeypatch.setattr(mod.urllib.request, "urlopen", urlopen)


def _drive(mod, monkeypatch, capsys, event):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(event)))
    monkeypatch.setattr(mod, "read_config", lambda: dict(_CFG))
    monkeypatch.setattr(mod, "_send_detached", lambda *a, **k: None)
    rc = mod.main()
    out = capsys.readouterr()
    return rc, out.out.strip() + out.err.strip()


def _contained_answer(hours=1):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return containment.verdict({"id": 1, "scope": "user", "target": "dev@acme.com",
                                "expires_at": now + timedelta(hours=hours)})


def _blocked(rc, out):
    return "Paused by your security team" in out


@pytest.mark.parametrize("name", list(_HOOKS))
def test_a_hook_fails_closed_while_contained_and_open_once_released(name, monkeypatch, capsys):
    mod, event = _HOOKS[name]
    down = urllib.error.URLError("unreachable")

    _wire(mod, monkeypatch, down)                       # never contained: fails open
    assert not _blocked(*_drive(mod, monkeypatch, capsys, event))

    _wire(mod, monkeypatch, _contained_answer())        # contained: blocked, remembered
    assert _blocked(*_drive(mod, monkeypatch, capsys, event))

    _wire(mod, monkeypatch, down)                       # cut off from Palivane: still blocked
    assert _blocked(*_drive(mod, monkeypatch, capsys, event))

    _wire(mod, monkeypatch, _ALLOW)                     # released: the answer clears it
    assert not _blocked(*_drive(mod, monkeypatch, capsys, event))

    _wire(mod, monkeypatch, down)                       # and offline fails open again
    assert not _blocked(*_drive(mod, monkeypatch, capsys, event))


def test_the_claude_hook_checks_tool_calls_inline_while_contained_in_monitor_mode(
        monkeypatch, capsys):
    """Monitor mode posts tool calls in the background; a contained device must not."""
    claude.contained_note(_contained_answer())
    _wire(claude, monkeypatch, urllib.error.URLError("unreachable"))
    rc, out = _drive(claude, monkeypatch, capsys,
                     {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                      "tool_input": {"command": "ls -la"}, "cwd": "/w"})
    assert '"permissionDecision": "deny"' in out and "Paused by your security team" in out


@pytest.mark.parametrize("until", ["past", "too-far", True, "soon"])
def test_a_stale_or_absurd_marker_is_ignored(until):
    import os
    until = {"past": time.time() - 5, "too-far": time.time() + 40 * 86400}.get(until, until)
    path = claude._contained_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        json.dump({"until": until, "message": "x"}, fh)
    assert claude.contained_offline() == {}


def test_the_proxy_fails_closed_while_contained(monkeypatch):
    _wire(proxy, monkeypatch, _contained_answer())
    v = proxy.scan(_BENIGN, "api.anthropic.com")
    assert proxy.should_block(v, False) and "Paused" in proxy.block_message(v)
    _wire(proxy, monkeypatch, urllib.error.URLError("unreachable"))
    v = proxy.scan(_BENIGN, "api.anthropic.com")
    assert proxy.should_block(v, False)
    _wire(proxy, monkeypatch, _ALLOW)
    proxy.scan(_BENIGN, "api.anthropic.com")
    _wire(proxy, monkeypatch, urllib.error.URLError("unreachable"))
    assert not proxy.should_block(proxy.scan(_BENIGN, "api.anthropic.com"), False)


def test_the_copies_have_not_drifted():
    """The containment block is copied into each standalone hook and the proxy."""
    import ast
    import inspect

    def body(f):
        node = ast.parse(inspect.getsource(f)).body[0]
        if ast.get_docstring(node) is not None:
            node.body = node.body[1:]
        return ast.dump(node)

    for fn in ("_contained_path", "contained_note", "contained_offline", "contained_message"):
        assert len({body(getattr(m, fn)) for m in _MODS}) == 1, fn
    for const in ("_CONTAINED_FILE", "_CONTAINED_MAX_SECS"):
        assert len({repr(getattr(m, const)) for m in _MODS}) == 1, const
