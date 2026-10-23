"""The ASK verdict: a tool call in the warn band is put to the developer instead of running
silently.

The server decides. `ask` is set on a tool-call verdict only when the org opted in, the actor
is enforced, and the verdict is a warn: a block is never softened into one, and monitor mode
never interrupts anyone. The hooks only honor the flag: Claude Code, Cursor, Gemini and
Copilot. Codex has no working ask, so there a warn runs."""

from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path

import app.main as main

_CLI = Path(__file__).resolve().parents[2] / "cli"


def _load(name: str, script: str):
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(_CLI / script)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


claude_hook = _load("palivane_hook_ask", "palivane-hook")
cursor_hook = _load("palivane_cursor_hook_ask", "palivane-cursor-hook")

# A novel, unlabeled high-entropy token in a file the agent writes. The heuristic scores it at
# warn level (suspicious), which is the fuzzy band an ASK is for: not certain enough to block.
# Assembled at runtime so no contiguous secret-looking literal sits in the source.
_NOVEL = "kJ8s9dLqW3" + "xZ7vB1nM4c" + "R6tY2uHgF5aP"
FUZZY_WRITE = ("Write", {"file_path": "/tmp/settings.py", "content": f"SECRET_KEY={_NOVEL}"})
DANGEROUS = ("Bash", {"command": "rm -rf /"})
BENIGN = ("Bash", {"command": "ls -la"})


def _key(client, actor="dev@acme.com"):
    return client.post("/api/apikeys", json={"label": "hook", "actor": actor}).json()["token"]


def _patch(client, **fields):
    r = client.patch("/api/tenant", json=fields)
    assert r.status_code == 200, r.text
    return r.json()


def _verdict(raw_client, key, call):
    activity = claude_hook.build_activity(*call)
    r = raw_client.post("/api/ingest/mcp", json=activity, headers={"X-Palivane-Token": key})
    assert r.status_code == 200, r.text
    return r.json()


def _enforce_and_ask(client):
    _patch(client, client_enforce="on", ask_on_warn="on")


def test_the_fuzzy_call_is_a_warn_not_a_block_at_default_thresholds(client, raw_client):
    # The premise the rest relies on: this call lands in the warn band, not above it.
    _patch(client, client_enforce="on")
    v = _verdict(raw_client, _key(client), FUZZY_WRITE)
    assert v["action"] == "warn", v
    assert v["ask"] is False                       # ASK is off until the org opts in


def test_on_asks_for_a_call_in_the_warn_band(client, raw_client):
    _enforce_and_ask(client)
    v = _verdict(raw_client, _key(client), FUZZY_WRITE)
    assert v["action"] == "warn" and v["ask"] is True and v["enforce"] is True


def test_monitor_mode_never_asks(client, raw_client):
    # The org opted in, but this actor is in monitor: nothing interrupts a monitored device.
    _patch(client, client_enforce="off", ask_on_warn="on")
    v = _verdict(raw_client, _key(client), FUZZY_WRITE)
    assert v["action"] == "warn" and v["enforce"] is False
    assert v["ask"] is False


def test_a_block_is_never_softened_into_an_ask(client, raw_client):
    _enforce_and_ask(client)
    v = _verdict(raw_client, _key(client), DANGEROUS)
    assert v["action"] == "block"
    assert v["ask"] is False


def test_a_benign_call_does_not_ask(client, raw_client):
    _enforce_and_ask(client)
    v = _verdict(raw_client, _key(client), BENIGN)
    assert v["action"] == "allow" and v["ask"] is False


def test_raising_the_block_severity_widens_the_ask_band(client, raw_client, monkeypatch):
    # Tool-call scores are mostly 0 or 60+, so at the default block severity (high) the warn
    # band is narrow. Blocking only at critical makes `high` an ask: an MCP server that is
    # not on the allowlist scores high.
    monkeypatch.setattr(main.settings, "mcp_allowed_servers", "mcp.acme.com")
    rogue = ("mcp__rogue__fetch", {"url": "https://x.dev"})
    key = _key(client)
    _enforce_and_ask(client)

    v = _verdict(raw_client, key, rogue)
    assert v["severity"] == "high" and v["action"] == "block" and v["ask"] is False

    _patch(client, mcp_block_severity="critical")
    v = _verdict(raw_client, key, rogue)
    assert v["action"] == "warn" and v["ask"] is True
    assert _verdict(raw_client, key, DANGEROUS)["action"] == "block"   # critical still blocks


def test_inherits_the_global_default_and_a_tenant_can_override_it(client, raw_client, monkeypatch):
    _patch(client, client_enforce="on")
    key = _key(client)
    monkeypatch.setattr(main.settings, "ask_on_warn", True)
    assert _verdict(raw_client, key, FUZZY_WRITE)["ask"] is True        # inherits the global
    _patch(client, ask_on_warn="off")
    assert _verdict(raw_client, key, FUZZY_WRITE)["ask"] is False       # the org says no
    _patch(client, ask_on_warn="inherit")
    assert _verdict(raw_client, key, FUZZY_WRITE)["ask"] is True        # back to the global


def test_a_pilot_user_can_be_asked_while_the_rest_are_not(client, raw_client):
    # Staged rollout rides the existing per-user enforce override: no new knob.
    _patch(client, ask_on_warn="on")
    client.post("/api/policies/overrides",
                json={"scope": "user", "match": "pilot@acme.com",
                      "disabled_checks": [], "enforce": "on"})
    pilot = _verdict(raw_client, _key(client, "pilot@acme.com"), FUZZY_WRITE)
    other = _verdict(raw_client, _key(client, "other@acme.com"), FUZZY_WRITE)
    assert pilot["ask"] is True and other["ask"] is False


def test_the_batch_endpoint_carries_the_flag_per_item(client, raw_client):
    _enforce_and_ask(client)
    items = [claude_hook.build_activity(*c) for c in (FUZZY_WRITE, DANGEROUS, BENIGN)]
    r = raw_client.post("/api/ingest/mcp/batch", json={"items": items},
                        headers={"X-Palivane-Token": _key(client)})
    assert r.status_code == 200, r.text
    assert [v["ask"] for v in r.json()["results"]] == [True, False, False]


def test_the_setting_round_trips_and_is_audited(client):
    # The console reads the tenant from /auth/me; an existing org has not opted in.
    assert client.get("/api/auth/me").json()["tenant"]["ask_on_warn"] is None
    assert _patch(client, ask_on_warn="on")["ask_on_warn"] is True
    assert _patch(client, ask_on_warn="off")["ask_on_warn"] is False
    assert _patch(client, ask_on_warn="inherit")["ask_on_warn"] is None
    r = client.patch("/api/tenant", json={"ask_on_warn": "sometimes"})
    assert r.status_code == 422                                          # not a stance
    entries = client.get("/api/audit", params={"action": "tenant.update"}).json()["entries"]
    assert any(e["detail"].get("ask_on_warn") == "on" for e in entries)


def test_the_hooks_honor_what_the_server_says(client, raw_client):
    # End to end: the hook's own activity mapping in, the hook's own decision out.
    _enforce_and_ask(client)
    key = _key(client)
    asked = _verdict(raw_client, key, FUZZY_WRITE)
    assert claude_hook.should_block(asked, True) is False
    assert claude_hook.should_ask("PreToolUse", asked) is True
    ho = claude_hook.ask_output(asked)["hookSpecificOutput"]
    assert ho["permissionDecision"] == "ask" and "secret_leak" in ho["permissionDecisionReason"]
    assert cursor_hook.should_ask("beforeShellExecution", asked) is True
    assert cursor_hook.should_ask("beforeReadFile", asked) is False

    blocked = _verdict(raw_client, key, DANGEROUS)
    assert claude_hook.should_block(blocked, True) is True
    assert claude_hook.should_ask("PreToolUse", blocked) is False
