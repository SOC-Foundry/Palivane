"""The tool call a model asks for in its response is checked in every gateway mode
(security review M6): recorded after a monitor-mode stream ends, buffered and checked when
the agent's role enforces, and read from Gemini SSE bodies too. Inert commands."""
from __future__ import annotations

import json

from app import gateway as g

P = g.Principal(1, "dev@acme.example")


def _anthropic_sse(name: str, args: dict) -> bytes:
    events = [
        {"type": "content_block_start", "index": 0,
         "content_block": {"type": "tool_use", "id": "t1", "name": name, "input": {}}},
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "input_json_delta", "partial_json": json.dumps(args)}},
        {"type": "content_block_stop", "index": 0},
    ]
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()


def test_monitor_stream_records_the_tool_call_afterwards(monkeypatch):
    calls = []
    monkeypatch.setattr(g, "_capture_tool_activity",
                        lambda name, args, tool, principal, db, tools=None, shell_command="": calls.append((name, args)))
    g._record_stream_tool_use(_anthropic_sse("run_shell", {"command": "ls -la"}), "claude-code", P)
    assert calls and calls[0][0] == "run_shell" and "ls -la" in calls[0][1]


def test_stream_without_a_tool_call_records_nothing(monkeypatch):
    calls = []
    monkeypatch.setattr(g, "_capture_tool_activity", lambda *a, **k: calls.append(a))
    g._record_stream_tool_use(b'data: {"type":"message_stop"}\n\n', "x", P)
    assert calls == []


def test_role_enforcement_buffers_streams(monkeypatch):
    import app.authz as authz
    agent = g.Principal(1, "ci-bot", agent="ci-bot")
    monkeypatch.setattr(authz, "role_context", lambda db, tid, name: ({"allow": []}, True))
    assert g._role_enforces(agent, None) is True
    monkeypatch.setattr(authz, "role_context", lambda db, tid, name: ({"allow": []}, False))
    assert g._role_enforces(agent, None) is False
    assert g._role_enforces(P, None) is False                  # not an agent


def test_gemini_sse_body_yields_the_function_call():
    chunk = {"candidates": [{"content": {"role": "model", "parts": [
        {"functionCall": {"name": "run_shell", "args": {"command": "ls"}}}]}}]}
    body = f"data: {json.dumps(chunk)}\r\n\r\n".encode()
    try:
        json.loads(body)
        raise AssertionError("an SSE body is not JSON")
    except ValueError:
        pass
    called = g._gemini_response_call(list(g._sse_json(body.decode())))
    assert called and called["tool"] == "run_shell"
