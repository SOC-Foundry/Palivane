"""What the gateway's request scan covers beyond the latest user turn: developer
messages, earlier turns it hasn't seen (a client can write any history it likes),
attachments, every parallel tool result, and a partial-scan marker for what it couldn't
read. Seen history is not re-read, so resent conversations don't re-flag. Inert text."""
from __future__ import annotations

import base64

import pytest

from app import gateway as g


@pytest.fixture(autouse=True)
def _fresh_seen():
    g._seen.clear()
    yield
    g._seen.clear()


def _msgs(*pairs):
    return [{"role": r, "content": c} for r, c in pairs]


def test_developer_messages_are_scanned():
    assert "dev note" in g._scan_messages(_msgs(("developer", "dev note"), ("user", "hi")))


def test_without_a_scope_only_the_latest_turn_is_read():
    out = g._scan_messages(_msgs(("user", "older"), ("assistant", "ok"), ("user", "latest")))
    assert "latest" in out and "older" not in out


def test_unseen_history_is_scanned_once_then_not_again():
    msgs = _msgs(("user", "written history"), ("assistant", "ok"), ("user", "latest"))
    s1 = g._ScanScope(1)
    assert "written history" in g._scan_messages(msgs, scope=s1)
    s1.let_through()
    s2 = g._ScanScope(1)
    out = g._scan_messages(msgs + _msgs(("assistant", "ok"), ("user", "next")), scope=s2)
    assert "written history" not in out and "latest" not in out and "next" in out


def test_blocked_content_is_read_again_when_resent_as_history():
    g._scan_messages(_msgs(("user", "was blocked")), scope=g._ScanScope(1))  # never let through
    out = g._scan_messages(_msgs(("user", "was blocked"), ("assistant", "x"), ("user", "retry")),
                           scope=g._ScanScope(1))
    assert "was blocked" in out


def test_seen_history_is_per_tenant():
    msgs = _msgs(("user", "shared text"), ("assistant", "ok"), ("user", "latest"))
    s = g._ScanScope(1)
    g._scan_messages(msgs, scope=s)
    s.let_through()
    assert "shared text" in g._scan_messages(msgs, scope=g._ScanScope(2))


def test_history_past_the_budget_is_marked_and_not_remembered(monkeypatch):
    monkeypatch.setattr(g, "_HISTORY_BUDGET", 10)
    msgs = _msgs(("user", "x" * 50), ("assistant", "ok"), ("user", "latest"))
    s = g._ScanScope(1)
    _, marks = g._outbound_text(g._scan_messages(msgs, scope=s), {"messages": msgs}, s)
    assert [m.evidence for m in marks] == ["history=over budget"]
    s.let_through()
    assert s._key("x" * 50) not in g._seen


def test_anthropic_documents_are_read_and_references_marked():
    doc_b64 = base64.b64encode(b"inline doc body").decode()
    body = {"messages": [{"role": "user", "content": [
        {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "text doc body"}},
        {"type": "document", "title": "n.txt", "source": {"type": "base64", "media_type": "text/plain", "data": doc_b64}},
        {"type": "document", "source": {"type": "file", "file_id": "file_1"}},
        {"type": "text", "text": "see attached"}]}]}
    s = g._ScanScope(1)
    prompt, marks = g._outbound_text(g._scan_messages(body["messages"], scope=s), body, s)
    assert "text doc body" in prompt and "inline doc body" in prompt
    assert [m.evidence for m in marks] == ["file=1 of 3 unread"]


def test_openai_and_responses_file_parts_are_read():
    data = "data:text/plain;base64," + base64.b64encode(b"chat file body").decode()
    chat = {"messages": [{"role": "user", "content": [
        {"type": "file", "file": {"filename": "a.txt", "file_data": data}}]}]}
    resp = {"input": [{"role": "user", "content": [
        {"type": "input_file", "filename": "b.txt", "file_data": data},
        {"type": "input_file", "file_id": "file_2"}]}]}
    p1, m1 = g._outbound_text("", chat, g._ScanScope(1))
    assert "chat file body" in p1 and m1 == []
    g._seen.clear()
    p2, m2 = g._outbound_text("", resp, g._ScanScope(1))
    assert "chat file body" in p2 and [m.evidence for m in m2] == ["file=1 of 2 unread"]


def test_gemini_non_image_inline_data_is_read():
    body = {"contents": [{"role": "user", "parts": [
        {"inline_data": {"mime_type": "text/plain", "data": base64.b64encode(b"gem body").decode()}},
        {"file_data": {"mime_type": "application/pdf", "file_uri": "gs://bucket/x.pdf"}}]}]}
    prompt, marks = g._outbound_text("", body, g._ScanScope(1))
    assert "gem body" in prompt and [m.evidence for m in marks] == ["file=1 of 2 unread"]


def test_every_parallel_openai_tool_result_is_scanned():
    msgs = [{"role": "user", "content": "go"},
            {"role": "assistant", "tool_calls": [
                {"function": {"name": "read", "arguments": "{}"}},
                {"function": {"name": "read", "arguments": "{}"}}]},
            {"role": "tool", "content": "first result"},
            {"role": "tool", "content": "second result"}]
    act = g._agentic_activity({"messages": msgs})
    assert "first result" in act["result_text"] and "second result" in act["result_text"]
    assert act["truncated"] is False


def test_every_parallel_responses_output_is_scanned():
    inp = [{"type": "function_call", "name": "read", "arguments": "{}"},
           {"type": "function_call_output", "output": "out one"},
           {"type": "function_call_output", "output": "out two"}]
    act = g._responses_agentic({"input": inp})
    assert "out one" in act["result_text"] and "out two" in act["result_text"]


def test_long_tool_output_is_flagged_truncated():
    msgs = [{"role": "assistant", "tool_calls": [{"function": {"name": "read", "arguments": "{}"}}]},
            {"role": "tool", "content": "y" * 30000}]
    act = g._agentic_activity({"messages": msgs})
    assert act["truncated"] is True and len(act["result_text"]) == 20000


def test_responses_history_goes_through_the_scope():
    inp = [{"role": "user", "content": "older item"}, {"role": "assistant", "content": "ok"},
           {"role": "user", "content": "latest item"}]
    assert "older item" not in g._responses_user_text(inp)
    assert "older item" in g._responses_user_text(inp, scope=g._ScanScope(1))
