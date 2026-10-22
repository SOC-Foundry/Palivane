"""Egress proxy vs claude.ai's current send: a Connect RPC with a protobuf body.

claude.ai no longer posts JSON to /completion. A message is
POST /claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/PerformAction with a protobuf
body: the typed text is one string among conversation/message/session uuids, a locale and a
timezone. The same service carries state calls (no text), and the page posts its own telemetry to
the same host. The proxy must scan the typed text, and only that: reading the body as text found
the message but also turned every uuid and every compressed telemetry blob into a "secret"."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
import uuid
import zlib
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "palivane_addon_rpc", Path(__file__).resolve().parents[2] / "proxy" / "palivane_addon.py")
addon = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(addon)

RPC = "/claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/"


# -- a protobuf encoder, enough for the shapes seen on a live claude.ai --------------------------
def _vi(n: int) -> bytes:
    out = bytearray()
    while n > 127:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def _s(field: int, value: str) -> bytes:
    b = value.encode()
    return _vi((field << 3) | 2) + _vi(len(b)) + b


def _m(field: int, payload: bytes) -> bytes:
    return _vi((field << 3) | 2) + _vi(len(payload)) + payload


def _head() -> bytes:
    return _m(1, _m(1, _s(1, "sess_" + uuid.uuid4().hex[:16])) + _s(2, str(uuid.uuid4())) + _s(14, "en-US"))


def perform_action(text: str) -> bytes:
    """The 257-byte message call seen live: ids around the typed text at field .2.3."""
    return _head() + _m(2, _s(1, str(uuid.uuid4())) + _s(2, str(uuid.uuid4())) + _s(3, text)
                        + _s(12, "America/Chicago") + _s(13, "en-US"))


def state_action() -> bytes:
    return _head() + _m(15, b"")


def connect_frame(payload: bytes) -> bytes:
    return b"\x00" + len(payload).to_bytes(4, "big") + payload


def stream_timeline() -> bytes:
    return connect_frame(_s(1, str(uuid.uuid4())) + _s(5, "en-US") + _s(8, "America/Chicago"))


# -- a fake mitmproxy flow, and the addon's request hook run against it ---------------------------
class _Headers(dict):
    def get(self, k, d=""):
        return super().get(k.lower(), d)


def _flow(path: str, body: bytes, host: str = "claude.ai"):
    req = types.SimpleNamespace(method="POST", pretty_host=host, path=path, content=body,
                                raw_content=body, headers=_Headers({"user-agent": "Mozilla/5.0 Chrome/140"}))
    return types.SimpleNamespace(request=req, response=None)


@pytest.fixture
def run(monkeypatch):
    """run(path, body) -> (prompts sent to the scanner, flow). The scanner records and allows,
    unless block=True."""
    http = types.ModuleType("mitmproxy.http")
    http.Response = types.SimpleNamespace(make=lambda status, body, headers: ("blocked", status))
    pkg = types.ModuleType("mitmproxy")
    pkg.http = http
    monkeypatch.setitem(sys.modules, "mitmproxy", pkg)
    monkeypatch.setitem(sys.modules, "mitmproxy.http", http)

    async def no_hooks():
        return frozenset()
    monkeypatch.setattr(addon, "hooked_tools_async", no_hooks)

    def _run(path, body, block=False, host="claude.ai"):
        seen: list[str] = []

        def fake_scan(prompt, destination, tool="", **kw):
            seen.append(prompt)
            return {"action": "block" if block else "allow"}
        monkeypatch.setattr(addon, "scan", fake_scan)
        guard = addon.PalivaneGuard()
        guard.enforce = True
        flow = _flow(path, body, host)
        asyncio.run(guard.request(flow))
        return seen, flow
    return _run


def test_message_is_scanned_as_its_typed_text_only(run):
    seen, _ = run(RPC + "PerformAction", perform_action("my ssn is 078-05-1120"))
    assert seen == ["my ssn is 078-05-1120"]       # no uuid, session id, locale or timezone


def test_a_secret_in_the_message_is_blocked(run):
    seen, flow = run(RPC + "PerformAction", perform_action("AKIA4YTGH2NBQF7XZP3K"), block=True)
    assert seen and "AKIA4YTGH2NBQF7XZP3K" in seen[0]
    assert flow.response == ("blocked", 400)


def test_a_benign_message_scans_only_the_words(run):
    seen, _ = run(RPC + "PerformAction", perform_action("what is the capital of France"))
    assert seen == ["what is the capital of France"]


def test_state_calls_carry_no_text_and_are_not_scanned(run):
    for path, body in [(RPC + "PerformAction", state_action()),
                       (RPC + "StreamTimeline", stream_timeline()),
                       (RPC + "ReportViewing", connect_frame(_s(1, str(uuid.uuid4())))),
                       (RPC + "GetNewConversationDefaults", connect_frame(_s(5, "en-US")))]:
        seen, flow = run(path, body)
        assert seen == [], f"{path.rsplit('/', 1)[1]} was scanned: {seen!r}"
        assert flow.response is None


def test_the_pages_own_compressed_telemetry_is_not_scanned(run):
    blob = zlib.compress(b'{"_dd":{"format_version":2},"session":{"id":"' + uuid.uuid4().bytes.hex().encode() + b'"}}')
    seen, _ = run("/api/v2/rum?ddsource=browser&dd-evp-encoding=deflate", blob)
    assert seen == []


def test_the_old_completion_json_is_still_scanned(run):
    seen, _ = run("/api/organizations/o1/chat_conversations/c1/completion",
                  b'{"prompt": "my ssn is 078-05-1120", "timezone": "UTC"}')
    assert seen == ["my ssn is 078-05-1120"]


def test_a_connect_envelope_is_unwrapped():
    assert addon.claude_rpc_text(connect_frame(perform_action("my ssn is 078-05-1120"))) == "my ssn is 078-05-1120"


def test_a_compressed_envelope_is_reported_not_skipped():
    payload = zlib.compress(perform_action("my ssn is 078-05-1120"))
    assert addon.claude_rpc_text(b"\x01" + len(payload).to_bytes(4, "big") + payload) is None


def test_a_body_that_is_not_protobuf_is_scanned_as_text(run):
    """If claude.ai changes shape the proxy must fall back to the text, not go quiet."""
    seen, _ = run(RPC + "PerformAction", b'{"prompt": "my ssn is 078-05-1120"}')
    assert seen and "078-05-1120" in seen[0]
    seen, _ = run(RPC + "PerformAction", b"my ssn is 078-05-1120, plain text")
    assert seen and "078-05-1120" in seen[0]


def test_a_message_whose_only_text_looks_like_an_id_is_still_a_message():
    # the ids are set aside by shape; a short real word is not lost for being short
    assert addon.claude_rpc_text(perform_action("hello there, 078-05-1120")) == "hello there, 078-05-1120"


def test_other_hosts_are_not_treated_as_claude_rpc():
    assert not addon.is_claude_rpc("example.com", RPC + "PerformAction")
    assert addon.is_claude_rpc("claude.ai", RPC + "PerformAction")
    assert addon.is_claude_rpc_send(RPC + "PerformAction")
    assert not addon.is_claude_rpc_send(RPC + "StreamTimeline")
