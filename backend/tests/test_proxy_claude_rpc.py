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


def _flow(path: str, body: bytes, host: str = "claude.ai", headers: dict | None = None):
    req = types.SimpleNamespace(method="POST", pretty_host=host, path=path, content=body,
                                raw_content=body, headers=_Headers({"user-agent": "Mozilla/5.0 Chrome/140", **(headers or {})}))
    return types.SimpleNamespace(request=req, response=None)


@pytest.fixture
def run(monkeypatch):
    """run(path, body) -> (prompts sent to the scanner, flow). The scanner records and allows,
    unless block=True."""
    http = types.ModuleType("mitmproxy.http")
    http.Response = types.SimpleNamespace(make=lambda status, body, headers: ("blocked", status, body))
    pkg = types.ModuleType("mitmproxy")
    pkg.http = http
    monkeypatch.setitem(sys.modules, "mitmproxy", pkg)
    monkeypatch.setitem(sys.modules, "mitmproxy.http", http)

    async def no_hooks():
        return frozenset()
    monkeypatch.setattr(addon, "hooked_tools_async", no_hooks)

    scans: list[str] = []

    def _run(path, body, block=False, host="claude.ai", guard=None, headers=None):
        seen: list[str] = []

        def fake_scan(prompt, destination, tool="", **kw):
            seen.append(prompt)
            scans.append(prompt)
            return {"action": "block" if block else "allow", "risk_score": 60, "severity": "high",
                    "signals": [{"category": "pii_exposure"}]}
        monkeypatch.setattr(addon, "scan", fake_scan)
        guard = guard or addon.PalivaneGuard()
        guard.enforce = True
        flow = _flow(path, body, host, headers)
        flow.guard = guard
        asyncio.run(guard.request(flow))
        return seen, flow
    _run.scans = scans
    return _run


def test_message_is_scanned_as_its_typed_text_only(run):
    seen, _ = run(RPC + "PerformAction", perform_action("my ssn is 078-05-1120"))
    assert seen == ["my ssn is 078-05-1120"]       # no uuid, session id, locale or timezone


def test_a_secret_in_the_message_is_blocked(run):
    seen, flow = run(RPC + "PerformAction", perform_action("AKIA4YTGH2NBQF7XZP3K"), block=True)
    assert seen and "AKIA4YTGH2NBQF7XZP3K" in seen[0]
    assert flow.response[1] == 403            # a Connect error, not the API-shaped 400


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


def test_a_block_is_a_connect_error_the_client_reads_as_final(run):
    import json
    _, flow = run(RPC + "PerformAction", perform_action("my ssn is 078-05-1120"), block=True)
    status, body = flow.response[1], json.loads(flow.response[2])
    assert status == 403 and body["code"] == "permission_denied"
    assert "Blocked by Palivane" in body["message"]


def test_other_hosts_keep_the_api_shaped_refusal(run):
    import json
    _, flow = run("/v1/messages", b'{"messages":[{"role":"user","content":"my ssn is 078-05-1120"}]}',
                  block=True, host="api.anthropic.com")
    assert flow.response[1] == 400 and json.loads(flow.response[2])["type"] == "error"


def test_a_retry_of_a_stopped_send_is_answered_without_scanning_again(run):
    """claude.ai retries a send it was told failed, on a backoff; each retry used to be scanned
    again and counted as another sighting for as long as the app kept trying."""
    body = lambda: perform_action("my ssn is 078-05-1120")            # new message ids every time
    seen, first = run(RPC + "PerformAction", body(), block=True)
    assert len(seen) == 1 and first.response[1] == 403
    for _ in range(7):
        again, flow = run(RPC + "PerformAction", body(), block=True, guard=first.guard)
        assert again == [], "a retry of the same text was scanned again"
        assert flow.response[1] == 403 and flow.response[2] == first.response[2]
    assert len(run.scans) == 1


def test_new_words_are_scanned_and_the_quiet_window_expires(run, monkeypatch):
    seen, first = run(RPC + "PerformAction", perform_action("my ssn is 078-05-1120"), block=True)
    seen, flow = run(RPC + "PerformAction", perform_action("my other ssn is 219-09-9999"), block=True, guard=first.guard)
    assert len(seen) == 1                                  # different text: a new send, scanned
    real = addon.time.time
    monkeypatch.setattr(addon.time, "time", lambda: real() + 3600)
    seen, flow = run(RPC + "PerformAction", perform_action("my ssn is 078-05-1120"), block=True, guard=first.guard)
    assert len(seen) == 1                                  # an hour later it is checked again


def test_an_openai_responses_list_input_is_scanned_and_blocked(run):
    import json
    body = json.dumps({"model": "gpt-5-codex", "input": [
        {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "earlier 078-05-1120"}]},
        {"type": "reasoning", "encrypted_content": "gAAAAABopaque"},
        {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "key AKIA4YTGH2NBQF7XZP3K"}]},
    ]}).encode()
    seen, flow = run("/v1/responses", body, block=True, host="api.openai.com")
    assert seen == ["key AKIA4YTGH2NBQF7XZP3K"]          # latest turn only, no history, no reasoning
    assert flow.response[1] == 400


def test_a_coached_secret_verdict_blocks_the_send(run, monkeypatch):
    """With coaching on, the backend answers a confirmed secret with warn + redacted_content. The
    proxy cannot coach, so the original must not go upstream."""
    seen = []

    def coached_scan(prompt, destination, tool="", **kw):
        seen.append(prompt)
        return {"action": "warn", "force_block": False, "coached": True, "enforce": False,
                "redacted_content": "key [REDACTED]", "risk_score": 90, "severity": "critical",
                "signals": [{"category": "secret_leak", "title": "AWS access key"}]}
    guard = addon.PalivaneGuard()
    run("/v1/messages", b"{}", host="api.anthropic.com", guard=guard)    # installs the mitmproxy stub
    monkeypatch.setattr(addon, "scan", coached_scan)
    guard.enforce = False
    flow = _flow("/v1/messages", b'{"messages":[{"role":"user","content":"key AKIA4YTGH2NBQF7XZP3K"}]}',
                 "api.anthropic.com")
    asyncio.run(guard.request(flow))
    assert seen and flow.response is not None and flow.response[1] == 400


# -- compressed Connect envelopes (flag byte 1, codec in connect-content-encoding) ----------------
def compressed_frame(payload: bytes) -> bytes:
    return b"\x01" + len(payload).to_bytes(4, "big") + payload


def _ledger(tmp_path) -> dict:
    import json
    p = tmp_path / "scan-failed-proxy.json"
    return json.loads(p.read_text()) if p.exists() else {}


def test_a_gzip_compressed_send_is_decoded_and_blocked(run, monkeypatch, tmp_path):
    import gzip
    monkeypatch.setenv("PALIVANE_STATE_DIR", str(tmp_path))
    body = compressed_frame(gzip.compress(perform_action("my key AKIA4YTGH2NBQF7XZP3K")))
    seen, flow = run(RPC + "PerformAction", body, block=True,
                     headers={"connect-content-encoding": "gzip"})
    assert seen == ["my key AKIA4YTGH2NBQF7XZP3K"]       # the typed text, not the gzip bytes
    assert flow.response[1] == 403
    assert _ledger(tmp_path) == {}                       # read fine: not a scan failure


def test_a_gzip_envelope_without_the_header_is_recognised_by_its_magic():
    import gzip
    body = compressed_frame(gzip.compress(perform_action("my ssn is 078-05-1120")))
    assert addon.claude_rpc_text(body) == "my ssn is 078-05-1120"


def test_a_zstd_compressed_send_is_decoded():
    zstd = pytest.importorskip("compression.zstd")
    body = compressed_frame(zstd.compress(perform_action("my ssn is 078-05-1120")))
    assert addon.claude_rpc_text(body, "zstd") == "my ssn is 078-05-1120"


def test_a_brotli_compressed_send_is_decoded():
    brotli = pytest.importorskip("brotli")
    body = compressed_frame(brotli.compress(perform_action("my ssn is 078-05-1120")))
    assert addon.claude_rpc_text(body, "br") == "my ssn is 078-05-1120"


def test_an_oversize_decompressed_send_is_unreadable(run, monkeypatch, tmp_path):
    import gzip
    monkeypatch.setenv("PALIVANE_STATE_DIR", str(tmp_path))
    huge = perform_action("x" * (addon._CONNECT_DECOMPRESSED_CAP + 10))
    body = compressed_frame(gzip.compress(huge))
    assert len(body) < 100_000                           # small on the wire, huge inflated
    assert addon.claude_rpc_text(body, "gzip") is None
    seen, flow = run(RPC + "PerformAction", body, block=True,
                     headers={"connect-content-encoding": "gzip"})
    assert seen == [] and flow.response is None          # not scanned as garbage; fails open…
    assert _ledger(tmp_path)["reasons"] == {"error": 1}  # …and is counted, not silent


def test_an_unknown_codec_or_corrupt_data_is_unreadable(run, monkeypatch, tmp_path):
    import gzip
    monkeypatch.setenv("PALIVANE_STATE_DIR", str(tmp_path))
    good = gzip.compress(perform_action("my ssn is 078-05-1120"))
    assert addon.claude_rpc_text(compressed_frame(good), "snappy") is None
    assert addon.claude_rpc_text(compressed_frame(good[:-6]), "gzip") is None    # truncated
    assert addon.claude_rpc_text(compressed_frame(b"not gzip at all"), "gzip") is None
    seen, flow = run(RPC + "PerformAction", compressed_frame(good), block=True,
                     headers={"connect-content-encoding": "snappy"})
    assert seen == [] and flow.response is None
    assert _ledger(tmp_path)["reasons"] == {"error": 1}
