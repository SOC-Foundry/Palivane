"""Agentic-browser verification collector: evidence classification + report emission.

Drives proxy/verify_browsers.py the way the field pass does — the synthetic Comet
fixtures stand in for the browser's request/SSE bodies, fake flow/TLS objects stand in
for mitmproxy — and asserts each runbook check lands on the right PASS / PARTIAL /
FAIL / NOT-EXERCISED verdict, including the pinning-signal path (simulated client-TLS
handshake failure)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

_ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("verify_browsers",
                                               _ROOT / "proxy" / "verify_browsers.py")
vb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vb)

_FIXTURES = _ROOT / "proxy" / "fixtures" / "comet"
ASK = "/rest/sse/perplexity_ask"
PPLX = "www.perplexity.ai"


def _collector():
    return vb.EvidenceCollector(platform_name="macOS", date="2026-08-12")


# --- classification: NOT-EXERCISED baseline ---------------------------------------------

def test_fresh_collector_everything_not_exercised():
    # Before the engineer performs any browser action, every check must say so — the
    # report must never claim a PASS for something that never crossed the proxy.
    checks = _collector().checks()
    assert checks  # all runbook checks present
    assert all(c["status"] == vb.NOT_EXERCISED for c in checks.values())


# --- Comet 1c: request/SSE parsing via the addon's own extractors -------------------------

def test_comet_request_fixture_parses_to_pass():
    c = _collector()
    c.see_request(PPLX, ASK, (_FIXTURES / "perplexity_ask_request.json").read_bytes())
    assert c.checks()["comet_1c_request"]["status"] == vb.PASS


def test_comet_request_shape_drift_fails():
    c = _collector()
    c.see_request(PPLX, ASK, json.dumps({"unexpected": {"shape": True}}))
    got = c.checks()["comet_1c_request"]
    assert got["status"] == vb.FAIL and "parse-miss" in got["evidence"]


def test_comet_sse_fixture_parses_to_pass():
    c = _collector()
    c.see_sse_response(PPLX, ASK, (_FIXTURES / "perplexity_ask_response.sse").read_bytes())
    assert c.checks()["comet_1c_sse_response"]["status"] == vb.PASS


def test_comet_sse_shape_drift_fails():
    c = _collector()
    c.see_sse_response(PPLX, ASK, 'data: {"status": 1}\n\n')
    got = c.checks()["comet_1c_sse_response"]
    assert got["status"] == vb.FAIL and "parse-miss" in got["evidence"]


def test_comet_empty_bodies_are_noops():
    # Mirror the addon: an empty body is neither a pass nor a parse-miss.
    c = _collector()
    c.see_request(PPLX, ASK, b"")
    c.see_sse_response(PPLX, ASK, b"")
    checks = c.checks()
    assert checks["comet_1c_request"]["status"] == vb.NOT_EXERCISED
    assert checks["comet_1c_sse_response"]["status"] == vb.NOT_EXERCISED


# --- Comet 1c: pinning signal (client TLS handshake failure) -----------------------------

def test_comet_pinning_tls_failure_fails_with_signature():
    c = _collector()
    c.see_connect(PPLX)
    c.tls_failed(PPLX, "Client TLS handshake failed. The client does not trust the "
                       "proxy's certificate (tlsv1 alert unknown ca)")
    got = c.checks()["comet_1c_pinning"]
    assert got["status"] == vb.FAIL
    assert "pinning" in got["evidence"] and "unknown ca" in got["evidence"]


def test_comet_pinning_clean_interception_passes():
    c = _collector()
    c.see_connect(PPLX)
    c.tls_established(PPLX)
    c.see_request(PPLX, ASK, (_FIXTURES / "perplexity_ask_request.json").read_bytes())
    assert c.checks()["comet_1c_pinning"]["status"] == vb.PASS


# --- Comet 1d: agent WebSocket -----------------------------------------------------------

def test_agent_ws_text_frames_pass():
    c = _collector()
    c.ws_open(PPLX, "/agent")
    c.ws_frame(PPLX, "/agent", b'{"action": "navigate", "url": "https://x.example"}')
    assert c.checks()["comet_1d_agent_ws"]["status"] == vb.PASS


def test_agent_ws_binary_only_is_partial():
    # The runbook's "partial pass": channel-open signal without readable frames.
    c = _collector()
    c.ws_open(PPLX, "/agent")
    c.ws_frame(PPLX, "/agent", b"\x88\x99\xff\xfe")
    got = c.checks()["comet_1d_agent_ws"]
    assert got["status"] == vb.PARTIAL and "binary" in got["evidence"]


def test_agent_ws_other_paths_ignored():
    c = _collector()
    c.ws_open(PPLX, "/agents")            # not the agent channel
    c.ws_open("evil.example", "/agent")   # not perplexity
    assert c.checks()["comet_1d_agent_ws"]["status"] == vb.NOT_EXERCISED


# --- ChatGPT desktop: proxy/trust + parsing ------------------------------------------------

def test_chatgpt_trust_pass_and_pinning_fail():
    ok = _collector()
    ok.see_connect("chatgpt.com")
    ok.tls_established("chatgpt.com")
    assert ok.checks()["chatgpt_proxy_trust"]["status"] == vb.PASS

    pinned = _collector()
    pinned.see_connect("ab.chatgpt.com")
    pinned.tls_failed("ab.chatgpt.com", "tlsv1 alert unknown ca")
    got = pinned.checks()["chatgpt_proxy_trust"]
    assert got["status"] == vb.FAIL and "pinning" in got["evidence"]


def test_chatgpt_parsing_pass_via_extract_prompt():
    c = _collector()
    # The desktop app's conversation shape is the chatgpt.com web shape the addon parses.
    body = json.dumps({"messages": [
        {"author": {"role": "user"}, "content": {"parts": ["marker 4111 1111 1111 1111"]}}]})
    c.see_request("chatgpt.com", "/backend-api/conversation", body)
    assert c.checks()["chatgpt_parsing"]["status"] == vb.PASS


def test_chatgpt_parsing_fails_when_nothing_parses():
    # Telemetry-only traffic means the conversation host/shape was missed — that's a
    # finding for the engineer (possible AI_HOST_SUFFIXES gap), not a silent pass.
    c = _collector()
    c.see_request("chatgpt.com", "/ces/v1/t", json.dumps({"event": "statsig"}))
    assert c.checks()["chatgpt_parsing"]["status"] == vb.FAIL


# --- Dia: host discovery -------------------------------------------------------------------

def test_dia_hosts_listed_for_catalog_followup():
    c = _collector()
    c.see_connect("api.diabrowser.com")
    c.see_connect("api.diabrowser.com")
    c.see_connect("cdn.example.net")      # noise stays out of the Dia verdict
    got = c.checks()["dia_host_capture"]
    assert got["status"] == vb.PASS and "api.diabrowser.com" in got["evidence"]
    fresh = _collector()
    fresh.see_connect("cdn.example.net")
    assert fresh.checks()["dia_host_capture"]["status"] == vb.NOT_EXERCISED


# --- results-table rows: verbatim runbook format -------------------------------------------

def test_results_table_rows_match_runbook_format():
    c = _collector()
    c.see_request(PPLX, ASK, (_FIXTURES / "perplexity_ask_request.json").read_bytes())
    rows = c.results_table_rows()
    names = [r.split("|")[1].strip() for r in rows]
    assert names == ["Comet 1c SSE inspect/pinning", "Comet 1d agent WebSocket",
                     "ChatGPT desktop proxy/trust", "ChatGPT desktop parsing/enforce",
                     "Dia host capture"]
    for r in rows:
        # `| Check | Platform | Date | Result | Notes |` — 5 cells, pipes intact.
        assert r.startswith("| ") and r.endswith(" |") and r.count("|") == 6
    comet_row = rows[0].split("|")
    assert comet_row[2].strip() == "macOS" and comet_row[3].strip() == "2026-08-12"
    # Request leg passed but SSE/pinning weren't exercised — the row must not claim PASS.
    assert comet_row[4].strip() == vb.PARTIAL and "not exercised" in comet_row[5]
    # The enforce leg is manual unless a block was observed — the row says so.
    assert "PALIVANE_PROXY_ENFORCE" in rows[3]


def test_enforce_block_observed_lands_in_notes():
    c = _collector()
    body = json.dumps({"messages": [
        {"author": {"role": "user"}, "content": {"parts": ["AKIAABCDEFGHIJKLMNOP leak"]}}]})
    c.see_request("chatgpt.com", "/backend-api/conversation", body)
    c.saw_block("chatgpt.com")
    row = [r for r in c.results_table_rows() if "parsing/enforce" in r][0]
    assert "1 enforce block(s) observed" in row


# --- report emission ------------------------------------------------------------------------

def test_write_reports_md_and_json(tmp_path):
    c = _collector()
    c.see_request(PPLX, ASK, (_FIXTURES / "perplexity_ask_request.json").read_bytes())
    c.tls_failed("ab.chatgpt.com", "tlsv1 alert unknown ca")
    md_path, json_path = c.write_reports(str(tmp_path))
    md = Path(md_path).read_text()
    # Honest about what's automated, and carries every classification + the paste rows.
    assert "evidence capture" in md and "classification only" in md
    assert "PASS" in md and "FAIL" in md and "NOT-EXERCISED" in md
    assert "| Comet 1c SSE inspect/pinning | macOS | 2026-08-12 |" in md
    assert "ab.chatgpt.com" in md                     # host inventory
    ev = json.loads(Path(json_path).read_text())
    assert ev["addon_version"] == vb.pal.VERSION
    assert ev["checks"]["comet_1c_request"]["status"] == vb.PASS
    assert ev["hosts"]["ab.chatgpt.com"]["tls_failed"] == 1
    assert ev["results_table_rows"]                    # rows also in the raw evidence


# --- the mitmproxy-facing wrapper, driven with fake flow/TLS objects ------------------------

def _flow(host, path, body=b"", method="POST", response=None):
    return SimpleNamespace(
        request=SimpleNamespace(pretty_host=host, path=path, method=method,
                                raw_content=body),
        response=response, metadata={}, websocket=None)


def test_recorder_records_requests_and_teed_sse():
    c = _collector()
    rec = vb.VerificationRecorder(collector=c)
    f = _flow(PPLX, ASK, (_FIXTURES / "perplexity_ask_request.json").read_bytes())
    rec.http_connect(f)
    rec.request(f)
    # The guard's responseheaders tee left its buffer on the flow; the recorder aliases
    # it (the guard pops its own key later) and classifies it once the stream ends.
    f.metadata["palivane_comet_sse"] = [(_FIXTURES / "perplexity_ask_response.sse").read_bytes()]
    rec.responseheaders(f)
    f.metadata.pop("palivane_comet_sse")               # guard's response() pops its key
    rec.response(f)
    checks = c.checks()
    assert checks["comet_1c_request"]["status"] == vb.PASS
    assert checks["comet_1c_sse_response"]["status"] == vb.PASS
    assert c.hosts[PPLX]["connects"] == 1 and c.hosts[PPLX]["requests"] == 1


def test_recorder_tls_hooks_use_sni_and_error():
    c = _collector()
    rec = vb.VerificationRecorder(collector=c)
    data = SimpleNamespace(
        conn=SimpleNamespace(sni=PPLX, error="tlsv1 alert unknown ca"),
        context=SimpleNamespace(server=SimpleNamespace(address=(PPLX, 443))))
    rec.tls_failed_client(data)
    got = c.checks()["comet_1c_pinning"]
    assert got["status"] == vb.FAIL and "unknown ca" in got["evidence"]
    # No SNI -> falls back to the upstream address.
    data2 = SimpleNamespace(conn=SimpleNamespace(sni=None, error=None),
                            context=SimpleNamespace(server=SimpleNamespace(
                                address=("chatgpt.com", 443))))
    rec.tls_established_client(data2)
    assert c.hosts["chatgpt.com"]["tls_ok"] == 1


def test_recorder_websocket_hooks():
    c = _collector()
    rec = vb.VerificationRecorder(collector=c)
    f = _flow(PPLX, "/agent", method="GET")
    f.websocket = SimpleNamespace(messages=[SimpleNamespace(content=b'{"cmd": "click"}')])
    rec.websocket_start(f)
    rec.websocket_message(f)
    assert c.checks()["comet_1d_agent_ws"]["status"] == vb.PASS


def test_recorder_guard_block_counted_not_misclassified():
    # Enforce mode: the guard staged a 400 block before the recorder ran. The block is
    # recorded as evidence, and the (crafted) response body must NOT be classified as a
    # failed SSE parse.
    c = _collector()
    rec = vb.VerificationRecorder(collector=c)
    block = SimpleNamespace(status_code=400,
                            raw_content=b'{"error": {"message": "Blocked by Palivane: ..."}}')
    f = _flow(PPLX, ASK, (_FIXTURES / "perplexity_ask_request.json").read_bytes(),
              response=block)
    rec.request(f)
    f.metadata["palivane_comet_sse"] = [block.raw_content]   # guard tees even its own 400
    rec.responseheaders(f)
    rec.response(f)
    checks = c.checks()
    assert c.blocks[PPLX] == 1
    assert checks["comet_1c_sse_response"]["status"] == vb.NOT_EXERCISED


def test_recorder_done_writes_reports(tmp_path):
    rec = vb.VerificationRecorder(collector=_collector(), out_dir=str(tmp_path))
    rec.done()
    assert (tmp_path / "verification-report.md").exists()
    assert (tmp_path / "verification-report.json").exists()
