"""SIEM forwarding: format builders, severity gating, SSRF guard, config + test endpoint."""

from __future__ import annotations

import json

from app import siem

_VERDICT = {"severity": "high", "risk_score": 75, "finding_id": 7,
            "signals": [{"category": "secret_leak"}, {"category": "pii_exposure"}]}


def _fields():
    return siem._fields(_VERDICT, subject="pasted into ChatGPT", actor="bob@acme.com",
                        surface="ai_usage", org="acme")


# --- format builders ------------------------------------------------------------------

def test_json_format():
    req = siem._request("https://collector/x", "tok", "json", _fields())
    assert req.headers["Authorization"] == "Bearer tok"
    body = json.loads(req.data)
    assert body["product"] == "Palivane" and body["severity"] == "high"
    assert body["categories"] == ["secret_leak", "pii_exposure"] and body["org"] == "acme"


def test_splunk_hec_format():
    req = siem._request("https://hec/x", "hectoken", "splunk_hec", _fields())
    assert req.headers["Authorization"] == "Splunk hectoken"    # HEC scheme
    body = json.loads(req.data)
    # bare default stays the legacy naming — an unset tenant value must never rebrand a sink
    assert body["sourcetype"] == "warden:finding" and body["event"]["risk_score"] == 75


def test_splunk_hec_format_palivane_naming():
    req = siem._request("https://hec/x", "tok", "splunk_hec", _fields(), naming="palivane")
    body = json.loads(req.data)
    assert body["sourcetype"] == "palivane:finding" and body["source"] == "palivane"


def test_cef_format():
    req = siem._request("https://collector/x", "", "cef", _fields())
    assert req.get_header("Content-type") == "text/plain"
    line = req.data.decode()
    assert line.startswith("CEF:0|Palivane|Palivane|1.0|")
    assert "secret_leak" in line and "cn1=75" in line and "suser=bob@acme.com" in line


def test_cef_header_escapes_pipe_no_injection():
    # A subject containing '|' must not forge a new CEF header field.
    f = siem._fields(_VERDICT, subject="pwn|9|extra|CEF:0|evil", actor="a", surface="ai_usage", org="o")
    line = siem._cef(f)
    # The name's pipes must be escaped (\|) so the injection can't forge new CEF fields —
    # it stays a single, contained name field.
    assert "pwn\\|9\\|extra\\|CEF:0\\|evil" in line
    assert "pwn|9" not in line        # no raw unescaped pipe from the injected subject


# --- gating + SSRF --------------------------------------------------------------------

def test_forward_gates_on_severity(monkeypatch):
    sent = []
    monkeypatch.setattr(siem, "send_detail", lambda *a, **k: (sent.append(a) or True, ""))
    # below threshold -> not forwarded
    siem.forward("https://c/x", "", "high", "json",
                 {"severity": "suspicious", "risk_score": 40, "signals": []})
    assert sent == []
    # at threshold -> forwarded (delivery runs on the dispatch pool; join briefly)
    import time
    siem.forward("https://c/x", "", "high", "json", _VERDICT)
    time.sleep(0.1)
    # the pool job called our stub
    assert sent, "expected a forward at/above threshold"


def test_send_sync_ssrf_guard():
    # internal / metadata targets are refused before any request
    assert siem.send_sync("http://169.254.169.254/", "", "json", _fields()) is False
    assert siem.send_sync("http://127.0.0.1:8088/x", "", "json", _fields()) is False
    assert siem.send_sync("", "", "json", _fields()) is False


# --- config + endpoint ----------------------------------------------------------------

def test_siem_config_roundtrip_token_write_only(client):
    t = client.patch("/api/tenant", json={"siem_url": "https://collector.acme.com/in",
                                          "siem_token": "sekret", "siem_format": "splunk_hec",
                                          "siem_min_severity": "suspicious"}).json()
    assert t["siem_url"] == "https://collector.acme.com/in"
    assert t["siem_format"] == "splunk_hec" and t["siem_min_severity"] == "suspicious"
    assert t["siem_token_set"] is True
    assert "siem_token" not in t                       # write-only, never returned


def test_siem_invalid_format_rejected(client):
    r = client.patch("/api/tenant", json={"siem_format": "logstash"})
    assert r.status_code == 400


def test_siem_naming_setting_roundtrip_and_validation(client):
    t = client.patch("/api/tenant", json={"siem_naming": "palivane"}).json()
    assert t["siem_naming"] == "palivane"
    t = client.patch("/api/tenant", json={"siem_naming": "warden"}).json()
    assert t["siem_naming"] == "warden"
    r = client.patch("/api/tenant", json={"siem_naming": "acme"})
    assert r.status_code == 400


def test_siem_test_endpoint_requires_config(client):
    # no SIEM configured on a fresh tenant -> 400
    r = client.post("/api/siem/test")
    assert r.status_code == 400
