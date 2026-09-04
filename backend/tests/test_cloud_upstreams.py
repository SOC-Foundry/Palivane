"""Cloud-contract Claude upstreams (Vertex AI / AWS Bedrock): flavor resolution
precedence, wire transports (URLs, bodies, auth), the synthesized Bedrock SSE burst, and
the /v1/messages forward path end to end with the upstream stubbed."""

from __future__ import annotations

import json

import app.upstreams as up_mod
from app import gateway
from app.upstreams import resolve_anthropic_upstream


BENIGN = {"model": "claude-opus-4-8@20260115", "max_tokens": 64,
          "messages": [{"role": "user", "content": "Explain TCP vs UDP."}]}


def _token(client):
    return client.headers["Authorization"].split(" ", 1)[1]


# --- flavor resolution ---------------------------------------------------------------------

def test_no_config_resolves_none(client, db_factory):
    db = db_factory()
    assert resolve_anthropic_upstream(None, db) is None
    db.close()


def test_anthropic_key_always_wins(client, db_factory, monkeypatch):
    monkeypatch.setattr(up_mod.settings, "gateway_anthropic_key", "sk-ant-x")
    monkeypatch.setattr(up_mod.settings, "gateway_vertex_project", "acme-proj")
    db = db_factory()
    up = resolve_anthropic_upstream(None, db)
    assert up["flavor"] == "anthropic" and up["key"] == "sk-ant-x"
    db.close()


def test_vertex_then_bedrock_precedence(client, db_factory, monkeypatch):
    monkeypatch.setattr(up_mod.settings, "gateway_anthropic_key", "")
    monkeypatch.setattr(up_mod.settings, "gateway_vertex_project", "acme-proj")
    monkeypatch.setattr(up_mod.settings, "gateway_vertex_region", "us-east5")
    monkeypatch.setattr(up_mod.settings, "gateway_bedrock_region", "us-east-1")
    db = db_factory()
    up = resolve_anthropic_upstream(None, db)
    assert up["flavor"] == "vertex" and up["project"] == "acme-proj"
    monkeypatch.setattr(up_mod.settings, "gateway_vertex_project", "")
    up = resolve_anthropic_upstream(None, db)
    assert up["flavor"] == "bedrock" and up["region"] == "us-east-1"
    db.close()


def test_tenant_vertex_blob_over_global(client, db_factory, monkeypatch):
    monkeypatch.setattr(up_mod.settings, "gateway_anthropic_key", "")
    blob = json.dumps({"project": "tenant-proj", "region": "europe-west1",
                       "service_account_json": {"client_email": "sa@t.iam"}})
    r = client.put("/api/upstreams/vertex", json={"base_url": "", "key": blob})
    assert r.status_code == 200, r.text
    from app.models import Tenant
    db = db_factory()
    tid = db.query(Tenant).filter(Tenant.slug == "acme").first().id
    up = resolve_anthropic_upstream(tid, db)
    assert up["flavor"] == "vertex" and up["project"] == "tenant-proj"
    assert up["region"] == "europe-west1"
    assert up["sa_json"]["client_email"] == "sa@t.iam"
    db.close()


# --- transports ----------------------------------------------------------------------------

def _fake_request():
    class R:  # only .headers is read
        headers = {}
    return R()


def test_vertex_transport_urls_and_body(monkeypatch):
    monkeypatch.setattr(up_mod, "vertex_token", lambda sa: "vtok")
    up = {"flavor": "vertex", "project": "acme-proj", "region": "us-east5", "sa_json": None}
    url, body, headers = gateway._anthropic_transport(up, dict(BENIGN), _fake_request(),
                                                      stream=False)
    assert url.endswith("publishers/anthropic/models/claude-opus-4-8%4020260115:rawPredict")
    assert "acme-proj" in url and "us-east5-aiplatform" in url
    assert body["anthropic_version"] == "vertex-2023-10-16"
    assert "model" not in body and "stream" not in body
    assert headers["Authorization"] == "Bearer vtok"

    url, body, _ = gateway._anthropic_transport(up, {**BENIGN, "stream": True},
                                                _fake_request(), stream=True)
    assert url.endswith(":streamRawPredict") and body["stream"] is True


def test_bedrock_transport_bytes_and_bearer(monkeypatch):
    up = {"flavor": "bedrock", "region": "us-east-1", "key": "bedrock-api-key"}
    url, body, headers = gateway._anthropic_transport(
        up, {"model": "us.anthropic.claude-opus-4-8-20260115-v1:0", "max_tokens": 1,
             "stream": True, "messages": []}, _fake_request(), stream=False)
    assert url == ("https://bedrock-runtime.us-east-1.amazonaws.com/model/"
                   "us.anthropic.claude-opus-4-8-20260115-v1%3A0/invoke")
    assert isinstance(body, bytes)                    # SigV4 signs exact bytes
    parsed = json.loads(body)
    assert parsed["anthropic_version"] == "bedrock-2023-05-31"
    assert "model" not in parsed and "stream" not in parsed
    assert headers["Authorization"] == "Bearer bedrock-api-key"


# --- synthesized SSE -----------------------------------------------------------------------

def test_synthesized_sse_is_valid_anthropic_stream():
    data = {"id": "msg_1", "type": "message", "role": "assistant", "model": "claude",
            "stop_reason": "tool_use", "usage": {"input_tokens": 5, "output_tokens": 9},
            "content": [{"type": "text", "text": "hello"},
                        {"type": "tool_use", "id": "tu_1", "name": "bash",
                         "input": {"command": "ls"}}]}
    raw = gateway._synthesize_anthropic_sse(data).decode()
    events = [line.split(": ", 1)[1] for line in raw.splitlines()
              if line.startswith("event: ")]
    assert events[0] == "message_start" and events[-1] == "message_stop"
    assert "content_block_delta" in events and "message_delta" in events
    payloads = [json.loads(line.split(": ", 1)[1]) for line in raw.splitlines()
                if line.startswith("data: ")]
    text = "".join(p["delta"].get("text", "") for p in payloads
                   if p.get("type") == "content_block_delta")
    assert "hello" in text
    tool_json = "".join(p["delta"].get("partial_json", "") for p in payloads
                        if p.get("type") == "content_block_delta")
    assert json.loads(tool_json or "{}").get("command") == "ls"


# --- /v1/messages end to end (upstream stubbed) --------------------------------------------

def test_messages_forwards_via_vertex(client, monkeypatch):
    monkeypatch.setattr(up_mod.settings, "gateway_anthropic_key", "")
    monkeypatch.setattr(up_mod.settings, "gateway_vertex_project", "acme-proj")
    monkeypatch.setattr(up_mod, "vertex_token", lambda sa: "vtok")
    seen = {}

    def fake_post(url, body, headers):
        seen.update(url=url, headers=headers)
        return 200, {"id": "msg_v", "type": "message", "role": "assistant",
                     "model": "claude", "stop_reason": "end_turn",
                     "content": [{"type": "text", "text": "hi from vertex"}],
                     "usage": {"input_tokens": 1, "output_tokens": 2}}

    monkeypatch.setattr(gateway, "_post_upstream_raw", fake_post)
    r = client.post("/v1/messages", json=BENIGN,
                    headers={"x-api-key": _token(client), "Authorization": ""})
    assert r.status_code == 200, r.text
    assert r.json()["content"][0]["text"] == "hi from vertex"
    assert ":rawPredict" in seen["url"] and seen["headers"]["Authorization"] == "Bearer vtok"


def test_messages_bedrock_stream_returns_sse_burst(client, monkeypatch):
    monkeypatch.setattr(up_mod.settings, "gateway_anthropic_key", "")
    monkeypatch.setattr(up_mod.settings, "gateway_vertex_project", "")
    monkeypatch.setattr(up_mod.settings, "gateway_bedrock_region", "us-east-1")
    monkeypatch.setattr(up_mod.settings, "gateway_bedrock_key", "bk")

    def fake_post(url, body, headers):
        assert "/invoke" in url
        return 200, {"id": "msg_b", "type": "message", "role": "assistant",
                     "model": "claude", "stop_reason": "end_turn",
                     "content": [{"type": "text", "text": "hi from bedrock"}],
                     "usage": {"input_tokens": 1, "output_tokens": 2}}

    monkeypatch.setattr(gateway, "_post_upstream_raw", fake_post)
    r = client.post("/v1/messages", json={**BENIGN, "stream": True},
                    headers={"x-api-key": _token(client), "Authorization": ""})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    assert "event: message_start" in r.text and "hi from bedrock" in r.text


def test_messages_no_upstream_still_stubs(client, monkeypatch):
    monkeypatch.setattr(up_mod.settings, "gateway_anthropic_key", "")
    monkeypatch.setattr(up_mod.settings, "gateway_vertex_project", "")
    monkeypatch.setattr(up_mod.settings, "gateway_bedrock_region", "")
    r = client.post("/v1/messages", json=BENIGN,
                    headers={"x-api-key": _token(client), "Authorization": ""})
    assert r.status_code == 200
    assert "no upstream configured" in r.json()["content"][0]["text"]
