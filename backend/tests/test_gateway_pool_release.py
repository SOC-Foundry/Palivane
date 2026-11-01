"""The gateway gives its DB connection back before calling the model (gateway._release_db).

Prod runs a small pool per instance (deploy.sh: 2 + 1) because the database caps connections.
A model call takes 10-120s; a handler that held its connection across it would let a few
concurrent turns starve every other request on the instance. Each endpoint below drives a
real request into a fake upstream that records how many of the test DB's connections are
checked out at the moment the upstream call starts: it must be none.
"""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event

import app.gateway as gw
from app.main import app
from app.models import ApiKey, Tenant
from app.security import generate_api_key

OPENAI = {"id": "c", "object": "chat.completion", "model": "gpt-4o",
          "choices": [{"index": 0, "finish_reason": "stop",
                       "message": {"role": "assistant", "content": "hello"}}],
          "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
RESPONSES = {"id": "r", "object": "response", "model": "gpt-4o", "status": "completed",
             "output": [{"type": "message", "role": "assistant",
                         "content": [{"type": "output_text", "text": "hello"}]}]}
ANTHROPIC = {"id": "m", "type": "message", "role": "assistant", "model": "claude-sonnet-5-5",
             "content": [{"type": "text", "text": "hello"}], "stop_reason": "end_turn",
             "usage": {"input_tokens": 1, "output_tokens": 1}}
GEMINI = {"candidates": [{"content": {"role": "model", "parts": [{"text": "hello"}]},
                          "finishReason": "STOP", "index": 0}]}


class _Resp:
    def __init__(self, body):
        self.status_code = 200
        self.headers = {"content-type": "application/json"}
        self._body = body
        self.content = json.dumps(body).encode()

    def json(self):
        return self._body

    def iter_bytes(self):
        yield b"data: " + self.content + b"\n\n"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def harness(db_factory, monkeypatch):
    Session = db_factory
    engine = Session.kw["bind"]
    out = {"n": 0}
    event.listen(engine.pool, "checkout", lambda *a: out.__setitem__("n", out["n"] + 1))
    event.listen(engine.pool, "checkin", lambda *a: out.__setitem__("n", out["n"] - 1))
    seen: list[int] = []
    body = {"v": OPENAI}

    class _Client:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, *a, **k):
            seen.append(out["n"])
            return _Resp(body["v"])

        def stream(self, *a, **k):
            seen.append(out["n"])
            return _Resp(body["v"])

    monkeypatch.setattr(gw, "safe_client", lambda *a, **k: _Client())
    monkeypatch.setattr(gw, "resolve_upstream", lambda *a, **k: ("https://upstream.test", "k"))

    db = Session()
    t = Tenant(slug="poolco", name="Pool Co")
    db.add(t)
    db.commit()
    token, prefix, digest = generate_api_key()
    db.add(ApiKey(tenant_id=t.id, prefix=prefix, token_hash=digest, scope="ingest"))
    db.commit()
    db.close()
    return TestClient(app), token, seen, body


@pytest.mark.parametrize("path,payload,reply,auth", [
    ("/v1/chat/completions",
     {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}, OPENAI, "bearer"),
    ("/v1/chat/completions",
     {"model": "gpt-4o", "stream": True, "messages": [{"role": "user", "content": "hi"}]},
     OPENAI, "bearer"),
    ("/v1/responses", {"model": "gpt-4o", "input": "hi"}, RESPONSES, "bearer"),
    ("/v1/messages",
     {"model": "claude-sonnet-5-5", "max_tokens": 16,
      "messages": [{"role": "user", "content": "hi"}]}, ANTHROPIC, "x-api-key"),
    ("/v1/messages/count_tokens",
     {"model": "claude-sonnet-5-5", "messages": [{"role": "user", "content": "hi"}]},
     {"input_tokens": 1}, "x-api-key"),
    ("/v1beta/models/gemini-2.5-pro:generateContent",
     {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}, GEMINI, "x-goog-api-key"),
])
def test_no_connection_held_during_upstream_call(harness, path, payload, reply, auth):
    client, token, seen, body = harness
    body["v"] = reply
    headers = ({"Authorization": f"Bearer {token}"} if auth == "bearer" else {auth: token})
    r = client.post(path, json=payload, headers=headers)
    assert r.status_code == 200, r.text[:300]
    assert seen, "the request never reached the upstream (fake not hit)"
    assert seen == [0] * len(seen), f"connections checked out during upstream call: {seen}"
