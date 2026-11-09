"""Correlation chains are an agent's sequence. A person's own chat prompts (a pasted key, the
word 'exfiltrate') do not make an attack chain on their own; an agent's tool calls do."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app import session_correlation as sc
from app.models import Finding

ACTOR = "dev@acme.com"
SECRET = {"category": "secret_leak", "detector": "shadow_ai", "title": "Credentials/secrets in outbound content",
          "weight": 0.9, "confidence": 0.9}
EXFIL_PHRASE = {"category": "data_exfiltration", "detector": "prompt_threats",
                "title": "System-prompt / data exfiltration attempt", "weight": 0.8, "confidence": 0.8}
SECRET_IN_IO = {"category": "data_exfiltration", "detector": "prompt_threats",
                "title": "Credential/secret present in LLM I/O", "weight": 0.85, "confidence": 0.8}
SENSITIVE_READ = {"category": "sensitive_resource_access", "detector": "mcp_guard",
                  "title": "Access to a sensitive resource", "weight": 0.9, "confidence": 0.9}
COMMAND = {"category": "dangerous_command", "detector": "mcp_guard",
           "title": "High-risk command in a tool call", "weight": 0.95, "confidence": 0.9}


@pytest.fixture(autouse=True)
def _correlation_on(monkeypatch):
    # conftest turns correlation off for every test; this file is about it.
    monkeypatch.setattr("app.config.settings.session_correlation", True)


def test_a_secret_in_a_prompt_is_collection():
    assert sc.stages_in([SECRET_IN_IO]) == {"collection"}       # the secret, not an egress
    assert sc.stages_in([EXFIL_PHRASE]) == {"exfiltration"}     # an instruction to send data out


def _tenant(client):
    me = client.get("/api/auth/me").json()
    return me["user"].get("tenant_id") or me["tenant"]["id"]


def _add(db, tenant_id, surface, signals):
    now = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
    db.add(Finding(tenant_id=tenant_id, sender=ACTOR, surface=surface, channel="t", signals=signals,
                   severity="high", risk_score=70, status="open", created_at=now, last_seen=now))
    db.commit()


def test_a_persons_chat_prompts_alone_are_not_a_chain(client, db_factory):
    tid = _tenant(client)
    db = db_factory()
    try:
        _add(db, tid, "ai_usage", [SECRET])            # pasted a key into a chat
        _add(db, tid, "ai_usage", [EXFIL_PHRASE])      # wrote about exfiltration in another
        _add(db, tid, "ai_usage", [SECRET_IN_IO])
        assert sc.correlate(db, tid, ACTOR) is None
    finally:
        db.close()


def test_an_agents_actions_still_make_a_chain(client, db_factory):
    tid = _tenant(client)
    db = db_factory()
    try:
        _add(db, tid, "agent_tools", [SENSITIVE_READ])  # the agent read credentials
        _add(db, tid, "agent_tools", [COMMAND])         # then ran a high-risk command
        assert sc.correlate(db, tid, ACTOR) is not None
    finally:
        db.close()


def test_a_prompt_can_still_be_a_link_in_an_agent_chain(client, db_factory):
    tid = _tenant(client)
    db = db_factory()
    try:
        _add(db, tid, "ai_usage", [SECRET])             # the secret in the conversation
        _add(db, tid, "agent_tools", [COMMAND])         # and the agent acting on it
        assert sc.correlate(db, tid, ACTOR) is not None
    finally:
        db.close()
