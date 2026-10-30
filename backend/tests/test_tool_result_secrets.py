"""A confirmed secret in what a tool returned is stopped before it reaches the model.

QA (H5): the gateway scanned the latest tool_result but only blocked it on an agent role
denial or in enforce mode, so in monitor mode a tool that read `.env` handed the model the
key, breaking "confirmed leaks always block". Inference-hook prompt frames skipped
tool_result blocks altogether. Credential-shaped values are built at runtime.
"""

from __future__ import annotations

from app import inference_hooks as ih
from app.gateway import GatewayPolicy, _agentic_block, _inbound_agentic_block
from app.models import Tenant


def _aws_key() -> str:
    return "AKIA" + "".join("QWERTYUIOPASDFGH"[(i * 7) % 16] for i in range(16))


def _anthropic_body(result: str) -> dict:
    return {"model": "claude-x", "max_tokens": 16, "messages": [
        {"role": "user", "content": "check the config"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "Read",
                                           "input": {"file_path": "/repo/.env"}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1",
                                      "content": result}]},
    ]}


def _monitor(db_factory):
    db = db_factory()
    t = db.query(Tenant).filter(Tenant.slug == "acme").one()
    t.gateway_enforce = False
    tid = t.id
    db.commit(); db.close()
    return tid


def test_gateway_blocks_a_secret_in_a_tool_result_in_monitor_mode(client, db_factory):
    _monitor(db_factory)
    r = client.post("/v1/messages", json=_anthropic_body(f"AWS_ACCESS_KEY_ID={_aws_key()}\n"))
    assert r.status_code in (400, 403), r.status_code
    assert _aws_key() not in r.text


def test_gateway_lets_an_ordinary_tool_result_through(client, db_factory):
    _monitor(db_factory)
    r = client.post("/v1/messages", json=_anthropic_body("DEBUG=true\nPORT=8080\n"))
    assert r.status_code not in (400, 403), r.text[:200]


def test_inbound_rule_adds_confirmed_leaks_only():
    mon = GatewayPolicy(enforce=False, block_severity="high")
    leak = {"severity": "high", "confirmed_leak": True, "signals": []}
    noisy = {"severity": "high", "confirmed_leak": False, "signals": []}
    assert _inbound_agentic_block(leak, mon) and not _agentic_block(leak, mon)
    assert not _inbound_agentic_block(noisy, mon)
    assert not _inbound_agentic_block(None, mon)
    assert _inbound_agentic_block({**noisy, "authz_block": True}, mon)


def test_latest_tool_results_reads_only_the_latest_turn():
    msgs = [
        {"role": "user", "content": [{"type": "tool_result", "content": "old result"}]},
        {"role": "assistant", "content": [{"type": "text", "text": "ok"}]},
        {"role": "user", "content": [
            {"type": "tool_result", "content": [{"type": "text", "text": "new result"},
                                                {"type": "image", "source": {"data": "x" * 50}}]},
            {"type": "tool_result", "content": "second"},
            {"type": "text", "text": "the user's words"}]},
    ]
    out = ih.latest_tool_results(msgs)
    assert out == "new result\nsecond"
    assert "the user's words" not in out and "old result" not in out
    assert ih.latest_tool_results([]) == ""


def _frame(result: str) -> dict:
    return {"type": "prompt", "session_id": "s1", "messages": [
        {"role": "user", "content": [{"type": "text", "text": "check the config"}]},
        {"role": "assistant", "content": [{"type": "tool_use", "tool_name": "Read",
                                           "input": {"file_path": "/repo/.env"}}]},
        {"role": "user", "content": [{"type": "tool_result", "content": result}]},
    ]}


def test_inference_hook_prompt_denies_a_secret_in_a_tool_result(client, db_factory):
    from app.main import _inference_hook_prompt
    tid = _monitor(db_factory)
    db = db_factory()
    try:
        v = _inference_hook_prompt(_frame(f"AWS_ACCESS_KEY_ID={_aws_key()}"), tid,
                                   "admin@acme.com", "claude-code", False, db)
        assert v["action"] == "deny" and "tool result" in v["deny_reason"]
        assert _aws_key() not in v["deny_reason"]
        ok = _inference_hook_prompt(_frame("DEBUG=true"), tid, "admin@acme.com",
                                    "claude-code", False, db)
        assert ok["action"] == "allow"
    finally:
        db.close()


# --- the org setting: on by default, off for orgs whose fixtures hold fake vendor keys ------

def test_setting_defaults_on_and_round_trips(client):
    assert client.get("/api/auth/me").json()["tenant"]["block_tool_result_secrets"] is True
    r = client.patch("/api/tenant", json={"block_tool_result_secrets": False})
    assert r.status_code == 200 and r.json()["block_tool_result_secrets"] is False


def test_turned_off_the_gateway_records_but_does_not_stop(client, db_factory):
    _monitor(db_factory)
    client.patch("/api/tenant", json={"block_tool_result_secrets": False})
    r = client.post("/v1/messages", json=_anthropic_body(f"AWS_ACCESS_KEY_ID={_aws_key()}\n"))
    assert r.status_code not in (400, 403)
    assert not _inbound_agentic_block({"severity": "high", "confirmed_leak": True},
                                      GatewayPolicy(False, "high", tool_result_secrets=False))
    # Enforce mode and role denials still apply with it off.
    assert _inbound_agentic_block({"severity": "high", "confirmed_leak": True},
                                  GatewayPolicy(True, "high", tool_result_secrets=False))


def test_turned_off_the_inference_hook_allows(client, db_factory):
    from app.main import _inference_hook_prompt
    tid = _monitor(db_factory)
    client.patch("/api/tenant", json={"block_tool_result_secrets": False})
    db = db_factory()
    try:
        v = _inference_hook_prompt(_frame(f"AWS_ACCESS_KEY_ID={_aws_key()}"), tid,
                                   "admin@acme.com", "claude-code", False, db)
        assert v["action"] == "allow"
    finally:
        db.close()
