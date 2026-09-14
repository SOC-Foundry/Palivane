"""Snowflake Cortex governance connector: prompt extraction from SQL + an end-to-end sync
(mocked Snowflake) that scores literal prompts into findings. The JWT/HTTP layer is not
exercised here — tests mock poll_query_history, the same boundary the other connectors mock."""

from __future__ import annotations

from app import saas_connectors as sc
from app import warehouse_ai as wa


# --- prompt extraction ----------------------------------------------------------------------

def test_extract_literal_prompt():
    calls = wa.extract_cortex_prompts(
        "SELECT AI_COMPLETE('claude-3-5-sonnet', 'my SSN is 123-45-6789')")
    assert len(calls) == 1
    fn, prompt, colbound = calls[0]
    assert fn == "AI_COMPLETE" and not colbound
    assert "123-45-6789" in prompt


def test_extract_legacy_cortex_namespace():
    calls = wa.extract_cortex_prompts("SELECT SNOWFLAKE.CORTEX.SUMMARIZE('the weather is nice')")
    assert calls and calls[0][0] == "SUMMARIZE" and "weather" in calls[0][1]


def test_extract_concat_with_column_is_partial():
    # A literal prefix plus a column: the literal is scored, but the column part is invisible.
    calls = wa.extract_cortex_prompts(
        "SELECT COMPLETE('mistral-large', 'Summarize this: ' || t.notes) FROM t")
    fn, prompt, colbound = calls[0]
    assert "Summarize this:" in prompt and colbound is True


def test_extract_fully_column_bound_has_no_literal():
    calls = wa.extract_cortex_prompts("SELECT AI_COMPLETE('mistral-large', t.notes) FROM t")
    fn, prompt, colbound = calls[0]
    # only the model literal remains as text; the prompt itself came from a column
    assert colbound is True and "123" not in prompt


def test_extract_escaped_quotes_and_no_cortex():
    assert wa.extract_cortex_prompts("SELECT * FROM orders WHERE id = 5") == []
    calls = wa.extract_cortex_prompts("SELECT AI_COMPLETE('m', 'it''s a secret AKIA')")
    assert calls[0][1] == "m\nit's a secret AKIA"


# --- end-to-end sync (mocked Snowflake) -----------------------------------------------------

def _mk_snowflake(client):
    r = client.post("/api/discovery/connectors", json={
        "platform": "snowflake", "label": "prod",
        "credentials": {"account": "acme-xy123", "user": "PALIVANE_RO",
                        "private_key": "-----BEGIN PRIVATE KEY-----\nnot-real\n-----END PRIVATE KEY-----"}})
    assert r.status_code == 200, r.text
    return r.json()


def test_snowflake_sync_scores_prompts_into_findings(client, monkeypatch):
    c = _mk_snowflake(client)
    monkeypatch.setattr(wa, "poll_query_history", lambda creds, since: [
        {"QUERY_ID": "q1", "USER_NAME": "analyst@acme.com", "START_TIME": "2026-09-13 10:00:00",
         "QUERY_TEXT": "SELECT AI_COMPLETE('claude-3-5-sonnet', 'summarize: SSN 123-45-6789')"},
        {"QUERY_ID": "q2", "USER_NAME": "bi@acme.com", "START_TIME": "2026-09-13 10:05:00",
         "QUERY_TEXT": "SELECT AI_COMPLETE('mistral-large', t.notes) FROM customers t"},  # column-bound
        {"QUERY_ID": "q3", "USER_NAME": "bi@acme.com", "START_TIME": "2026-09-13 10:06:00",
         "QUERY_TEXT": "SELECT SUMMARIZE('quarterly revenue was up')"},                  # benign
    ])
    out = client.post(f"/api/discovery/connectors/{c['id']}/sync")
    assert out.status_code == 200, out.text
    body = out.json()
    assert body["queries"] == 3
    assert body["scanned_calls"] == 3           # three Cortex calls seen
    assert body["column_bound"] >= 1            # the AI_COMPLETE(..., column) call
    assert body["findings"] >= 1                # the SSN prompt

    # the SSN finding is attributed to the warehouse user and the cortex destination
    inv = client.get("/api/findings").json()
    ssn = [f for f in inv["findings"] if f.get("sender") == "analyst@acme.com"]
    assert ssn, "expected a finding attributed to the Cortex caller"


# --- Databricks prompt extraction (Model Serving inference-table payloads) ------------------

def test_dbx_extract_chat_last_user_turn():
    req = '{"messages":[{"role":"system","content":"be brief"},' \
          '{"role":"user","content":"my card is 4111 1111 1111 1111"}]}'
    assert "4111 1111 1111 1111" in wa.extract_databricks_prompt(req)


def test_dbx_extract_completions_prompt():
    assert wa.extract_databricks_prompt({"prompt": "leak: AKIAIOSFODNN7EXAMPLE"}) \
        == "leak: AKIAIOSFODNN7EXAMPLE"


def test_dbx_extract_custom_pyfunc_harvests_strings():
    req = {"dataframe_records": [{"text": "SSN 123-45-6789", "id": 7}]}
    assert "123-45-6789" in wa.extract_databricks_prompt(req)


def test_dbx_extract_non_json_falls_back_to_raw():
    assert wa.extract_databricks_prompt("not json but has AKIAIOSFODNN7EXAMPLE").strip() \
        .endswith("AKIAIOSFODNN7EXAMPLE")


def _mk_databricks(client):
    r = client.post("/api/discovery/connectors", json={
        "platform": "databricks", "label": "prod",
        "credentials": {"host": "dbc-abc.cloud.databricks.com", "client_id": "sp-123",
                        "client_secret": "sekret", "warehouse_id": "wh1",
                        "inference_table": "main.ai.payload_logging"}})
    assert r.status_code == 200, r.text
    return r.json()


def test_databricks_sync_scores_inference_payloads(client, monkeypatch):
    c = _mk_databricks(client)
    monkeypatch.setattr(wa, "poll_inference_table", lambda creds, since: [
        {"request": '{"messages":[{"role":"user","content":"summarize: SSN 123-45-6789"}]}',
         "request_time": "2026-09-13 10:00:00"},
        {"request": '{"prompt":"the weather is nice"}', "request_time": "2026-09-13 10:01:00"},
    ])
    out = client.post(f"/api/discovery/connectors/{c['id']}/sync")
    assert out.status_code == 200, out.text
    body = out.json()
    assert body["rows"] == 2 and body["scanned_calls"] == 2
    assert body["findings"] >= 1     # the SSN payload


def _seed_watermark(db_factory, connector_id, value):
    """Give the sync a known starting watermark.

    Without one, `since` falls back to now-minus-24h, so what the watermark does to a fixed
    timestamp depends on the day the suite runs. That is what broke this test: it asserted a
    hardcoded 2026-09-13 11:22:33 became the watermark, which only held while the clock was
    within 24h of it — roughly one day after it was written.
    """
    from app.models import SaasConnector
    db = db_factory()
    row = db.query(SaasConnector).filter_by(id=connector_id).first()
    row.state = {**(row.state or {}), "cortex_since": value}
    db.commit()
    db.close()


def _watermark(db_factory, connector_id):
    from app.models import SaasConnector
    db = db_factory()
    row = db.query(SaasConnector).filter_by(id=connector_id).first()
    mark = (row.state or {}).get("cortex_since")
    db.close()
    return mark


def test_snowflake_sync_advances_watermark(client, db_factory, monkeypatch):
    c = _mk_snowflake(client)
    _seed_watermark(db_factory, c["id"], "2026-09-13 10:00:00")
    monkeypatch.setattr(wa, "poll_query_history", lambda creds, since: [
        {"QUERY_ID": "q1", "USER_NAME": "u@acme.com", "START_TIME": "2026-09-13 11:22:33",
         "QUERY_TEXT": "SELECT AI_COMPLETE('m', 'hello')"}])
    client.post(f"/api/discovery/connectors/{c['id']}/sync")
    assert _watermark(db_factory, c["id"]) == "2026-09-13 11:22:33"


def test_snowflake_watermark_never_moves_backwards(client, db_factory, monkeypatch):
    """The invariant the previous test accidentally asserted the opposite of.

    A row older than the current watermark must leave it alone — re-polling a window that
    returns stale rows must not rewind the cursor and re-scan everything behind it.
    """
    c = _mk_snowflake(client)
    _seed_watermark(db_factory, c["id"], "2026-09-13 12:00:00")
    monkeypatch.setattr(wa, "poll_query_history", lambda creds, since: [
        {"QUERY_ID": "old", "USER_NAME": "u@acme.com", "START_TIME": "2026-09-13 09:00:00",
         "QUERY_TEXT": "SELECT AI_COMPLETE('m', 'hello')"}])
    client.post(f"/api/discovery/connectors/{c['id']}/sync")
    assert _watermark(db_factory, c["id"]) == "2026-09-13 12:00:00"
