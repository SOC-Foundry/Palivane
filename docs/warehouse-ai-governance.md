# Warehouse AI governance — Snowflake Cortex & Databricks

Goal: extend shadow-AI governance to **in-warehouse LLM usage** — the prompts and data sent
to Snowflake Cortex and Databricks-served models, which run *server-side* inside the platform.
The browser extension, gateway, and egress proxy never see these (no client makes the call —
the warehouse does), so the capture model is an **agentless, read-only pull connector** per
platform: poll the platform's own query/usage/payload logs, extract the LLM prompt, score it
through the Palivane engine, and record a finding. Mirrors the existing SaaS connectors
(`saas_connectors.py`), but scores prompts instead of ingesting OAuth grants.

This document is honest about what agentless read-only access **cannot** see, because those
limits shape the product promise.

## Snowflake Cortex

**LLM functions to watch:** `SNOWFLAKE.CORTEX.COMPLETE/SUMMARIZE/EXTRACT_ANSWER/CLASSIFY_TEXT`
and the current `AI_*` family (`AI_COMPLETE`, `AI_CLASSIFY`, `AI_FILTER`, `AI_AGG`,
`AI_EXTRACT`, `AI_SUMMARIZE_AGG`, …), plus Cortex Analyst (NL questions) and Cortex Search.

**Capture (post-hoc, read-only):**
- `SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY.QUERY_TEXT` — the only view exposing prompt content.
  Contains the full SQL including a prompt passed as a **literal**. Truncated at 100K chars;
  **~45-min latency**; 365-day retention.
- `ACCOUNT_USAGE.CORTEX_AI_FUNCTIONS_USAGE_HISTORY` — per-call **metadata only** (function,
  model, user, role, tokens, query_id); ~2–5-min latency. Join on `QUERY_ID` to attribute a
  prompt to model/user/tokens.

**Auth / privileges:** key-pair JWT service account (password sign-in for service users is
being disallowed); grant a read-only role `USAGE_VIEWER` + `GOVERNANCE_VIEWER` (or
`IMPORTED PRIVILEGES` on the SNOWFLAKE db). No warehouse write.

**Hard limits:** a prompt sourced from a **column** (`AI_COMPLETE('...', t.text_col)`) is
invisible — QUERY_TEXT shows only the column reference, never the row value. LLM **responses**
are never logged. No agentless **pre-execution** hook exists (row/masking policies gate
rows/columns, not function calls); real-time governance would need a non-agentless view/UDF
wrapper or app-layer gateway.

## Databricks

**Surfaces:** `ai_query()` + task `ai_*` functions (prompt inline in SQL), Model Serving
endpoints (custom, Foundation Model APIs, external models), Genie/Assistant.

**Capture (post-hoc, read-only):**
- **Inference tables** (AI Gateway) — the real payload source: full **request + response**
  as a Delta table per endpoint in Unity Catalog. Must be **pre-enabled per endpoint** (no
  retroactive capture), 1 MiB/payload cap, configurable sampling, available within minutes.
- `system.serving.endpoint_usage` (+ `served_entities`) — token/usage metadata, no prompt.
- `system.query.history.statement_text` — **`<REDACTED>` by default**; the `ai_query` prompt
  is hidden unless the service principal is in the privileged `databricks_pii_access` group.
- `system.access.audit` — metadata; SQL in `request_params` also omitted unless privileged.

**Auth / privileges:** OAuth M2M service principal; `USE CATALOG/SCHEMA` + `SELECT` on
`system.*` and each inference table.

**Hard limits:** without inference tables enabled (or `databricks_pii_access`), a read-only
connector sees **metadata only, not prompts**. Payloads >1 MiB or sampled-out are missed.
Real-time governance requires routing through Unity AI Gateway (customer-side config).

## The uncomfortable truth (say it in sales)
Agentless read-only gives **post-hoc visibility, not inline blocking**, and only of prompts
the platform actually logs in a readable place:
- Snowflake: literal prompts in QUERY_HISTORY (not column-bound data), ~45-min lag.
- Databricks: only if inference tables are pre-enabled or the SP has `databricks_pii_access`.

That is still valuable (a governance/audit inventory of who ran what AI on what data, scored
for secrets/PII/confidential leakage), but it is **monitoring**, not enforcement. Inline
enforcement on either platform requires customer-side plumbing (a UDF/view wrapper on
Snowflake; AI Gateway guardrails on Databricks) that is out of scope for a read-only connector.

## Connector shape
A new warehouse-LLM connector (distinct from the OAuth-grant SaaS connectors):
1. Stored, encrypted credential (`SaasConnector`-style row; platform = `snowflake` |
   `databricks`).
2. Scheduled sync: query the log views since the last watermark; for each LLM call, extract
   the prompt text; score it via the engine on a `warehouse_ai` surface (or reuse `ai_usage`
   with `destination = snowflake-cortex:<model>` / `databricks:<endpoint>`); create/fold a
   finding with actor = the warehouse user, tokens/model as metadata.
3. Dedup by query_id / request_id so a re-poll doesn't re-flag.
4. Honest coverage reporting: surface "column-bound prompts not visible" / "inference tables
   not enabled on N endpoints" so gaps are visible, not silently missing.

## Phasing
1. **Snowflake Cortex** first — literal-prompt capture from QUERY_HISTORY + usage-view
   enrichment. Cleanest agentless win.
2. **Databricks inference tables** — full payloads where enabled; metadata-only fallback with
   a clear "enable inference tables for prompt capture" nudge.
3. (Later, opt-in) Inline enforcement helpers: a Snowflake UDF/view wrapper and Databricks AI
   Gateway guardrail config — customer-installed, not agentless.
