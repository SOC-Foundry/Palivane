"""Snowflake Cortex governance — agentless, read-only (Phase 1 of warehouse AI governance).

In-warehouse LLM calls (Cortex / AI_* functions) run server-side, so no client traffic exists
to intercept: this polls the platform's own logs after the fact. Each sync reads
ACCOUNT_USAGE.QUERY_HISTORY for Cortex calls newer than a per-connector watermark, extracts
the LITERAL prompt text from the SQL, and scores it through the engine as shadow-AI usage
(surface=ai_usage). Post-hoc MONITORING, not inline blocking (see docs/warehouse-ai-governance.md).

Honest limits: a prompt sourced from a COLUMN (AI_COMPLETE('...', t.col)) is not in the SQL —
only its shape is — so it is counted but not scored; LLM responses are never logged; ~45-min
QUERY_HISTORY latency. No vendor SDK: key-pair (JWT) auth + the Snowflake SQL REST API over
urllib; cryptography (already a dep) signs the JWT.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

# Cortex / AI_* functions whose arguments carry user-authored prompt or input text worth
# scanning for secrets / PII / confidential data. (Embed-only / pure-metadata calls omitted.)
_CORTEX_FN = re.compile(
    r"(?is)\b(?:SNOWFLAKE\.CORTEX\.)?"
    r"(AI_COMPLETE|COMPLETE|AI_CLASSIFY|CLASSIFY_TEXT|AI_FILTER|AI_AGG|AI_SUMMARIZE_AGG|"
    r"SUMMARIZE|EXTRACT_ANSWER|AI_EXTRACT|AI_SENTIMENT|SENTIMENT|AI_TRANSLATE|TRANSLATE)\s*\(")


def _match_paren(s: str, open_idx: int) -> int:
    """Index of the ')' matching the '(' at open_idx, respecting '..'' string literals."""
    depth = 0
    i = open_idx
    n = len(s)
    in_str = False
    while i < n:
        c = s[i]
        if in_str:
            if c == "'":
                if i + 1 < n and s[i + 1] == "'":   # '' escape inside a literal
                    i += 2
                    continue
                in_str = False
        elif c == "'":
            in_str = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _string_literals(argstr: str) -> list[str]:
    """The single-quoted string literals in a SQL arg list, '' un-escaped to '."""
    out: list[str] = []
    i, n = 0, len(argstr)
    while i < n:
        if argstr[i] == "'":
            j = i + 1
            buf: list[str] = []
            while j < n:
                if argstr[j] == "'":
                    if j + 1 < n and argstr[j + 1] == "'":
                        buf.append("'")
                        j += 2
                        continue
                    break
                buf.append(argstr[j])
                j += 1
            out.append("".join(buf))
            i = j + 1
        else:
            i += 1
    return out


def _has_column_ref(argstr: str) -> bool:
    """True if, after removing string literals, an identifier (column/expr) remains — i.e. the
    prompt is (partly) sourced from data, which the SQL text does not contain."""
    stripped = re.sub(r"'(?:[^']|'')*'", "", argstr)
    return bool(re.search(r"[A-Za-z_][A-Za-z0-9_$.]*", stripped))


def extract_cortex_prompts(query_text: str) -> list[tuple[str, str, bool]]:
    """(function, literal_prompt, column_bound) for each Cortex/AI_* call in the SQL. The
    literal prompt is the concatenation of the call's string literals (the model-name literal
    is harmless noise for secret/PII scanning); column_bound flags a call that also reads a
    column, so a caller can report the gap instead of silently missing it."""
    out: list[tuple[str, str, bool]] = []
    for m in _CORTEX_FN.finditer(query_text or ""):
        fn = m.group(1).upper()
        open_idx = m.end() - 1
        close = _match_paren(query_text, open_idx)
        if close < 0:
            continue
        args = query_text[open_idx + 1:close]
        prompt = "\n".join(_string_literals(args)).strip()
        out.append((fn, prompt, _has_column_ref(args)))
    return out


# --- Snowflake SQL REST API (key-pair JWT auth) --------------------------------------------

def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def snowflake_jwt(account: str, user: str, private_key_pem: str, passphrase: str = "") -> str:
    """A key-pair JWT for the SQL REST API: iss = ACCOUNT.USER.SHA256:<pubkey-fp>, RS256."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    key = serialization.load_pem_private_key(
        private_key_pem.encode(), password=(passphrase.encode() or None))
    pub_der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(pub_der).digest()).decode()
    acct = account.split(".")[0].upper()      # account locator/name, not the full host
    qual = f"{acct}.{user.upper()}"
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    claims = {"iss": f"{qual}.{fp}", "sub": qual, "iat": now, "exp": now + 3540}
    signing_input = (_b64url(json.dumps(header).encode()) + "." +
                     _b64url(json.dumps(claims).encode())).encode()
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return signing_input.decode() + "." + _b64url(sig)


def snowflake_query(host: str, jwt_token: str, sql: str, timeout: float = 30.0) -> list[dict]:
    """Run one statement via POST /api/v2/statements and return rows as list[dict]."""
    url = f"https://{host}/api/v2/statements"
    body = json.dumps({"statement": sql, "timeout": int(timeout)}).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {jwt_token}",
        "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT",
        "User-Agent": "palivane-warehouse/1.0",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        payload = json.loads(r.read())
    cols = [c["name"] for c in payload.get("resultSetMetaData", {}).get("rowType", [])]
    return [dict(zip(cols, row)) for row in payload.get("data", [])]


# Cortex calls show up in QUERY_HISTORY; scope to statements that name a Cortex/AI_ function so
# we don't pull the whole warehouse's SQL. ~45-min latency, so poll a little behind now().
_POLL_SQL = """
SELECT QUERY_ID, QUERY_TEXT, USER_NAME, START_TIME
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE START_TIME > '{since}'
  AND (QUERY_TEXT ILIKE '%CORTEX.%' OR QUERY_TEXT ILIKE '%AI_COMPLETE%'
       OR QUERY_TEXT ILIKE '%AI_CLASSIFY%' OR QUERY_TEXT ILIKE '%AI_FILTER%'
       OR QUERY_TEXT ILIKE '%AI_AGG%' OR QUERY_TEXT ILIKE '%AI_EXTRACT%'
       OR QUERY_TEXT ILIKE '%AI_SENTIMENT%' OR QUERY_TEXT ILIKE '%AI_TRANSLATE%'
       OR QUERY_TEXT ILIKE '%AI_SUMMARIZE_AGG%')
ORDER BY START_TIME ASC
LIMIT 1000
"""


def poll_query_history(creds: dict, since_iso: str) -> list[dict]:
    """Pull Cortex-bearing queries newer than since_iso. Isolated so tests mock it."""
    host = creds.get("host") or f"{creds['account']}.snowflakecomputing.com"
    jwt_token = snowflake_jwt(creds["account"], creds["user"],
                              creds["private_key"], creds.get("passphrase", ""))
    return snowflake_query(host, jwt_token, _POLL_SQL.format(since=since_iso))


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def scan_snowflake_cortex(db, connector, creds: dict) -> dict:
    """Registry `scan` entry: poll Cortex query history, score each literal prompt, persist
    findings. Advances a per-connector watermark in connector.state. Rules-only (no LLM judge
    — this is a bulk background scan). Returns a summary the connector records."""
    from .detectors.base import AnalysisInput, Surface
    from .service import run_analysis

    state = dict(connector.state or {})
    since = state.get("cortex_since") or (_utcnow() - timedelta(hours=24)).isoformat(sep=" ")
    rows = poll_query_history(creds, since)

    scanned = findings = column_bound = 0
    newest = since
    for r in rows:
        st = str(r.get("START_TIME") or "")
        if st > newest:
            newest = st
        user = r.get("USER_NAME") or ""
        for fn, prompt, colbound in extract_cortex_prompts(r.get("QUERY_TEXT") or ""):
            scanned += 1
            if not prompt:                    # fully column-bound: the data isn't in the SQL
                if colbound:
                    column_bound += 1
                continue
            item = AnalysisInput(
                content=prompt, subject=f"Snowflake Cortex {fn}", sender=user,
                channel="warehouse", surface=Surface.AI_USAGE,
                metadata={"destination": "snowflake-cortex", "tool": "snowflake-cortex",
                          "user": user})
            verdict = run_analysis(item, persist=True, db=db, tenant_id=connector.tenant_id,
                                   use_judge=False)
            if verdict.get("finding_id"):
                findings += 1
            if colbound:
                column_bound += 1     # partial: literal scored, but a column part is invisible

    state["cortex_since"] = newest
    connector.state = state
    return {"scanned_calls": scanned, "findings": findings,
            "column_bound": column_bound, "queries": len(rows)}


# --- Databricks (Model Serving inference tables) --------------------------------------------
#
# Phase 2. Model Serving / ai_query calls run server-side too; the reliable prompt source is
# an AI Gateway INFERENCE TABLE (a UC Delta table logging full request/response payloads,
# customer-enabled per endpoint). We poll it with a read-only service principal (OAuth M2M) via
# the SQL Statement Execution API, extract the prompt from each `request` payload, and score
# it. Honest limits (docs/warehouse-ai-governance.md): inference tables must be pre-enabled
# (else there's nothing to read — system.query.history.statement_text is redacted by default);
# payloads >1 MiB or sampled-out are missed; monitoring, not inline blocking.

def _harvest_strings(obj, out: list[str], budget: int = 60) -> None:
    if len(out) >= budget:
        return
    if isinstance(obj, str):
        if obj.strip():
            out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _harvest_strings(v, out, budget)
    elif isinstance(obj, list):
        for v in obj:
            _harvest_strings(v, out, budget)


def extract_databricks_prompt(request) -> str:
    """The user-authored text from a Model Serving inference-table `request` payload. Handles
    chat (messages), completions/FMAPI (prompt), and custom pyfunc shapes (inputs/dataframe*);
    falls back to harvesting all string values so a proprietary shape is still scanned."""
    if isinstance(request, (bytes, bytearray)):
        request = request.decode("utf-8", "replace")
    if isinstance(request, str):
        try:
            request = json.loads(request)
        except (ValueError, TypeError):
            return request.strip()[:200000]
    if not isinstance(request, dict):
        return ""
    # Chat completions: the last user turn.
    msgs = request.get("messages")
    if isinstance(msgs, list):
        last = ""
        for m in msgs:
            if not isinstance(m, dict) or m.get("role") != "user":
                continue
            c = m.get("content")
            if isinstance(c, str) and c.strip():
                last = c
            elif isinstance(c, list):
                t = "\n".join(b["text"] for b in c
                              if isinstance(b, dict) and isinstance(b.get("text"), str))
                if t.strip():
                    last = t
        if last:
            return last
    # Completions / Foundation Model APIs: prompt (str or list of str).
    p = request.get("prompt")
    if isinstance(p, str) and p.strip():
        return p
    if isinstance(p, list):
        joined = "\n".join(x for x in p if isinstance(x, str))
        if joined.strip():
            return joined
    # Custom pyfunc / batch shapes, then a whole-payload fallback.
    out: list[str] = []
    for key in ("inputs", "dataframe_records", "dataframe_split", "instances", "input"):
        if key in request:
            _harvest_strings(request[key], out)
    if not out:
        _harvest_strings(request, out)
    return "\n".join(out)[:200000]


def databricks_token(host: str, client_id: str, client_secret: str, timeout: float = 30.0) -> str:
    """OAuth M2M token for a service principal (client_credentials, scope=all-apis)."""
    url = f"https://{host}/oidc/v1/token"
    data = urllib.parse.urlencode({"grant_type": "client_credentials",
                                   "scope": "all-apis"}).encode()
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {basic}",
        "User-Agent": "palivane-warehouse/1.0",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())["access_token"]


def databricks_query(host: str, token: str, warehouse_id: str, sql: str,
                     timeout: float = 60.0) -> list[dict]:
    """Run one statement via the SQL Statement Execution API; return rows as list[dict]."""
    url = f"https://{host}/api/2.0/sql/statements"
    body = json.dumps({"statement": sql, "warehouse_id": warehouse_id,
                       "wait_timeout": "30s", "format": "JSON_ARRAY"}).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", "Authorization": f"Bearer {token}",
        "User-Agent": "palivane-warehouse/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        payload = json.loads(r.read())
    cols = [c["name"] for c in
            payload.get("manifest", {}).get("schema", {}).get("columns", [])]
    rows = (payload.get("result") or {}).get("data_array") or []
    return [dict(zip(cols, row)) for row in rows]


# Inference tables carry request_time; a UC-safe identifier for the table is customer-supplied.
_DBX_POLL_SQL = ("SELECT request, request_time FROM {table} "
                 "WHERE request_time > '{since}' ORDER BY request_time ASC LIMIT 1000")


def poll_inference_table(creds: dict, since_iso: str) -> list[dict]:
    """Pull inference-table rows newer than since_iso. Isolated so tests mock it."""
    token = databricks_token(creds["host"], creds["client_id"], creds["client_secret"])
    sql = _DBX_POLL_SQL.format(table=creds["inference_table"], since=since_iso)
    return databricks_query(creds["host"], token, creds["warehouse_id"], sql)


def scan_databricks(db, connector, creds: dict) -> dict:
    """Registry `scan` entry: poll a Databricks inference table, score each request payload's
    prompt, persist findings. Advances a per-connector watermark. Rules-only (no LLM judge)."""
    from .detectors.base import AnalysisInput, Surface
    from .service import run_analysis

    state = dict(connector.state or {})
    since = state.get("dbx_since") or (_utcnow() - timedelta(hours=24)).isoformat(sep=" ")
    rows = poll_inference_table(creds, since)

    scanned = findings = 0
    newest = since
    for r in rows:
        st = str(r.get("request_time") or "")
        if st > newest:
            newest = st
        prompt = extract_databricks_prompt(r.get("request") or "")
        if not prompt.strip():
            continue
        scanned += 1
        item = AnalysisInput(
            content=prompt, subject="Databricks model serving", sender="",
            channel="warehouse", surface=Surface.AI_USAGE,
            metadata={"destination": "databricks", "tool": "databricks"})
        verdict = run_analysis(item, persist=True, db=db, tenant_id=connector.tenant_id,
                               use_judge=False)
        if verdict.get("finding_id"):
            findings += 1

    state["dbx_since"] = newest
    connector.state = state
    return {"scanned_calls": scanned, "findings": findings, "rows": len(rows)}
