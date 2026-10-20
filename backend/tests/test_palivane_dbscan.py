"""palivane-dbscan: what it finds in a real (SQLite) database, what it leaves alone, that nothing but
metadata is reported, how the Postgres adapter reads, and how the server words and folds its findings."""

from __future__ import annotations

import importlib.util
import io
import json
import sqlite3
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

_path = Path(__file__).resolve().parents[2] / "cli" / "palivane-dbscan"
_spec = importlib.util.spec_from_loader("palivane_dbscan", SourceFileLoader("palivane_dbscan", str(_path)))
dbs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dbs)

OPENAI = "sk-" + "proj-" + "abcDEF123456ghiJKL789012mnoPQR"
GHP = "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
AWS = "AK" + "IA" + "4YTGH2NBQF7XZP3K"
SLACK = "xo" + "xb-" + "1234567890-0987654321-AbCdEfGhIjKlMnOpQrStUvWx"
SESSION = "q9Zx3Lm7Rt2VbN8cKw4HsJ6yPd1FgA5e"          # a random bearer value kept in the clear
FERNET = "gAAAAAB" + "k" * 80
BCRYPT = "$2b$12$" + "a" * 53
ALL_SECRETS = (OPENAI, GHP, AWS, SLACK, SESSION)


@pytest.fixture
def sqlite_db(tmp_path):
    path = tmp_path / "app.db"
    c = sqlite3.connect(path)
    c.executescript("""
        CREATE TABLE workspace_credentials (id INTEGER PRIMARY KEY, workspace TEXT, provider TEXT, api_key TEXT);
        CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, session_token TEXT);
        CREATE TABLE vault (id INTEGER PRIMARY KEY, name TEXT, secret TEXT);
        CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT);
        CREATE TABLE events (id INTEGER PRIMARY KEY, payload TEXT);
        CREATE TABLE settings (id INTEGER PRIMARY KEY, api_key_expires_at TEXT, token_count TEXT, label TEXT);
    """)
    c.executemany("INSERT INTO workspace_credentials VALUES (?,?,?,?)",
                  [(1, "w1", "openai", OPENAI), (2, "w2", "github", GHP)])
    c.executemany("INSERT INTO users VALUES (?,?,?,?)",
                  [(i, f"u{i}@acme.com", BCRYPT, SESSION[:-2] + f"{i:02d}") for i in range(1, 6)])
    c.executemany("INSERT INTO vault VALUES (?,?,?)", [(1, "a", FERNET), (2, "b", "enc:v2:" + FERNET)])
    c.execute("INSERT INTO notes VALUES (1, ?)", (f"remember the prod key is {AWS} ok",))
    c.execute("INSERT INTO events VALUES (1, ?)", (json.dumps({"hook": SLACK, "n": 3}),))
    c.execute("INSERT INTO settings VALUES (1, '2026-12-01T00:00:00', '12', 'hello world')")
    c.commit()
    c.close()
    return str(path)


def _scan(path, **kw):
    db = dbs.SqliteDB(path)
    try:
        return db, dbs.scan(db, **kw)
    finally:
        pass


def _by_column(result):
    out = {}
    for f in result["findings"]:
        out.setdefault(f["column"], []).append(f["label"])
    return out


def test_it_finds_credentials_stored_in_a_table_and_in_free_text(sqlite_db):
    db, result = _scan(sqlite_db)
    cols = _by_column(result)
    assert sorted(cols["main.workspace_credentials.api_key"]) == ["GitHub token", "OpenAI API key"]
    assert "AWS access key id" in cols["main.notes.body"]
    assert "Slack token" in cols["main.events.payload"]


def test_a_credential_column_kept_in_clear_is_flagged_but_hashes_and_ciphertext_are_not(sqlite_db):
    db, result = _scan(sqlite_db)
    cols = _by_column(result)
    assert cols["main.users.session_token"] == [dbs.PLAINTEXT_LABEL]       # bearer values stored in the clear
    assert "main.users.password_hash" not in cols                         # a bcrypt hash is the safe way
    assert "main.vault.secret" not in cols                                # Fernet and enc:v2: are ciphertext
    assert not any(c.startswith("main.settings.") for c in cols)           # an expiry and a count are not credentials


def test_only_metadata_is_reported_never_a_value(sqlite_db):
    db, result = _scan(sqlite_db)
    items = dbs.to_items(db, result["findings"])
    blob = json.dumps(items, ensure_ascii=False)
    assert not any(s in blob for s in ALL_SECRETS) and "u1@acme.com" not in blob
    assert all(i["path"].startswith("db://app.db/main.") and i["source"] == "dbscan" for i in items)
    clear = next(i for i in items if dbs.PLAINTEXT_LABEL in i["secret_types"])
    assert clear["count"] == 5 and "••••" in clear["masked"]               # all five sampled rows, masked example only


def test_the_masked_example_has_no_count_so_a_repeat_can_fold(sqlite_db):
    db, result = _scan(sqlite_db)
    items = dbs.to_items(db, result["findings"])
    assert all("sampled" not in i["masked"] and " of " not in i["masked"] for i in items)
    openai = next(i for i in items if i["secret_types"] == ["OpenAI API key"])
    assert openai["masked"].startswith("sk-p") and openai["masked"].endswith("oPQR") and "••••" in openai["masked"]


def test_tables_can_be_excluded_and_included(sqlite_db):
    _, r1 = _scan(sqlite_db, exclude=["notes", "main.events"])
    assert "main.notes.body" not in _by_column(r1) and "main.events.payload" not in _by_column(r1)
    _, r2 = _scan(sqlite_db, include=["users"])
    assert set(_by_column(r2)) == {"main.users.session_token"} and r2["tables"] == 1


def test_a_table_is_read_up_to_the_sample_cap(sqlite_db):
    db, result = _scan(sqlite_db, sample=2)
    f = next(f for f in result["findings"] if f["column"] == "main.users.session_token")
    assert f["sampled"] == 2 and f["count"] == 2


def test_the_connection_cannot_write(sqlite_db):
    db = dbs.SqliteDB(sqlite_db)
    with pytest.raises(sqlite3.OperationalError):
        db.conn.execute("INSERT INTO notes VALUES (99, 'x')")


def test_a_failing_table_does_not_stop_the_scan(sqlite_db):
    db = dbs.SqliteDB(sqlite_db)
    real = db.sample

    def flaky(schema, table, cols, n):
        if table == "users":
            raise RuntimeError("permission denied for table users")
        return real(schema, table, cols, n)

    db.sample = flaky
    result = dbs.scan(db)
    assert any("users" in e for e in result["errors"]) and "main.notes.body" in _by_column(result)


@pytest.mark.parametrize("value,want", [
    ("", "empty"), (BCRYPT, "safe"), (FERNET, "safe"), ("enc:v2:abc", "safe"), ("vault:v1:abcdef", "safe"),
    ("ENC(abcdefg)", "safe"), ("a" * 64, "safe"), ('{"ciphertext": "x", "iv": "y"}', "safe"),
    ("AQICAHh" + "A" * 60, "safe"), (SESSION, "cleartext"), ("short", "other"), ("a sentence with spaces in it, long enough", "other"),
    ("https://example.com/hook", "other"), ("aaaaaaaaaaaaaaaaaaaaaaaa", "other"),
])
def test_classify_stored(value, want):
    assert dbs.classify_stored(value) == want


@pytest.mark.parametrize("name,want", [
    ("api_key", True), ("access_token", True), ("client_secret", True), ("password", True), ("webhook_url", True),
    ("password_hash", False), ("token_expires_at", False), ("token_count", False), ("api_key_id", False),
    ("secret_name", False), ("has_token", False), ("email", False), ("label", False),
])
def test_credential_column_names(name, want):
    assert dbs.is_credential_column(name) is want


# --- the command line ---------------------------------------------------------------------------

def test_dry_run_prints_findings_and_sends_nothing(sqlite_db, monkeypatch, capsys):
    monkeypatch.setattr(dbs.urllib.request, "urlopen", lambda *a, **k: pytest.fail("a dry run sent something"))
    monkeypatch.setattr(dbs.sys, "argv", ["palivane-dbscan", "--sqlite", sqlite_db, "--dry-run"])
    assert dbs.main() == 0
    out = capsys.readouterr().out
    assert "workspace_credentials.api_key" in out and not any(s in out for s in ALL_SECRETS)


def test_findings_are_posted_in_the_secrets_shape(sqlite_db, monkeypatch):
    seen = {}

    class Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake(req, timeout=0):
        seen.update(url=req.full_url, token=req.headers.get("X-palivane-token"), body=json.loads(req.data))
        return Resp(json.dumps({"scanned": len(seen["body"]["items"]), "flagged": 2}).encode())

    monkeypatch.setattr(dbs.urllib.request, "urlopen", fake)
    monkeypatch.setenv("PALIVANE_URL", "https://p.example")
    monkeypatch.setenv("PALIVANE_TOKEN", "ak_test")
    monkeypatch.setattr(dbs.sys, "argv", ["palivane-dbscan", "--sqlite", sqlite_db, "--record"])
    assert dbs.main() == 0
    assert seen["url"] == "https://p.example/api/scan/secrets" and seen["token"] == "ak_test"
    assert seen["body"]["record"] is True and seen["body"]["host"].startswith("sqlite:")
    assert not any(s in json.dumps(seen["body"]) for s in ALL_SECRETS)


def test_fail_on_findings_is_for_ci(sqlite_db, monkeypatch):
    monkeypatch.setattr(dbs.sys, "argv", ["palivane-dbscan", "--sqlite", sqlite_db, "--dry-run", "--fail-on-findings"])
    assert dbs.main() == 2


def test_a_clean_database_exits_zero_and_says_a_sample_is_not_proof(tmp_path, monkeypatch, capsys):
    p = tmp_path / "clean.db"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE t (id INTEGER, name TEXT)")
    c.execute("INSERT INTO t VALUES (1, 'hello')")
    c.commit()
    c.close()
    monkeypatch.setattr(dbs.sys, "argv", ["palivane-dbscan", "--sqlite", str(p), "--dry-run", "--fail-on-findings"])
    assert dbs.main() == 0
    assert "not proof" in capsys.readouterr().out


# --- the Postgres adapter, against a fake connection -----------------------------------------

class _Cur:
    def __init__(self, log, est, fail_tablesample=False):
        self.log, self.est, self.fail, self._rows = log, est, fail_tablesample, []

    def execute(self, sql, params=None):
        self.log.append(sql)
        if "TABLESAMPLE" in sql and self.fail:
            raise RuntimeError("TABLESAMPLE not supported")
        self._rows = [(self.est,)] if "reltuples" in sql else [("v1",), ("v2",)]

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def __iter__(self):
        return iter(self._rows)


class _Conn:
    def __init__(self, est, fail_tablesample=False):
        self.log, self.est, self.fail, self.rolled = [], est, fail_tablesample, 0

    def cursor(self):
        return _Cur(self.log, self.est, self.fail)

    def rollback(self):
        self.rolled += 1

    def close(self):
        pass


def _pg(est, fail=False):
    pg = object.__new__(dbs.PostgresDB)
    pg.conn = _Conn(est, fail)
    return pg


def test_a_big_postgres_table_is_sampled_not_read_from_the_top():
    pg = _pg(1_000_000)
    list(pg.sample("public", "events", ["payload"], 2000))
    sql = pg.conn.log[-1]
    assert "TABLESAMPLE SYSTEM" in sql and sql.endswith("LIMIT 2000")


def test_a_small_postgres_table_is_read_whole_up_to_the_cap():
    pg = _pg(500)
    list(pg.sample("public", "events", ["payload"], 2000))
    assert "TABLESAMPLE" not in pg.conn.log[-1]


def test_a_table_that_cannot_be_sampled_falls_back_to_a_limit():
    pg = _pg(1_000_000, fail=True)
    assert list(pg.sample("public", "parted", ["c"], 100)) == [("v1",), ("v2",)]
    assert pg.conn.rolled == 1 and "TABLESAMPLE" not in pg.conn.log[-1]


def test_identifiers_are_quoted_so_a_hostile_table_name_stays_one_identifier():
    assert dbs._q('weird"; DROP TABLE x; --') == '"weird""; DROP TABLE x; --"'
    pg = _pg(10)
    list(pg.sample("public", 'a"b', ['c"d'], 5))
    assert '"a""b"' in pg.conn.log[-1] and '"c""d"' in pg.conn.log[-1]


def test_postgres_needs_a_connection_string_from_the_environment(monkeypatch):
    for k in ("PALIVANE_DB_DSN", "PGHOST", "PGDATABASE", "PGSERVICE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(dbs.sys, "argv", ["palivane-dbscan", "--dry-run"])
    with pytest.raises(SystemExit) as e:
        dbs.main()
    assert "PALIVANE_DB_DSN" in str(e.value)


# --- the server's side ---------------------------------------------------------------------------

def _key(client):
    return client.post("/api/apikeys", json={"label": "dbscan", "actor": "ops@acme.com"}).json()["token"]


def _post(raw_client, key, items, host="postgres:10.0.0.5"):
    return raw_client.post("/api/scan/secrets", json={"items": items, "host": host, "record": True},
                           headers={"X-Palivane-Token": key})


def _item(label="OpenAI API key", count=12, masked="sk-p••••opQR", column="public.workspace_credentials.api_key"):
    return {"path": f"db://prod/{column}", "secret_types": [label], "masked": masked, "line": 0,
            "world_readable": False, "verified": False, "source": "dbscan", "count": count}


def test_a_database_finding_reads_as_one_and_names_the_column(client, raw_client):
    r = _post(raw_client, _key(client), [_item()])
    assert r.status_code == 200 and r.json()["flagged"] == 1
    f = client.get("/api/findings").json()["findings"][0]
    d = client.get(f"/api/findings/{f['id']}").json()
    sig = d["signals"][0]
    assert sig["title"].startswith("Credential in a database") and "public.workspace_credentials.api_key" in sig["detail"]
    assert "12 sampled values" in sig["detail"] and "device" not in sig["detail"]
    steps = r.json()["findings"][0]["remediation"]
    assert any("KMS" in s for s in steps) and not any("chmod" in s for s in steps)


def test_a_plaintext_column_finding_says_what_to_do(client, raw_client):
    r = _post(raw_client, _key(client), [_item(label=dbs.PLAINTEXT_LABEL, masked="q9Zx••••HsJ6", column="public.users.session_token")])
    f = client.get("/api/findings").json()["findings"][0]
    sig = client.get(f"/api/findings/{f['id']}").json()["signals"][0]
    assert sig["title"] == "Credentials stored in clear in a database column"
    assert "neither encrypted nor hashed" in sig["detail"] and r.json()["findings"][0]["severity"] in ("high", "critical")


def test_a_changing_count_does_not_open_a_new_finding(client, raw_client):
    key = _key(client)
    _post(raw_client, key, [_item(count=12)])
    _post(raw_client, key, [_item(count=57)])
    assert len(client.get("/api/findings").json()["findings"]) == 1


def test_no_value_is_stored(client, raw_client):
    _post(raw_client, _key(client), [_item()])
    f = client.get("/api/findings").json()["findings"][0]
    assert OPENAI not in json.dumps(client.get(f"/api/findings/{f['id']}").json())


def test_the_scanner_is_downloadable_but_not_auto_installed():
    from app import distribution
    assert "palivane-dbscan" in distribution._ALLOW and "palivane-dbscan" not in distribution._CLI_TOOLS
