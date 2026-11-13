"""A read-only path into an org's findings for an operator: the palivane-findings CLI on a
console-read key, over /api/export/findings and the new /api/export/findings/{id}. Every
read a person makes leaves the trail a person in the console would."""
from __future__ import annotations

import importlib.util
import io
import json
from datetime import datetime, timezone
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

from app.models import Finding, Tenant

_ROOT = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_loader(
        "pv_findings_cli", SourceFileLoader("pv_findings_cli", str(_ROOT / "cli" / "palivane-findings")))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _key(client, scope):
    return client.post("/api/apikeys", json={"label": scope, "scope": scope}).json()["token"]


def _seed(db_factory, n=3):
    db = db_factory()
    tid = db.query(Tenant).filter(Tenant.slug == "acme").one().id
    ids = []
    for i in range(n):
        f = Finding(tenant_id=tid, sender=f"p{i}@acme.com", surface="ai_usage", channel="claude-code",
                    subject=f"finding {i}", content=f"secret number {i}", severity="high", risk_score=70,
                    status="open" if i else "dismissed",
                    signals=[{"category": "secret_leak", "title": "Credentials in outbound content",
                              "weight": 0.9, "confidence": 0.85, "detector": "shadow_ai",
                              "evidence": "AWS access key id", "check": "secret_leak"}])
        db.add(f)
        db.flush()
        ids.append(f.id)
    db.commit()
    db.close()
    return ids


def _audit(client):
    body = client.get("/api/audit").json()
    return body if isinstance(body, list) else body.get("entries") or body.get("items") or []


# --- the endpoint ----------------------------------------------------------------------------

def test_a_console_read_key_reads_one_finding_and_it_is_audited(client, raw_client, db_factory):
    ids = _seed(db_factory)
    key = _key(client, "console_read")
    r = raw_client.get(f"/api/export/findings/{ids[1]}", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["id"] == ids[1] and d["signals"][0]["evidence"] == "AWS access key id"
    assert d["content"] == ""                                   # not unless asked for
    r = raw_client.get(f"/api/export/findings/{ids[1]}?content=1", headers={"Authorization": f"Bearer {key}"})
    assert r.json()["content"] == "secret number 1"
    reads = [e for e in _audit(client) if e.get("action") == "finding.export"]
    assert [(e.get("target"), (e.get("detail") or {}).get("content")) for e in reads] == [
        (str(ids[1]), True), (str(ids[1]), False)]
    assert all(e.get("actor") == "admin@acme.com" for e in reads)   # the key's user, not the key


def test_an_ingest_key_cannot_read_findings(client, raw_client, db_factory):
    ids = _seed(db_factory)
    key = _key(client, "ingest")
    r = raw_client.get(f"/api/export/findings/{ids[0]}", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 401
    r = raw_client.get("/api/export/findings", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 401


def test_another_orgs_finding_is_not_found(client, raw_client, db_factory):
    from app import users as users_cli
    db = db_factory()
    users_cli.create_tenant(db, "beta", "Beta")
    other = Finding(tenant_id=db.query(Tenant).filter(Tenant.slug == "beta").one().id,
                    sender="x@beta.com", severity="high", signals=[])
    db.add(other)
    db.commit()
    oid = other.id
    db.close()
    key = _key(client, "console_read")
    assert raw_client.get(f"/api/export/findings/{oid}", headers={"Authorization": f"Bearer {key}"}).status_code == 404


def test_the_list_filters_by_status_and_audits_an_undated_pull(client, raw_client, db_factory):
    ids = _seed(db_factory)
    key = _key(client, "console_read")
    h = {"Authorization": f"Bearer {key}"}
    rows = [json.loads(l) for l in raw_client.get("/api/export/findings?status=open", headers=h).text.splitlines()]
    assert sorted(r["id"] for r in rows) == sorted(ids[1:])
    rows = [json.loads(l) for l in raw_client.get("/api/export/findings?status=dismissed", headers=h).text.splitlines()]
    assert [r["id"] for r in rows] == [ids[0]]
    # A watermark pull is a poller: not audited. An undated one is a person: audited.
    raw_client.get("/api/export/findings?since=2020-01-01T00:00:00Z", headers=h)
    pulls = [e for e in _audit(client) if e.get("action") == "findings.export"]
    assert sorted((e.get("detail") or {}).get("status") for e in pulls) == ["dismissed", "open"]


# --- the CLI -----------------------------------------------------------------------------------

def test_since_shorthand_and_iso(monkeypatch):
    cli = _load()
    now = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
    assert cli.parse_since("24h", now) == "2026-11-12T12:00:00Z"
    assert cli.parse_since("7d", now) == "2026-11-06T12:00:00Z"
    assert cli.parse_since("2w", now) == "2026-10-30T12:00:00Z"
    assert cli.parse_since("2026-11-01T08:30:00+02:00", now) == "2026-11-01T06:30:00Z"
    with pytest.raises(SystemExit):
        cli.parse_since("yesterday", now)


class _FakeResp(io.BytesIO):
    def __init__(self, status, body):
        super().__init__(body.encode())
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_list_and_show_against_a_stubbed_server(monkeypatch, capsys):
    cli = _load()
    calls = []

    def fake_urlopen(req, timeout=0):
        calls.append((req.full_url, req.headers.get("Authorization")))
        if "/api/export/findings/1425" in req.full_url:
            return _FakeResp(200, json.dumps({
                "id": 1425, "severity": "critical", "risk_score": 97, "recommended_action": "block",
                "status": "dismissed", "created_at": "2026-11-12T04:37:29", "last_seen": "2026-11-12T04:37:29",
                "seen_count": 1, "sender": "david@socfoundry.com", "surface": "ai_usage", "channel": "claude-code",
                "subject": "", "reviewed_by": "david@socfoundry.com", "review_via": "bulk",
                "review_reason": "false_positive", "reviewed_at": "2026-11-13T03:20:00",
                "signals": [{"category": "secret_leak", "title": "Credentials/secrets in outbound content",
                             "weight": 0.9, "confidence": 0.85, "evidence": "AWS access key id"}],
                "origin": None, "content": ""}))
        rows = [{"id": 1, "last_seen": "2026-11-12T04:37:29", "severity": "critical", "status": "open",
                 "surface": "session", "sender": "david@socfoundry.com", "subject": "attack chain: recon → execution",
                 "top_signals": [], "categories": ["session_correlation"]},
                {"id": 2, "last_seen": "2026-11-13T02:26:49", "severity": "high", "status": "open",
                 "surface": "agent_tools", "sender": "david@socfoundry.com", "subject": "",
                 "top_signals": [{"title": "Personal data in outbound content", "evidence": "Spain DNI/NIE"}],
                 "categories": ["pii_exposure"]}]
        return _FakeResp(200, "\n".join(json.dumps(r) for r in rows))

    monkeypatch.setattr(cli.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("PALIVANE_URL", "https://pv.example")
    monkeypatch.setenv("PALIVANE_READ_TOKEN", "ak_readonly_key")

    assert cli.main(["--since", "24h", "--severity", "critical"]) == 0
    out = capsys.readouterr().out
    assert "attack chain" in out and "Spain DNI/NIE" in out
    assert out.splitlines()[0].startswith("ID")
    assert out.splitlines()[1].startswith("2 ")                # newest first on a dated pull
    url, auth = calls[-1]
    assert url.startswith("https://pv.example/api/export/findings?") and "severity=critical" in url
    assert "status=open" in url and "since=" in url and auth == "Bearer ak_readonly_key"

    assert cli.main(["show", "1425"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("#1425  critical (risk 97), block, dismissed")
    assert "review   david@socfoundry.com via bulk, false_positive" in out
    assert "secret_leak: Credentials/secrets in outbound content [0.77]" in out
    assert "AWS access key id" in out and "\ncontent\n" not in out      # no content section
    assert calls[-1][0] == "https://pv.example/api/export/findings/1425"

    assert cli.main(["--status", "all", "--json"]) == 0
    assert "status=" not in calls[-1][0]
    assert json.loads(capsys.readouterr().out)[0]["id"] in (1, 2)


def test_an_ingest_key_gets_a_pointer_to_the_right_key(monkeypatch, capsys):
    cli = _load()

    def fake_urlopen(req, timeout=0):
        import urllib.error
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(b'{"detail":"invalid API key"}'))

    monkeypatch.setattr(cli.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("PALIVANE_URL", "https://pv.example")
    monkeypatch.setenv("PALIVANE_READ_TOKEN", "ak_device_key")
    assert cli.main([]) == 1
    err = capsys.readouterr().err
    assert "console_read" in err and "PALIVANE_READ_TOKEN" in err


def test_no_key_is_a_clear_exit(monkeypatch, capsys):
    cli = _load()
    for v in ("PALIVANE_READ_TOKEN", "PALIVANE_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setattr(cli, "_settings_env", lambda path="": {})
    assert cli.main([]) == 2
    assert "console-read" in capsys.readouterr().err
