"""S3 delivery via IAM role (STS AssumeRole): config validation, external-ID minting,
the role-setup helper, STS session caching, and role-only delivery through the sinks."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone

import pytest

import app.siem_s3 as s3

ROLE = "arn:aws:iam::123456789012:role/palivane-delivery"


# --- fake boto3 (not installed in the test env; imported lazily by siem_s3) -------------

class _FakeSTS:
    def __init__(self, log, ttl_secs=3600):
        self.log, self.ttl = log, ttl_secs

    def assume_role(self, **kw):
        self.log.append(kw)
        return {"Credentials": {
            "AccessKeyId": f"ASIA{len(self.log)}", "SecretAccessKey": "tmp", "SessionToken": "tok",
            "Expiration": datetime.now(timezone.utc) + timedelta(seconds=self.ttl)}}


class _FakeBoto3:
    def __init__(self, assumes, ttl_secs=3600):
        self.assumes, self.ttl, self.puts = assumes, ttl_secs, []

    def client(self, svc, **kw):
        if svc == "sts":
            return _FakeSTS(self.assumes, self.ttl)
        fake = self

        class _S3:
            def put_object(self, **pkw):
                fake.puts.append(pkw)
        s3c = _S3()
        s3c.session_token = kw.get("aws_session_token")
        return s3c


@pytest.fixture
def fake_boto3(monkeypatch):
    assumes = []
    fake = _FakeBoto3(assumes)
    monkeypatch.setitem(sys.modules, "boto3", fake)
    s3._role_clients.clear()
    s3._clients.clear()
    yield fake
    s3._role_clients.clear()
    s3._clients.clear()


# --- config / validation -----------------------------------------------------------------

def test_role_arn_validated_and_external_id_minted(client):
    r = client.patch("/api/tenant", json={"siem_s3_role_arn": "arn:aws:iam::123:user/bob"})
    assert r.status_code == 400                     # not a role ARN
    r = client.patch("/api/tenant", json={"siem_s3_role_arn": "not-an-arn"})
    assert r.status_code == 400
    t = client.patch("/api/tenant", json={"siem_s3_role_arn": ROLE,
                                          "siem_s3_bucket": "lake"}).json()
    assert t["siem_s3_role_arn"] == ROLE
    assert t["siem_s3_external_id"].startswith("plv-")
    # role alone (no static keys) counts as configured
    assert t["siem_s3_configured"] is True
    # the external ID is stable across saves — the customer's trust policy pins it
    t2 = client.patch("/api/tenant", json={"siem_s3_role_arn": ROLE}).json()
    assert t2["siem_s3_external_id"] == t["siem_s3_external_id"]
    # clearing the role is always allowed and keeps the external ID for later re-enable
    t3 = client.patch("/api/tenant", json={"siem_s3_role_arn": ""}).json()
    assert t3["siem_s3_role_arn"] == "" and t3["siem_s3_configured"] is False
    assert t3["siem_s3_external_id"] == t["siem_s3_external_id"]


def test_role_setup_endpoint(client, raw_client):
    r = client.get("/api/siem/s3/role-setup")
    assert r.status_code == 200
    body = r.json()
    ext = body["external_id"]
    assert ext.startswith("plv-")
    stmt = body["trust_policy"]["Statement"][0]
    assert stmt["Action"] == "sts:AssumeRole"
    assert stmt["Condition"]["StringEquals"]["sts:ExternalId"] == ext
    # idempotent: the second call returns the same external ID
    assert client.get("/api/siem/s3/role-setup").json()["external_id"] == ext
    assert raw_client.get("/api/siem/s3/role-setup").status_code == 401


# --- STS client behavior -----------------------------------------------------------------

def test_role_client_assumes_with_external_id_and_caches(fake_boto3):
    c1 = s3._client("us-east-1", "", "", role_arn=ROLE, external_id="plv-abc")
    assert len(fake_boto3.assumes) == 1
    kw = fake_boto3.assumes[0]
    assert kw["RoleArn"] == ROLE and kw["ExternalId"] == "plv-abc"
    assert kw["RoleSessionName"] == "palivane-s3-delivery"
    # cached: a second call within the session lifetime does not re-assume
    c2 = s3._client("us-east-1", "", "", role_arn=ROLE, external_id="plv-abc")
    assert c2 is c1 and len(fake_boto3.assumes) == 1


def test_role_client_refreshes_near_expiry(monkeypatch, fake_boto3):
    fake_boto3.ttl = 60          # sessions come back with < _STS_REFRESH_SLACK remaining
    s3._client("", "", "", role_arn=ROLE, external_id="x")
    s3._client("", "", "", role_arn=ROLE, external_id="x")
    assert len(fake_boto3.assumes) == 2   # near-expiry hit is not served from cache


def test_role_takes_precedence_over_static_keys(fake_boto3):
    s3._client("us-east-1", "AKIA", "sek", role_arn=ROLE, external_id="e")
    assert len(fake_boto3.assumes) == 1   # went through STS, not the static-key path
    assert s3._clients == {}


# --- delivery through the sinks ----------------------------------------------------------

def test_forward_s3_delivers_with_role_only(monkeypatch):
    calls = []
    monkeypatch.setattr(s3, "_put", lambda *a, **k: (calls.append((a, k)) or (True, "")))
    import app.dispatch as dispatch
    monkeypatch.setattr(dispatch, "submit", lambda fn, *a, **k: fn(*a, **k))
    v = {"severity": "critical", "risk_score": 90, "finding_id": 1,
         "signals": [{"category": "secret_leak"}]}
    # no keys, no role -> no-op
    s3.forward_s3("b", "", "", "", "", "high", v)
    assert calls == []
    # role only -> delivered, with the role threaded through to the put
    s3.forward_s3("b", "", "", "", "", "high", v, role_arn=ROLE, external_id="plv-x")
    assert len(calls) == 1
    assert calls[0][1].get("role_arn") == ROLE and calls[0][1].get("external_id") == "plv-x"


def test_sts_failure_is_reported_not_swallowed(monkeypatch):
    class _Boom:
        def client(self, svc, **kw):
            raise RuntimeError("AccessDenied: not authorized to perform sts:AssumeRole")
    monkeypatch.setitem(sys.modules, "boto3", _Boom())
    s3._role_clients.clear()
    ok, detail = s3._put("b", "", "", "", "", {"x": 1}, role_arn=ROLE, external_id="e")
    assert ok is False and "AssumeRole" in detail


def test_archive_buffers_with_role_only_config(client, monkeypatch):
    import app.archive_s3 as a
    flushed = []
    monkeypatch.setattr(a, "_submit", lambda cfg, body, count, tid=0: flushed.append(cfg))
    monkeypatch.setattr(a, "_ensure_flusher", lambda: None)
    # Patch the settings object archive_s3 actually holds (test_config.py can rebind
    # app.config.settings, so `from app.config import settings` here may be a different
    # instance than the one bound at archive_s3 import time).
    monkeypatch.setattr(a.settings, "archive_flush_kb", 1)  # tiny threshold: flush fast
    client.patch("/api/tenant", json={"siem_s3_bucket": "lake", "siem_s3_role_arn": ROLE,
                                      "archive_s3_enabled": True})
    from app.detectors import AnalysisInput, Surface

    class _T:  # minimal tenant shape for archive()
        id = 1; slug = "acme"; archive_s3_enabled = True; archive_s3_raw_content = False
        archive_s3_daily_mb = 0
        siem_s3_bucket = "lake"; siem_s3_prefix = ""; siem_s3_region = ""
        siem_s3_key_id = ""; siem_s3_secret = ""
        siem_s3_role_arn = ROLE; siem_s3_external_id = "plv-x"
        siem_naming = "palivane"
    item = AnalysisInput(content="hello " * 400, surface=Surface.AI_USAGE,
                         channel="chatgpt.com", sender="dev@acme.com")
    a.archive(_T(), item, {"severity": "benign", "risk_score": 0, "signals": []})
    assert flushed and flushed[0][6] == ROLE and flushed[0][7] == "plv-x"


def test_s3_test_endpoint_works_with_role_only(client, monkeypatch):
    monkeypatch.setattr(s3, "_put", lambda *a, **k: (True, ""))
    client.patch("/api/tenant", json={"siem_s3_bucket": "lake", "siem_s3_role_arn": ROLE})
    r = client.post("/api/siem/s3/test").json()
    assert r["ok"] is True
