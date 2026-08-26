"""S3 delivery via IAM role (STS AssumeRole): config validation, external-ID minting,
the role-setup helper, STS session caching, and role-only delivery through the sinks.

Every role path is conditional on the deployment having an AWS identity of its own for the
customer's trust policy to name (PALIVANE_AWS_DELIVERY_PRINCIPAL). The `delivery_principal`
fixture below is what makes a test run as such a deployment; the tests at the bottom cover
the deployments that have no AWS identity at all, where role delivery is simply not offered."""

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
def delivery_principal(monkeypatch):
    """Run as a deployment that has an AWS identity to be assumed from. Set on every live
    Settings instance, since test_config.py can rebind app.config.settings while modules
    that imported it early still hold the original."""
    import app.archive_s3 as arch
    import app.auth as auth_mod
    import app.config as cfg
    import app.main as main_mod
    arn = "arn:aws:iam::999999999999:role/palivane-delivery"
    for obj in {id(o): o for o in (cfg.settings, auth_mod.settings,
                                   main_mod.settings, arch.settings)}.values():
        monkeypatch.setattr(obj, "aws_delivery_principal", arn)
    return arn


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

def test_role_arn_validated_and_external_id_minted(client, delivery_principal):
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


def test_role_setup_endpoint(client, raw_client, delivery_principal):
    r = client.get("/api/siem/s3/role-setup")
    assert r.status_code == 200
    body = r.json()
    ext = body["external_id"]
    assert ext.startswith("plv-")
    stmt = body["trust_policy"]["Statement"][0]
    assert stmt["Action"] == "sts:AssumeRole"
    assert stmt["Principal"]["AWS"] == delivery_principal   # never a placeholder
    assert stmt["Condition"]["StringEquals"]["sts:ExternalId"] == ext
    # idempotent: the second call returns the same external ID
    assert client.get("/api/siem/s3/role-setup").json()["external_id"] == ext
    assert raw_client.get("/api/siem/s3/role-setup").status_code == 401


# --- STS client behavior -----------------------------------------------------------------

def test_role_client_assumes_with_external_id_and_caches(fake_boto3, delivery_principal):
    c1 = s3._client("us-east-1", "", "", role_arn=ROLE, external_id="plv-abc")
    assert len(fake_boto3.assumes) == 1
    kw = fake_boto3.assumes[0]
    assert kw["RoleArn"] == ROLE and kw["ExternalId"] == "plv-abc"
    assert kw["RoleSessionName"] == "palivane-s3-delivery"
    # cached: a second call within the session lifetime does not re-assume
    c2 = s3._client("us-east-1", "", "", role_arn=ROLE, external_id="plv-abc")
    assert c2 is c1 and len(fake_boto3.assumes) == 1


def test_role_client_refreshes_near_expiry(monkeypatch, fake_boto3, delivery_principal):
    fake_boto3.ttl = 60          # sessions come back with < _STS_REFRESH_SLACK remaining
    s3._client("", "", "", role_arn=ROLE, external_id="x")
    s3._client("", "", "", role_arn=ROLE, external_id="x")
    assert len(fake_boto3.assumes) == 2   # near-expiry hit is not served from cache


def test_role_takes_precedence_over_static_keys(fake_boto3, delivery_principal):
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


def test_archive_buffers_with_role_only_config(client, monkeypatch, delivery_principal):
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
    item = AnalysisInput(content="hello " * 400, surface=Surface.AI_USAGE,
                         channel="chatgpt.com", sender="dev@acme.com")
    a.archive(_T(), item, {"severity": "benign", "risk_score": 0, "signals": []})
    assert flushed and flushed[0][5] == ROLE and flushed[0][6] == "plv-x"


def test_s3_test_endpoint_works_with_role_only(client, monkeypatch, delivery_principal):
    monkeypatch.setattr(s3, "_put", lambda *a, **k: (True, ""))
    client.patch("/api/tenant", json={"siem_s3_bucket": "lake", "siem_s3_role_arn": ROLE})
    r = client.post("/api/siem/s3/test").json()
    assert r["ok"] is True


# --- deployments with no AWS identity of their own ---------------------------------------
# Palivane's own hosted deployment is one: PALIVANE_AWS_DELIVERY_PRINCIPAL is unset, so no
# customer trust policy can name it and no AssumeRole can ever succeed. The console used to
# recommend role-based delivery anyway. These pin the path shut instead of half-offering it.

def test_role_arn_refused_without_a_delivery_principal(client):
    r = client.patch("/api/tenant", json={"siem_s3_role_arn": ROLE})
    assert r.status_code == 400
    assert "not available on this deployment" in r.json()["detail"]
    # clearing is always allowed — a tenant configured earlier must be able to undo it
    assert client.patch("/api/tenant", json={"siem_s3_role_arn": ""}).status_code == 200


def test_role_setup_endpoint_refuses_without_a_delivery_principal(client):
    r = client.get("/api/siem/s3/role-setup")
    assert r.status_code == 501       # not a placeholder trust policy nobody can use


def test_static_keys_win_over_a_role_that_cannot_be_assumed(fake_boto3):
    # A tenant configured back when the console recommended a role keeps that ARN in the
    # database. It must not shadow a key pair that does work.
    c = s3._client("us-east-1", "AKIA", "sek", role_arn=ROLE, external_id="e")
    assert fake_boto3.assumes == []           # no STS call
    assert c is s3._clients[("us-east-1", "AKIA", "sek")]


def test_archive_ignores_a_stored_role_without_a_delivery_principal(monkeypatch):
    import app.archive_s3 as a
    flushed = []
    monkeypatch.setattr(a, "_submit", lambda cfg, body, count, tid=0: flushed.append(cfg))
    monkeypatch.setattr(a, "_ensure_flusher", lambda: None)
    monkeypatch.setattr(a.settings, "archive_flush_kb", 1)
    from app.detectors import AnalysisInput, Surface

    class _T:  # role stored, no keys — nothing deliverable, so nothing should buffer
        id = 1; slug = "acme"; archive_s3_enabled = True; archive_s3_raw_content = False
        archive_s3_daily_mb = 0
        siem_s3_bucket = "lake"; siem_s3_prefix = ""; siem_s3_region = ""
        siem_s3_key_id = ""; siem_s3_secret = ""
        siem_s3_role_arn = ROLE; siem_s3_external_id = "plv-x"
    item = AnalysisInput(content="hello " * 400, surface=Surface.AI_USAGE,
                         channel="chatgpt.com", sender="dev@acme.com")
    a.archive(_T(), item, {"severity": "benign", "risk_score": 0, "signals": []})
    assert flushed == []


def test_role_only_tenant_does_not_report_itself_configured(delivery_principal, monkeypatch):
    from app.models import Tenant
    t = Tenant(slug="acme", name="Acme", siem_s3_bucket="lake", siem_s3_role_arn=ROLE)
    assert t.to_dict()["siem_s3_configured"] is True        # deployment can assume the role
    import app.config as cfg
    monkeypatch.setattr(cfg.settings, "aws_delivery_principal", "")
    assert t.to_dict()["siem_s3_configured"] is False       # same row, nowhere to deliver
