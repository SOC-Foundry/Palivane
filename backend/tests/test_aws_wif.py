"""GCP→AWS web-identity federation (aws_wif): token exchange, caching, and role
chaining into customer delivery roles via siem_s3."""

from __future__ import annotations

import sys
import time
import types
from datetime import datetime, timedelta, timezone

import pytest

import app.aws_wif as wif
import app.siem_s3 as s3

WIF_ROLE = "arn:aws:iam::592954524802:role/palivane-delivery-wif"
CUSTOMER_ROLE = "arn:aws:iam::111122223333:role/customer-delivery"


@pytest.fixture(autouse=True)
def _clean():
    wif.reset()
    s3._role_clients.clear()
    s3._clients.clear()
    yield
    wif.reset()
    s3._role_clients.clear()
    s3._clients.clear()


def _configure(monkeypatch):
    # Patch the settings object the modules actually hold (test_config.py can rebind
    # app.config.settings; the import-time binding is the one that matters here).
    monkeypatch.setattr(wif.settings, "aws_wif_role_arn", WIF_ROLE)
    monkeypatch.setattr(wif.settings, "aws_wif_audience", "palivane-aws-delivery")


def _fake_botocore(monkeypatch):
    bc = types.ModuleType("botocore")
    bc.UNSIGNED = object()
    cfg = types.ModuleType("botocore.config")

    class Config:
        def __init__(self, **kw):
            self.kw = kw
    cfg.Config = Config
    monkeypatch.setitem(sys.modules, "botocore", bc)
    monkeypatch.setitem(sys.modules, "botocore.config", cfg)


class _FakeSTS:
    def __init__(self, rec):
        self.rec = rec

    def assume_role_with_web_identity(self, **kw):
        self.rec.setdefault("wif_calls", []).append(kw)
        return {"Credentials": {
            "AccessKeyId": "ASIA-WIF", "SecretAccessKey": "wif-secret", "SessionToken": "wif-tok",
            "Expiration": datetime.now(timezone.utc) + timedelta(hours=1)}}

    def assume_role(self, **kw):
        self.rec.setdefault("assume_calls", []).append(kw)
        return {"Credentials": {
            "AccessKeyId": "ASIA-CUST", "SecretAccessKey": "cust-secret", "SessionToken": "cust-tok",
            "Expiration": datetime.now(timezone.utc) + timedelta(hours=1)}}


class _FakeBoto3:
    def __init__(self, rec):
        self.rec = rec

    def client(self, svc, **kw):
        self.rec.setdefault("clients", []).append((svc, kw))
        if svc == "sts":
            return _FakeSTS(self.rec)
        return types.SimpleNamespace(put_object=lambda **_kw: None)


@pytest.fixture
def rec(monkeypatch):
    rec = {}
    monkeypatch.setitem(sys.modules, "boto3", _FakeBoto3(rec))
    _fake_botocore(monkeypatch)
    return rec


def test_unconfigured_is_inert(monkeypatch, rec):
    monkeypatch.setattr(wif.settings, "aws_wif_role_arn", "")
    assert wif.base_credentials() is None
    # _sts_client falls back to the default chain: no explicit credential kwargs
    s3._sts_client("us-east-1")
    svc, kw = rec["clients"][-1]
    assert svc == "sts" and "aws_access_key_id" not in kw


def test_exchange_sends_metadata_token_to_wif_role(monkeypatch, rec):
    _configure(monkeypatch)
    monkeypatch.setattr(wif, "_identity_token", lambda: "gcp-oidc-jwt")
    creds = wif.base_credentials()
    assert creds["AccessKeyId"] == "ASIA-WIF" and creds["SessionToken"] == "wif-tok"
    call = rec["wif_calls"][0]
    assert call["RoleArn"] == WIF_ROLE and call["WebIdentityToken"] == "gcp-oidc-jwt"
    assert call["DurationSeconds"] == 3600


def test_base_credentials_cached_then_refreshed_near_expiry(monkeypatch, rec):
    _configure(monkeypatch)
    monkeypatch.setattr(wif, "_identity_token", lambda: "tok")
    wif.base_credentials()
    wif.base_credentials()
    assert len(rec["wif_calls"]) == 1              # served from cache
    with wif._lock:
        wif._cached["exp"] = time.time() + 60      # < refresh slack
    wif.base_credentials()
    assert len(rec["wif_calls"]) == 2              # re-exchanged


def test_role_client_chains_wif_into_customer_role(monkeypatch, rec):
    _configure(monkeypatch)
    monkeypatch.setattr(wif, "_identity_token", lambda: "tok")
    s3._client("us-east-1", "", "", role_arn=CUSTOMER_ROLE, external_id="plv-x")
    # the STS client that assumed the customer role carries the federated session
    sts_clients = [kw for svc, kw in rec["clients"] if svc == "sts" and kw.get("aws_session_token")]
    assert any(kw["aws_session_token"] == "wif-tok" for kw in sts_clients)
    assume = rec["assume_calls"][0]
    assert assume["RoleArn"] == CUSTOMER_ROLE and assume["ExternalId"] == "plv-x"
    # and the resulting S3 client uses the chained (customer-role) session
    s3_clients = [kw for svc, kw in rec["clients"] if svc == "s3"]
    assert s3_clients and s3_clients[-1]["aws_session_token"] == "cust-tok"


def test_wif_failure_surfaces_in_put_detail(monkeypatch, rec):
    _configure(monkeypatch)

    def _boom():
        raise RuntimeError("metadata server unreachable")
    monkeypatch.setattr(wif, "_identity_token", _boom)
    ok, detail = s3._put("bucket", "", "", "", "", {"x": 1},
                         role_arn=CUSTOMER_ROLE, external_id="e")
    assert ok is False and "metadata server unreachable" in detail
