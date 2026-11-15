"""Blast radius (app/reach.py): what a leaked credential can reach, from its shape, and for
AWS keys from the IAM user the org's role can read."""
from __future__ import annotations

from datetime import datetime, timezone

from app import reach, secrets_ledger
from app.config import settings
from app.models import SecretReach, Tenant

UA = "palivane-hook/1.3.4 (claude-code/2.1.4)"
AWS = "AKIA" + "IOSFODNN7" + "QXAMPLE"
GHP = "ghp_" + "wY3kD8fJ2mNp6qRt7vBx1zLc4hAe5gUi9oKs"
GHS = "ghs_" + "wY3kD8fJ2mNp6qRt7vBx1zLc4hAe5gUi9oKs"
XOXP = "xoxp-" + "1234567890-1234567890-abcdefghijkl"
SKT = "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc"


def test_static_classification_by_shape():
    assert reach.classify("GitHub token", GHP)["severity"] == "high"
    assert reach.classify("GitHub token", GHS)["severity"] == "medium" and "installation" in reach.classify("GitHub token", GHS)["scope"]
    assert reach.classify("GitHub fine-grained PAT", "github_pat_x")["severity"] == "medium"
    assert "acts as the person" in reach.classify("Slack token", XOXP)["scope"] and reach.classify("Slack token", XOXP)["severity"] == "high"
    assert reach.classify("Stripe secret key", SKT)["severity"] == "low"
    assert reach.classify("Stripe secret key", "sk_live_x")["severity"] == "critical"
    assert reach.classify("AWS access key id", AWS)["kind"] == "cloud"
    u = reach.classify("Something new", "zzz")
    assert u["kind"] == "unknown" and u["severity"] == "medium"


def test_assess_stores_once_per_fingerprint(client, db_factory):
    db = db_factory()
    t = db.query(Tenant).first()
    fp = secrets_ledger.fingerprint(t.id, GHP)
    a = reach.assess(db, t, t.id, fp, "GitHub token", GHP)
    b = reach.assess(db, t, t.id, fp, "GitHub token", GHP)
    assert a.id == b.id and db.query(SecretReach).count() == 1
    assert reach.for_fingerprint(db, t.id, fp)["severity"] == "high"


def test_aws_key_is_looked_up_through_the_orgs_role(client, db_factory, monkeypatch):
    db = db_factory()
    t = db.query(Tenant).first()
    t.siem_s3_role_arn = "arn:aws:iam::123456789012:role/palivane-read"
    db.commit()
    monkeypatch.setattr(settings, "aws_delivery_principal", "arn:aws:iam::999:role/palivane")

    class _IAM:
        def get_access_key_last_used(self, AccessKeyId):
            assert AccessKeyId == AWS
            return {"UserName": "ci-deployer", "AccessKeyLastUsed": {"LastUsedDate": datetime(2026, 11, 14, 9, 0, tzinfo=timezone.utc), "ServiceName": "s3"}}
        def list_attached_user_policies(self, UserName):
            return {"AttachedPolicies": [{"PolicyName": "AmazonS3FullAccess"}, {"PolicyName": "CloudWatchLogsReadOnly"}]}
        def list_user_policies(self, UserName):
            return {"PolicyNames": []}
        def list_groups_for_user(self, UserName):
            return {"Groups": [{"GroupName": "deployers"}]}
        def list_attached_group_policies(self, GroupName):
            return {"AttachedPolicies": [{"PolicyName": "AdministratorAccess"}]}
    monkeypatch.setattr(reach, "_iam_client", lambda role_arn, ext_id, region: _IAM())

    fp = secrets_ledger.fingerprint(t.id, AWS)
    row = reach.assess(db, t, t.id, fp, "AWS access key id", AWS)
    assert row.source == "aws" and row.severity == "critical"
    assert "IAM user ci-deployer" in row.scope and "AdministratorAccess" in row.scope and "groups deployers" in row.scope
    assert row.detail["last_service"] == "s3" and row.detail["user"] == "ci-deployer"
    assert AWS not in (row.scope + str(row.detail)), "the key never lands in the record"


def test_without_a_role_aws_stays_static_and_a_failing_lookup_falls_back(client, db_factory, monkeypatch):
    db = db_factory()
    t = db.query(Tenant).first()
    fp = secrets_ledger.fingerprint(t.id, AWS)
    assert reach.assess(db, t, t.id, fp, "AWS access key id", AWS).source == "static"
    db.query(SecretReach).delete(); db.commit()
    t.siem_s3_role_arn = "arn:aws:iam::123456789012:role/r"; db.commit()
    monkeypatch.setattr(settings, "aws_delivery_principal", "arn:x")
    def boom(*a): raise RuntimeError("AccessDenied")
    monkeypatch.setattr(reach, "_iam_client", boom)
    row = reach.assess(db, t, t.id, fp, "AWS access key id", AWS)
    assert row.source == "static" and row.severity == "high"


def test_ledger_reports_reach_with_the_travel(client, raw_client, db_factory, monkeypatch):
    monkeypatch.setattr(settings, "gateway_enforce_secrets", False)
    tok = client.post("/api/apikeys", json={"label": "laptop", "actor": "dev@acme.com"}).json()["token"]
    v = raw_client.post("/api/ingest/ai-usage", json={"content": f"use {XOXP} to post the digest", "tool": "claude-code"},
                        headers={"X-Palivane-Token": tok, "User-Agent": UA}).json()
    assert v.get("finding_id")
    led = client.get(f"/api/findings/{v['finding_id']}/secrets").json()["secrets"]
    assert led and led[0]["reach"]["severity"] == "high" and "acts as the person" in led[0]["reach"]["scope"]
    assert db_factory().query(SecretReach).count() == 1
