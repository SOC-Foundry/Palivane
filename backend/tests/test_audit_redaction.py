"""The audit trail records THAT a credential changed, never its value.

PATCH /api/tenant used to put its request body in the audit detail verbatim, so the SIEM token,
S3 secret and key id, inference-hook secret and token-bearing webhook / SIEM URLs sat in plain
text in /api/audit, readable by every admin and by read-only console keys. Values here are
built at runtime, never written out literally.
"""

from __future__ import annotations

import base64
import importlib.util
from pathlib import Path

from app import audit_log
from app.models import AuditLog, Tenant

_MIG = Path(__file__).resolve().parents[1] / "migrations" / "versions" / "1763cbaf8910_scrub_audit_secrets.py"


def _values():
    marker = "q" + "a" * 23
    return {
        "siem_token": "tok-" + marker,
        "siem_s3_key_id": "id-" + marker,
        "siem_s3_secret": "sec-" + marker,
        "inference_hook_secret": "whsec_" + base64.b64encode(marker.encode()).decode(),
        "alert_webhook": "https://hooks." + "slack.com/" + "/".join(["services", "T0", "B0", marker]),
        "siem_url": "https://siem.example.com/collect?token=" + marker,
    }, marker


def test_settings_secrets_never_reach_the_audit_log(client, db_factory):
    values, marker = _values()
    r = client.patch("/api/tenant", json={**values, "siem_format": "json"})
    assert r.status_code == 200, r.text

    entry = next(e for e in client.get("/api/audit").json()["entries"]
                 if e["action"] == "tenant.update")
    d = entry["detail"]
    assert d["siem_token"] == d["siem_s3_secret"] == d["siem_s3_key_id"] == "(set)"
    assert d["inference_hook_secret"] == "(set)"
    assert d["alert_webhook"] == "hooks.slack.com"            # where, not the token in the path
    assert d["siem_url"] == "siem.example.com"
    assert d["siem_format"] == "json"                          # ordinary settings untouched
    assert marker not in str(entry)

    # Not just hidden on the way out: the stored row never had them.
    db = db_factory()
    stored = [row.detail for row in db.query(AuditLog).filter(AuditLog.action == "tenant.update")]
    db.close()
    assert stored and marker not in str(stored)


def test_clearing_a_secret_is_recorded_as_cleared(client):
    client.patch("/api/tenant", json={"siem_token": "", "alert_webhook": ""})
    d = next(e for e in client.get("/api/audit").json()["entries"]
             if e["action"] == "tenant.update")["detail"]
    assert d["siem_token"] == "(cleared)" and d["alert_webhook"] == "(cleared)"


def test_rows_written_before_the_fix_are_redacted_on_read(client, db_factory):
    values, marker = _values()
    db = db_factory()
    tid = db.query(Tenant).filter(Tenant.slug == "acme").one().id
    db.add(AuditLog(tenant_id=tid, actor="admin@acme.com", action="tenant.update",
                    detail=dict(values)))                      # the old, unredacted shape
    db.commit(); db.close()
    entries = client.get("/api/audit").json()["entries"]
    assert marker not in str(entries)


def test_unrelated_details_are_left_alone():
    d = {"sessions_revoked": True, "api_keys_revoked": 2, "keys": ["laptop"], "role": "admin",
         "nested": {"siem_token": "x", "count": 3}}
    out = audit_log.redact(d)
    assert out["api_keys_revoked"] == 2 and out["keys"] == ["laptop"] and out["role"] == "admin"
    assert out["nested"] == {"siem_token": "(set)", "count": 3}
    assert audit_log.redact("not a dict") == "not a dict"


def test_migration_scrubs_like_the_app_and_is_idempotent():
    spec = importlib.util.spec_from_file_location("scrub", _MIG)
    mig = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mig)
    values, marker = _values()
    once = mig._redact(dict(values))
    assert once == audit_log.redact(dict(values))              # same rule as the app's
    assert mig._redact(once) == once                           # a second run changes nothing
    assert audit_log.redact(once) == once                      # nor does read-time redaction
    assert marker not in str(once)
