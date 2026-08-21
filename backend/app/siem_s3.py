"""SIEM/data-lake delivery to Amazon S3 — a second, independent sink alongside the HTTP
push in siem.py. Writes one JSON object per finding (severity-gated) under a date-partitioned
prefix a Panther S3 log source / Athena / Snowflake external stage can ingest.

Per-finding objects (not an in-memory batch) on purpose: Cloud Run scales to zero and runs
many short-lived instances, so a buffered batch would lose data on shutdown. Finding volume
is low enough that per-object writes are fine; batching is a later cost optimization.

Fire-and-forget via the shared bounded pool (never blocks the request path). Credentials are
the tenant's own AWS key (stored write-only). boto3 is imported lazily so the module loads
even where boto3 isn't installed (tests mock the put).
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid

from . import siem  # reuse _fields + _RANK for a consistent event shape/threshold

log = logging.getLogger("uvicorn.error")

# boto3 clients are thread-safe once built, but building one per put costs a fresh TLS
# handshake — cache per credential set. Small hard cap: on overflow just clear (clients
# rebuild on demand), which also evicts entries for since-rotated tenant keys.
_clients: dict[tuple[str, str, str], object] = {}
# Role-based clients carry hour-long STS session credentials, so each cache entry also
# tracks its expiry: (client, expires_epoch). Rebuilt when the session nears expiry.
_role_clients: dict[tuple[str, str, str], tuple[object, float]] = {}
_clients_lock = threading.Lock()
_STS_REFRESH_SLACK = 300     # rebuild when < 5 min of the session remains
_STS_SESSION_SECS = 3600


def _sts_client(region: str):
    """The STS client that assumes customer roles. Its identity is, in order: the
    GCP→AWS federated session (aws_wif, when PALIVANE_AWS_WIF_ROLE_ARN is set — no
    stored secret), else boto3's default chain (instance/task role on AWS self-host,
    or static env keys as the legacy bootstrap)."""
    import boto3  # noqa: PLC0415
    from . import aws_wif

    base = aws_wif.base_credentials()
    if base:
        return boto3.client("sts", region_name=(region or None),
                            aws_access_key_id=base["AccessKeyId"],
                            aws_secret_access_key=base["SecretAccessKey"],
                            aws_session_token=base["SessionToken"])
    return boto3.client("sts", region_name=(region or None))


def _role_client(region: str, role_arn: str, external_id: str):
    """S3 client via STS AssumeRole — the no-stored-secret path. The deployment's own
    AWS identity (_sts_client: WIF-federated on GCP, default chain elsewhere) assumes
    the customer's delivery role, pinned by their per-tenant external ID."""
    import boto3  # noqa: PLC0415

    ck = (region or "", role_arn, external_id)
    now = time.time()
    with _clients_lock:
        hit = _role_clients.get(ck)
        if hit and hit[1] - now > _STS_REFRESH_SLACK:
            return hit[0]
    # AssumeRole is a network call — do it outside the lock. A concurrent duplicate
    # assume is harmless (last one wins the cache slot).
    sts = _sts_client(region)
    kwargs = {"RoleArn": role_arn, "RoleSessionName": "palivane-s3-delivery",
              "DurationSeconds": _STS_SESSION_SECS}
    if external_id:
        kwargs["ExternalId"] = external_id
    creds = sts.assume_role(**kwargs)["Credentials"]
    client = boto3.client("s3", region_name=(region or None),
                          aws_access_key_id=creds["AccessKeyId"],
                          aws_secret_access_key=creds["SecretAccessKey"],
                          aws_session_token=creds["SessionToken"])
    expires = creds["Expiration"].timestamp()
    with _clients_lock:
        if len(_role_clients) >= 64:
            _role_clients.clear()
        _role_clients[ck] = (client, expires)
    return client


def _client(region: str, key_id: str, secret: str, role_arn: str = "",
            external_id: str = ""):
    if role_arn:                 # role takes precedence over a leftover static key pair
        return _role_client(region, role_arn, external_id)
    import boto3  # noqa: PLC0415

    ck = (region or "", key_id, secret)
    with _clients_lock:
        c = _clients.get(ck)
        if c is None:
            if len(_clients) >= 64:
                _clients.clear()
            c = _clients[ck] = boto3.client("s3", region_name=(region or None),
                                            aws_access_key_id=key_id, aws_secret_access_key=secret)
        return c


BRAND = "palivane"   # brand key in the SIEM sourcetype and S3 object paths


def _key(prefix: str) -> str:
    p = (prefix or "").strip().strip("/")
    now = time.gmtime()
    day = time.strftime("%Y/%m/%d", now)
    uid = f"{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}"
    # Tenant-selected brand segment: existing tenants' pipelines (Panther/Athena/Glue)
    # point at the pre-rebrand palivane/findings/ prefix; new tenants use palivane/findings/.
    base = f"{BRAND}/findings/{day}/{uid}.json"
    return f"{p}/{base}" if p else base


def _put(bucket: str, prefix: str, region: str, key_id: str, secret: str, fields: dict,
         role_arn: str = "", external_id: str = "") -> tuple[bool, str]:
    """PUT one finding object to S3. Returns (ok, detail). boto3 imported lazily."""
    try:
        s3 = _client(region, key_id, secret, role_arn=role_arn, external_id=external_id)
    except Exception as e:      # boto3 not installed, or STS refused the AssumeRole
        return False, f"S3 client unavailable: {str(e)[:280]}"
    try:
        s3.put_object(Bucket=bucket, Key=_key(prefix),
                      Body=json.dumps(fields).encode(), ContentType="application/json")
        return True, ""
    except Exception as e:
        return False, str(e)[:300]


def _deliver(bucket: str, prefix: str, region: str, key_id: str, secret: str, fields: dict,
             tenant_id: int, role_arn: str = "", external_id: str = "") -> None:
    """Pool job: put + record the outcome, so a broken bucket/credential is visible."""
    ok, detail = _put(bucket, prefix, region, key_id, secret, fields,
                      role_arn=role_arn, external_id=external_id)
    from . import sink_health
    sink_health.record(tenant_id, "siem_s3", ok, detail)
    if not ok:
        log.warning("SIEM S3 delivery failed (tenant %s, bucket %s): %s",
                    tenant_id, bucket, detail)


def forward_s3(bucket: str, prefix: str, region: str, key_id: str, secret: str,
               min_severity: str, verdict: dict, subject: str = "", actor: str = "",
               surface: str = "", org: str = "",
               tenant_id: int = 0, role_arn: str = "", external_id: str = "") -> None:
    """Deliver a finding to the tenant's S3 sink if configured (an assumable role, or a
    static key pair) and severity >= min_severity. Non-blocking and best-effort, but
    failures are logged + counted (sink_health)."""
    if not (bucket and (role_arn or (key_id and secret))):
        return
    if siem._RANK.get(verdict.get("severity"), 0) < siem._RANK.get(min_severity or "high", 3):
        return
    fields = siem._fields(verdict, subject, actor, surface, org)
    from .dispatch import submit
    submit(_deliver, bucket, prefix, region, key_id, secret, fields, tenant_id,
           role_arn, external_id)


def test(bucket: str, prefix: str, region: str, key_id: str, secret: str,
         role_arn: str = "", external_id: str = "") -> tuple[bool, str]:
    """Synchronously write a sample object so the console can validate the config."""
    if not (bucket and (role_arn or (key_id and secret))):
        return False, "bucket plus an IAM role ARN or an AWS key id + secret are required"
    fields = siem._fields({"severity": "high", "risk_score": 75, "finding_id": 0,
                           "signals": [{"category": "secret_leak"}]},
                          subject="Palivane S3 test event", actor="palivane", surface="test", org="")
    fields["event"] = "test"
    return _put(bucket, prefix, region, key_id, secret, fields,
                role_arn=role_arn, external_id=external_id)
