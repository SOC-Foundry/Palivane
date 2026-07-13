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
import threading
import time
import uuid

from . import siem  # reuse _fields + _RANK for a consistent event shape/threshold

# boto3 clients are thread-safe once built, but building one per put costs a fresh TLS
# handshake — cache per credential set. Small hard cap: on overflow just clear (clients
# rebuild on demand), which also evicts entries for since-rotated tenant keys.
_clients: dict[tuple[str, str, str], object] = {}
_clients_lock = threading.Lock()


def _client(region: str, key_id: str, secret: str):
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


def _key(prefix: str) -> str:
    p = (prefix or "").strip().strip("/")
    now = time.gmtime()
    day = time.strftime("%Y/%m/%d", now)
    uid = f"{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}"
    base = f"warden/findings/{day}/{uid}.json"
    return f"{p}/{base}" if p else base


def _put(bucket: str, prefix: str, region: str, key_id: str, secret: str, fields: dict) -> tuple[bool, str]:
    """PUT one finding object to S3. Returns (ok, detail). boto3 imported lazily."""
    try:
        s3 = _client(region, key_id, secret)
    except Exception as e:      # boto3 not installed
        return False, f"boto3 unavailable: {e}"
    try:
        s3.put_object(Bucket=bucket, Key=_key(prefix),
                      Body=json.dumps(fields).encode(), ContentType="application/json")
        return True, ""
    except Exception as e:
        return False, str(e)[:300]


def forward_s3(bucket: str, prefix: str, region: str, key_id: str, secret: str,
               min_severity: str, verdict: dict, subject: str = "", actor: str = "",
               surface: str = "", org: str = "") -> None:
    """Deliver a finding to the tenant's S3 sink if configured and severity >= min_severity.
    Non-blocking; failures are swallowed (delivery is best-effort, like the HTTP push)."""
    if not (bucket and key_id and secret):
        return
    if siem._RANK.get(verdict.get("severity"), 0) < siem._RANK.get(min_severity or "high", 3):
        return
    fields = siem._fields(verdict, subject, actor, surface, org)
    from .dispatch import submit
    submit(_put, bucket, prefix, region, key_id, secret, fields)


def test(bucket: str, prefix: str, region: str, key_id: str, secret: str) -> tuple[bool, str]:
    """Synchronously write a sample object so the console can validate the config."""
    if not (bucket and key_id and secret):
        return False, "bucket + AWS key id + secret are required"
    fields = siem._fields({"severity": "high", "risk_score": 75, "finding_id": 0,
                           "signals": [{"category": "secret_leak"}]},
                          subject="Warden S3 test event", actor="warden", surface="test", org="")
    fields["event"] = "test"
    return _put(bucket, prefix, region, key_id, secret, fields)
