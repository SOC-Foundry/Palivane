"""Blast radius: what a leaked credential can reach, so rotation gets a priority order.

The ledger says where a secret travelled. This says what it unlocks. Two sources:

  static   the kind of credential, from its shape: a classic GitHub PAT reaches every repo
           the user can, a fine-grained one only what it was scoped to, a Slack user token
           acts as the person, a bot token as the app, a live Stripe key moves money.
  aws      an AWS access key id is not itself secret; it names an IAM user. When the org has
           an AWS role Palivane may assume (the same role S3 delivery uses), the user's
           attached and inline policies and groups are read and summarised: "this key can
           read every S3 bucket" instead of "a key leaked". Read-only, once per key, cached.

The assessment is made at capture time, while the value is in memory, and stored under the
secret's fingerprint; the value itself is never kept. Everything is best-effort: a lookup
that fails leaves the static answer in place.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .config import settings
from .models import SecretReach, Tenant

log = logging.getLogger("uvicorn.error")

_lock = threading.Lock()
_inflight: set[tuple[int, str]] = set()

_SEV = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# label -> (kind, scope, severity hint). Refined by prefix below.
_STATIC = {
    "AWS access key id": ("cloud", "An IAM user's key: everything that user's policies allow across the AWS account.", "high"),
    "AWS secret access key": ("cloud", "The secret half of an IAM user's key: everything that user's policies allow.", "high"),
    "GitHub token": ("source", "Classic personal access token: every repository the user can reach, with the scopes granted at creation (often repo and workflow).", "high"),
    "GitHub fine-grained PAT": ("source", "Fine-grained token: only the repositories and permissions chosen at creation, and it expires.", "medium"),
    "Slack token": ("chat", "Slack token: the channels and scopes the app or person it belongs to has.", "medium"),
    "Slack app token": ("chat", "App-level token: a Socket Mode connection, not messages or files.", "low"),
    "Google API key": ("cloud", "Google API key: the APIs it is enabled for and billing on its project; user data only if unrestricted.", "medium"),
    "OpenAI API key": ("provider", "Provider key: spend on the account and whatever data flows through it; files and assistants if any are stored.", "medium"),
    "Anthropic API key": ("provider", "Provider key: spend on the account and whatever data flows through it.", "medium"),
    "Stripe secret key": ("payments", "Live Stripe secret: charges, refunds, payouts and every customer record.", "critical"),
    "Palivane canary": ("test", "The org's self-test value: reaches nothing.", "low"),
}


def classify(label: str, value: str) -> dict:
    kind, scope, sev = _STATIC.get(label, ("unknown", "Scope depends on the service it belongs to; treat as full access until it is rotated.", "medium"))
    v = value or ""
    if label == "GitHub token":
        if v.startswith("ghs_"):
            scope, sev = "GitHub App installation token: the repositories the app is installed on, expires within an hour.", "medium"
        elif v.startswith("gho_") or v.startswith("ghu_"):
            scope, sev = "GitHub OAuth user token: what the user authorised the app for, across their repositories.", "high"
        elif v.startswith("ghr_"):
            scope, sev = "GitHub refresh token: can mint new user tokens.", "high"
    elif label == "Slack token":
        if v.startswith("xoxp-"):
            scope, sev = "Slack user token: acts as the person in every channel and DM they can see.", "high"
        elif v.startswith("xoxb-"):
            scope, sev = "Slack bot token: the channels the app is in, with the scopes it was installed with.", "medium"
        elif v.startswith("xoxr-"):
            scope, sev = "Slack refresh token: can mint new tokens.", "high"
    elif label == "Stripe secret key" and v.startswith(("sk_test_", "rk_test_")):
        scope, sev = "Test-mode Stripe key: sandbox data only, no real money.", "low"
    return {"kind": kind, "scope": scope, "severity": sev, "source": "static", "detail": {}}


# --- AWS: the key id names the user; the org's role reads the user's policies --------------

def _aws_role(tenant: Tenant | None) -> tuple[str, str, str] | None:
    arn = (getattr(tenant, "siem_s3_role_arn", "") or "").strip() if tenant else ""
    if not arn or not settings.role_delivery_principal:
        return None
    from .siem_s3 import external_id
    return arn, external_id(tenant), (getattr(tenant, "siem_s3_region", "") or "").strip()


def _iam_client(role_arn: str, ext_id: str, region: str):
    import boto3  # noqa: PLC0415
    from botocore.config import Config  # noqa: PLC0415

    from .siem_s3 import _sts_client
    sts = _sts_client(region)
    kw = {"RoleArn": role_arn, "RoleSessionName": "palivane-secret-reach", "DurationSeconds": 900}
    if ext_id:
        kw["ExternalId"] = ext_id
    creds = sts.assume_role(**kw)["Credentials"]
    return boto3.client("iam", region_name=(region or None),
                        aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                        aws_session_token=creds["SessionToken"],
                        config=Config(connect_timeout=3, read_timeout=4, retries={"max_attempts": 1}))


_BROAD = {"AdministratorAccess": "critical", "PowerUserAccess": "critical", "IAMFullAccess": "critical",
          "AmazonS3FullAccess": "high", "AmazonEC2FullAccess": "high", "AmazonRDSFullAccess": "high",
          "SecretsManagerReadWrite": "high", "AmazonS3ReadOnlyAccess": "medium", "ReadOnlyAccess": "medium"}


def aws_lookup(tenant: Tenant | None, access_key_id: str) -> dict | None:
    """{user, policies, groups, last_used, severity, scope} for an access key id, or None."""
    role = _aws_role(tenant)
    if role is None or not access_key_id:
        return None
    try:
        iam = _iam_client(*role)
        used = iam.get_access_key_last_used(AccessKeyId=access_key_id)
        user = used.get("UserName") or ""
        if not user:
            return None
        attached = [p["PolicyName"] for p in iam.list_attached_user_policies(UserName=user).get("AttachedPolicies", [])]
        inline = list(iam.list_user_policies(UserName=user).get("PolicyNames", []))
        groups = [g["GroupName"] for g in iam.list_groups_for_user(UserName=user).get("Groups", [])]
        for g in groups[:10]:
            attached += [p["PolicyName"] for p in iam.list_attached_group_policies(GroupName=g).get("AttachedPolicies", [])]
        lu = (used.get("AccessKeyLastUsed") or {})
        sev = "medium"
        for p in attached:
            s = _BROAD.get(p)
            if s and _SEV[s] > _SEV[sev]:
                sev = s
        if inline and _SEV[sev] < _SEV["high"]:
            sev = "high"      # inline policies are custom; assume they grant something real
        names = sorted(set(attached))
        scope = (f"IAM user {user}: " + (", ".join(names[:6]) + (f" and {len(names) - 6} more" if len(names) > 6 else "")
                 if names else "no managed policies") + (f"; {len(inline)} inline polic{'y' if len(inline) == 1 else 'ies'}" if inline else "")
                 + (f"; groups {', '.join(groups[:4])}" if groups else "") + ".")
        return {"user": user, "policies": names, "inline": inline, "groups": groups,
                "last_used": lu.get("LastUsedDate").isoformat() if lu.get("LastUsedDate") else None,
                "last_service": lu.get("ServiceName") or "", "severity": sev, "scope": scope}
    except Exception as e:  # noqa: BLE001 - best effort, the static answer stands
        log.info("secret reach: AWS lookup unavailable (%s)", str(e)[:120])
        return None


def assess(db: Session, tenant: Tenant | None, tenant_id: int, fp: str, label: str, value: str) -> SecretReach | None:
    """The reach of one secret, computed once per fingerprint and stored. Never raises."""
    if db is None or tenant_id is None or not fp:
        return None
    try:
        row = (db.query(SecretReach).filter(SecretReach.tenant_id == tenant_id, SecretReach.secret_fp == fp)
                 .one_or_none())
        if row is not None:
            return row
        key = (tenant_id, fp)
        with _lock:
            if key in _inflight:
                return None
            _inflight.add(key)
        try:
            base = classify(label, value)
            if label == "AWS access key id":
                live = aws_lookup(tenant, value)
                if live:
                    base = {"kind": "cloud", "scope": live["scope"], "severity": live["severity"],
                            "source": "aws", "detail": {k: v for k, v in live.items() if k not in ("scope", "severity")}}
            row = SecretReach(tenant_id=tenant_id, secret_fp=fp, label=label[:64], kind=base["kind"],
                              scope=base["scope"][:500], severity=base["severity"], source=base["source"],
                              detail=base["detail"], checked_at=datetime.now(timezone.utc).replace(tzinfo=None))
            db.add(row)
            db.commit()
            return row
        finally:
            with _lock:
                _inflight.discard(key)
    except Exception:  # noqa: BLE001
        db.rollback()
        return None


def for_fingerprint(db: Session, tenant_id: int, fp: str) -> dict | None:
    row = (db.query(SecretReach).filter(SecretReach.tenant_id == tenant_id, SecretReach.secret_fp == fp)
             .one_or_none())
    return row.to_dict() if row else None
