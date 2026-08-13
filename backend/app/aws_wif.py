"""GCP→AWS web-identity federation — base AWS credentials with no stored secret.

The hosted runtime lives on Cloud Run, but S3 delivery must assume customer roles in
AWS. Rather than shipping a static AWS access key, the runtime exchanges its own GCP
identity for AWS credentials:

  1. Fetch an OIDC identity token for this instance's service account from the GCP
     metadata server (audience = PALIVANE_AWS_WIF_AUDIENCE).
  2. Call sts:AssumeRoleWithWebIdentity on PALIVANE_AWS_WIF_ROLE_ARN — an AWS role
     whose trust policy federates accounts.google.com, pinned to the service account's
     unique ID (accounts.google.com:sub) and the audience (accounts.google.com:oaud).
     This STS call is unsigned: the Google token IS the credential.
  3. Use those hour-long session credentials as the BASE identity that then assumes
     each customer's delivery role (role chaining; chained sessions are capped at 1h,
     which matches siem_s3._STS_SESSION_SECS).

Unconfigured (no PALIVANE_AWS_WIF_ROLE_ARN) this module is inert and siem_s3 falls
back to boto3's default credential chain — instance/task role on AWS self-host, or
static env keys as the legacy bootstrap.

Credentials are cached and refreshed shortly before expiry; failures raise to the
caller (siem_s3._put's try/except), so a broken federation surfaces in sink_health
and the console test buttons like any other delivery error.
"""

from __future__ import annotations

import threading
import time
import urllib.parse
import urllib.request

from .config import settings

# GCP metadata server: identity tokens for the instance's service account. Fixed IP
# alias `metadata.google.internal`; the Metadata-Flavor header is required.
_METADATA_URL = ("http://metadata.google.internal/computeMetadata/v1/instance/"
                 "service-accounts/default/identity?audience={aud}")

_lock = threading.Lock()
_cached: dict | None = None      # {"AccessKeyId", "SecretAccessKey", "SessionToken", "exp": epoch}
_REFRESH_SLACK = 300             # refresh when < 5 min of the session remains


def configured() -> bool:
    return bool(settings.aws_wif_role_arn)


def _identity_token() -> str:
    """This instance's OIDC identity token from the GCP metadata server (~1h validity)."""
    url = _METADATA_URL.format(aud=urllib.parse.quote(settings.aws_wif_audience))
    req = urllib.request.Request(url, headers={"Metadata-Flavor": "Google"})
    with urllib.request.urlopen(req, timeout=3) as resp:
        return resp.read().decode().strip()


def _exchange() -> dict:
    """Trade the GCP identity token for AWS session credentials (unsigned STS call)."""
    import boto3  # noqa: PLC0415
    from botocore import UNSIGNED  # noqa: PLC0415
    from botocore.config import Config  # noqa: PLC0415

    sts = boto3.client("sts", config=Config(signature_version=UNSIGNED))
    resp = sts.assume_role_with_web_identity(
        RoleArn=settings.aws_wif_role_arn,
        RoleSessionName="palivane-wif",
        WebIdentityToken=_identity_token(),
        DurationSeconds=3600,
    )
    c = resp["Credentials"]
    return {"AccessKeyId": c["AccessKeyId"], "SecretAccessKey": c["SecretAccessKey"],
            "SessionToken": c["SessionToken"], "exp": c["Expiration"].timestamp()}


def base_credentials() -> dict | None:
    """The federated base credentials, or None when WIF isn't configured. Cached;
    re-exchanged when the session nears expiry. Raises on exchange failure so the
    caller's error path (sink_health / test-endpoint detail) reports the real cause."""
    if not configured():
        return None
    global _cached
    now = time.time()
    with _lock:
        if _cached and _cached["exp"] - now > _REFRESH_SLACK:
            return _cached
    fresh = _exchange()          # network calls outside the lock; last writer wins
    with _lock:
        _cached = fresh
        return _cached


def reset() -> None:
    """Test hook: drop the cached session."""
    global _cached
    with _lock:
        _cached = None
