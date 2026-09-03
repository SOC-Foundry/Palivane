"""Outbound email — the delivery plane for password resets, join-request mailbox
verification, and invites.

Deliberately provider-neutral, three transports (preferred in this order): the Gmail API
(GMAIL_SA_JSON + GMAIL_SEND_AS — HTTPS, so it works from Cloud Run, which blocks outbound
SMTP to Gmail), stdlib SMTP (point SMTP_HOST at an SMTP relay), or the Cloudflare Email
Service REST API (CF_EMAIL_ACCOUNT_ID + CF_EMAIL_TOKEN). Dark by default — enabled() is
false until MAIL_FROM plus one transport are set, and every calling flow degrades to its
email-less behavior, so a bare deployment keeps working exactly as before.

Delivery is best-effort and non-blocking: sends ride the shared bounded dispatch pool
(same as alerts/SIEM) so a slow mail server can never add latency to the request path.
"""

from __future__ import annotations

import json
import logging
import smtplib
import urllib.request
from email.message import EmailMessage

from .config import settings
from .dispatch import submit

log = logging.getLogger("uvicorn.error")


def enabled() -> bool:
    return bool(settings.mail_from and
                (_gmail_configured() or settings.smtp_host or _cf_configured()))


def _cf_configured() -> bool:
    return bool(settings.cf_email_account_id and settings.cf_email_token)


def _gmail_configured() -> bool:
    return bool(settings.gmail_sa_json and settings.gmail_send_as)


_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GMAIL_SEND_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
_GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.send"


def _gmail_token() -> str:
    """Service-account JWT grant (RFC 7523) with domain-wide delegation, impersonating
    GMAIL_SEND_AS for the gmail.send scope — same flow the Workspace connector uses."""
    import time
    import urllib.parse
    from authlib.jose import jwt   # RS256 assertion signing
    sa = json.loads(settings.gmail_sa_json)
    now = int(time.time())
    assertion = jwt.encode(
        {"alg": "RS256"},
        {"iss": sa["client_email"], "sub": settings.gmail_send_as, "scope": _GMAIL_SCOPE,
         "aud": _GOOGLE_TOKEN_URL, "iat": now, "exp": now + 3600},
        sa["private_key"])
    body = urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": assertion.decode() if isinstance(assertion, bytes) else assertion,
    }).encode()
    req = urllib.request.Request(
        _GOOGLE_TOKEN_URL, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=20) as r:
        tok = json.loads(r.read() or b"{}")
    if not tok.get("access_token"):
        raise RuntimeError(f"gmail token exchange: no access_token ({tok.get('error')})")
    return tok["access_token"]


def _send_gmail(to: str, subject: str, body: str) -> None:
    import base64
    msg = EmailMessage()
    msg["From"] = settings.mail_from
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    req = urllib.request.Request(
        _GMAIL_SEND_URL, data=json.dumps({"raw": raw}).encode(), method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {_gmail_token()}"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        out = json.loads(resp.read() or b"{}")
    if not out.get("id"):
        raise RuntimeError(f"gmail send: no message id ({out})")


def _send_smtp(to: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"] = settings.mail_from
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as s:
        if settings.smtp_tls:
            s.starttls()
        if settings.smtp_user:
            s.login(settings.smtp_user, settings.smtp_pass)
        s.send_message(msg)


def _send_cf(to: str, subject: str, body: str) -> None:
    # https://developers.cloudflare.com/email-service/ — REST field names differ from the
    # Workers binding: from.address (not .email), snake_case. Text-only, like the SMTP path.
    url = (f"https://api.cloudflare.com/client/v4/accounts/"
           f"{settings.cf_email_account_id}/email/sending/send")
    payload = {"to": to,
               "from": {"address": settings.mail_from, "name": "Palivane"},
               "subject": subject, "text": body}
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {settings.cf_email_token}"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        out = json.loads(resp.read() or b"{}")
    if not out.get("success"):
        raise RuntimeError(f"cloudflare email api: {out.get('errors')}")


def _send_sync(to: str, subject: str, body: str) -> None:
    try:
        if _gmail_configured():   # HTTPS — the only Gmail path that works from Cloud Run
            _send_gmail(to, subject, body)
        elif settings.smtp_host:  # an explicitly pointed relay beats the platform API
            _send_smtp(to, subject, body)
        else:
            _send_cf(to, subject, body)
    except Exception as e:   # best-effort, like alert/SIEM delivery
        log.warning("email to %s (%r) failed: %s", to, subject, str(e)[:200])


def send(to: str, subject: str, body: str) -> None:
    """Queue one email on the dispatch pool. No-op (with a debug log) when disabled."""
    if not enabled():
        log.debug("email disabled — dropping %r to %s", subject, to)
        return
    submit(_send_sync, to, subject, body)


def base_url() -> str:
    """Absolute URL links in emails point at. Falls back to localhost for dev."""
    return settings.public_base_url or "http://localhost:5173"
