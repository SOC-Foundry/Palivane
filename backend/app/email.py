"""Outbound email — the delivery plane for password resets, join-request mailbox
verification, and invites.

Deliberately provider-neutral, two transports: stdlib SMTP (point SMTP_HOST at a Google
Workspace relay, SES SMTP, SendGrid, or anything else) or the Cloudflare Email Service
REST API (CF_EMAIL_ACCOUNT_ID + CF_EMAIL_TOKEN — no relay to run; the MAIL_FROM domain
must be onboarded to Email Sending in the Cloudflare account). Dark by default —
enabled() is false until MAIL_FROM plus one transport are set, and every calling flow
degrades to its email-less behavior, so a bare deployment keeps working exactly as before.

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
    return bool(settings.mail_from and (settings.smtp_host or _cf_configured()))


def _cf_configured() -> bool:
    return bool(settings.cf_email_account_id and settings.cf_email_token)


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
        if settings.smtp_host:   # an explicitly pointed relay beats the platform API
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
