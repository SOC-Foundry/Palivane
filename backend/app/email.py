"""Outbound email (stdlib SMTP) — the delivery plane for password resets, join-request
mailbox verification, and invites.

Deliberately provider-neutral: point SMTP_HOST at a Google Workspace relay, SES SMTP,
SendGrid, or anything else. Dark by default — enabled() is false until SMTP_HOST and
MAIL_FROM are set, and every calling flow degrades to its email-less behavior, so a bare
deployment keeps working exactly as before.

Delivery is best-effort and non-blocking: sends ride the shared bounded dispatch pool
(same as alerts/SIEM) so a slow mail server can never add latency to the request path.
"""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from .config import settings
from .dispatch import submit

log = logging.getLogger("uvicorn.error")


def enabled() -> bool:
    return bool(settings.smtp_host and settings.mail_from)


def _send_sync(to: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"] = settings.mail_from
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as s:
            if settings.smtp_tls:
                s.starttls()
            if settings.smtp_user:
                s.login(settings.smtp_user, settings.smtp_pass)
            s.send_message(msg)
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
