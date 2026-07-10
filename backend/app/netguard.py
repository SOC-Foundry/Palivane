"""SSRF guard for user-supplied URLs (alert webhooks, per-tenant gateway upstreams).

In a shared/multi-tenant deployment a tenant admin can set URLs the *server* then fetches.
`is_safe_url` rejects non-http(s) schemes and any host that resolves to a private,
loopback, link-local, reserved, or metadata address — so those URLs can't be turned into
an SSRF into your cloud metadata or internal network.

Note: this resolves and checks at call time. A determined attacker could still DNS-rebind
between check and connect; pinning the resolved IP on the actual connection would close
that, and is a reasonable follow-up. Unresolvable hosts fail closed (rejected) — a guard
shouldn't treat "doesn't resolve right now" as safe.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def _blocked_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable -> treat as unsafe
    return (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
            or a.is_multicast or a.is_unspecified)


def is_safe_url_static(url: str) -> bool:
    """Cheap set-time check (no DNS): require an http(s) scheme, and if the host is a literal
    IP it must be public (blocks http://169.254.169.254, http://127.0.0.1, …). Hostnames pass
    here and are re-checked with DNS by `is_safe_url` at send time. Used to give an admin
    immediate feedback without coupling config writes to DNS."""
    if not url:
        return False
    try:
        u = urlparse(url.strip())
    except ValueError:
        return False
    if u.scheme not in ("http", "https") or not u.hostname:
        return False
    try:
        ipaddress.ip_address(u.hostname)   # literal IP?
    except ValueError:
        return True                        # hostname — defer to the send-time DNS guard
    return not _blocked_ip(u.hostname)


def is_safe_url(url: str) -> bool:
    """True if `url` is an http(s) URL whose host does not resolve to an internal address."""
    if not url:
        return False
    try:
        u = urlparse(url.strip())
    except ValueError:
        return False
    if u.scheme not in ("http", "https") or not u.hostname:
        return False
    try:
        ips = {ai[4][0] for ai in socket.getaddrinfo(u.hostname, None)}
    except Exception:
        return False   # unresolvable / lookup error -> fail closed (a guard, not a resolver)
    return bool(ips) and not any(_blocked_ip(ip) for ip in ips)
