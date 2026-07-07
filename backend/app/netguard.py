"""SSRF guard for user-supplied URLs (alert webhooks, per-tenant gateway upstreams).

In a shared/multi-tenant deployment a tenant admin can set URLs the *server* then fetches.
`is_safe_url` rejects non-http(s) schemes and any host that resolves to a private,
loopback, link-local, reserved, or metadata address — so those URLs can't be turned into
an SSRF into your cloud metadata or internal network.

Note: this resolves and checks at call time. A determined attacker could still DNS-rebind
between check and connect; pinning the resolved IP on the actual connection would close
that, and is a reasonable follow-up. Unresolvable hosts are allowed (they can't reach
anything) so a typo just fails to connect rather than being flagged as malicious.
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
    except socket.gaierror:
        return True   # unresolvable -> can't reach an internal service
    except Exception:
        return False
    return bool(ips) and not any(_blocked_ip(ip) for ip in ips)
