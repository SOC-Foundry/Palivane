"""SSRF guard for user-supplied URLs (alert webhooks, per-tenant gateway upstreams).

In a shared/multi-tenant deployment a tenant admin can set URLs the *server* then fetches.
`is_safe_url` rejects non-http(s) schemes and any host that resolves to a private,
loopback, link-local, reserved, or metadata address — so those URLs can't be turned into
an SSRF into your cloud metadata or internal network.

`is_safe_url` alone leaves a DNS-rebinding window: it resolves+checks, but the HTTP client
then resolves again independently, so an attacker with a low-TTL record can pass the check
with a public IP and serve 169.254.169.254 at connect time. `safe_client()` / `safe_urlopen()`
close that — they resolve+validate once and pin the connection to that exact IP, preserving
the hostname for the Host header and TLS SNI so certificate validation is unchanged. Use
those for any server-side fetch of a tenant/user-influenced URL. Unresolvable hosts fail
closed (rejected) — a guard shouldn't treat "doesn't resolve right now" as safe.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import httpx


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


def pin_ip(host: str) -> str | None:
    """Resolve `host` to a single public IP to pin a connection to, or None if it's a blocked
    literal address, resolves to any internal address, or doesn't resolve. Rejects when ANY
    resolved address is internal — we can't know which one a later resolution would pick."""
    try:
        ipaddress.ip_address(host)                 # already a literal IP
        return host if not _blocked_ip(host) else None
    except ValueError:
        pass
    try:
        ips = [ai[4][0] for ai in socket.getaddrinfo(host, None)]
    except Exception:
        return None
    if not ips or any(_blocked_ip(ip) for ip in ips):
        return None
    return ips[0]


class _PinnedHTTPTransport(httpx.HTTPTransport):
    """Pin each connection to an IP validated at resolve time, closing the DNS-rebinding
    window between the check and httpx's own resolution. We connect to that exact IP but keep
    the hostname for the Host header (set at request-build time) and the TLS SNI, so cert
    validation is unchanged."""

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        u = request.url
        if u.scheme not in ("http", "https"):
            raise httpx.ConnectError(f"blocked URL scheme: {u.scheme}", request=request)
        ip = pin_ip(u.host)
        if ip is None:
            raise httpx.ConnectError(
                f"blocked host (internal/loopback/metadata or unresolvable): {u.host}",
                request=request)
        request.url = u.copy_with(host=ip)
        if u.scheme == "https":
            request.extensions = {**request.extensions, "sni_hostname": u.host}
        return super().handle_request(request)


def safe_client(**kwargs) -> httpx.Client:
    """An httpx.Client whose connections are pinned to an SSRF-validated IP. Drop-in for
    httpx.Client(...) on any server-side fetch of a tenant/user-influenced URL."""
    return httpx.Client(transport=_PinnedHTTPTransport(), **kwargs)


def safe_urlopen(req, timeout: float = 8.0) -> httpx.Response:
    """Send a urllib.request.Request through the pinned transport, so urllib-based callers
    get IP-pinning without rebuilding their request. Raises on a network error or non-2xx
    (like urllib.request.urlopen), so existing try/except callers behave the same."""
    with safe_client(timeout=timeout) as c:
        r = c.request(req.get_method(), req.full_url,
                      content=req.data, headers=dict(req.header_items()))
        r.raise_for_status()
        return r
