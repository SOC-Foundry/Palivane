"""SSRF guard: is_safe_url + its use in the alert webhook and gateway upstream config."""

from __future__ import annotations

import httpx
import pytest

import app.alerts as alerts
import app.netguard as ng


def test_is_safe_url():
    assert ng.is_safe_url("https://8.8.8.8/") is True             # public IP literal
    assert ng.is_safe_url("https://hooks.invalid/x") is False     # unresolvable -> fail closed
    assert ng.is_safe_url("http://169.254.169.254/latest/meta-data/") is False  # cloud metadata
    assert ng.is_safe_url("http://127.0.0.1:9000/") is False      # loopback
    assert ng.is_safe_url("http://10.0.0.5/hook") is False        # private
    assert ng.is_safe_url("http://localhost/") is False           # resolves to loopback
    assert ng.is_safe_url("ftp://8.8.8.8/") is False              # non-http scheme
    assert ng.is_safe_url("") is False


def test_is_safe_url_static():
    # No DNS: literal internal IPs are rejected, hostnames pass (deferred to send-time).
    assert ng.is_safe_url_static("http://169.254.169.254/") is False   # metadata literal
    assert ng.is_safe_url_static("http://127.0.0.1/") is False         # loopback literal
    assert ng.is_safe_url_static("http://10.0.0.5/") is False          # private literal
    assert ng.is_safe_url_static("https://8.8.8.8/") is True           # public literal
    assert ng.is_safe_url_static("https://collector.acme.com/in") is True  # hostname passes
    assert ng.is_safe_url_static("https://anything.invalid/x") is True     # no DNS at set time
    assert ng.is_safe_url_static("ftp://8.8.8.8/") is False            # non-http scheme
    assert ng.is_safe_url_static("") is False


def test_webhook_send_refuses_internal():
    assert alerts.send_sync("http://169.254.169.254/", {"text": "x"}) is False
    assert alerts.send_sync("http://127.0.0.1:8080/hook", {"text": "x"}) is False


def test_webhook_and_siem_reject_internal_at_set_time(client):
    # Literal internal targets are refused when the admin sets them (early feedback).
    assert client.patch("/api/tenant", json={"alert_webhook": "http://169.254.169.254/x"}).status_code == 400
    assert client.patch("/api/tenant", json={"siem_url": "http://127.0.0.1:8088/in"}).status_code == 400
    # A normal public hostname is accepted (no DNS coupling at set time).
    assert client.patch("/api/tenant", json={"alert_webhook": "https://hooks.slack.com/x"}).status_code == 200


def test_upstream_rejects_internal_base(client):
    r = client.put("/api/upstreams/openai", json={"base_url": "http://169.254.169.254/v1", "key": "sk-x"})
    assert r.status_code == 400
    # an unresolvable / public host is accepted (no internal reach)
    r2 = client.put("/api/upstreams/openai", json={"base_url": "https://upstream.invalid/v1", "key": "sk-x"})
    assert r2.status_code == 200


# --- IP pinning (DNS-rebinding fix) ---------------------------------------------------

def test_pin_ip_literal_addresses():
    assert ng.pin_ip("8.8.8.8") == "8.8.8.8"                 # public literal — pinned as-is
    assert ng.pin_ip("169.254.169.254") is None             # cloud metadata
    assert ng.pin_ip("127.0.0.1") is None                   # loopback
    assert ng.pin_ip("10.0.0.5") is None                    # private


def test_pin_ip_resolution(monkeypatch):
    """A host that resolves to a public IP is pinned to it; one that resolves to an internal
    IP is rejected even though the *name* looks innocuous (the rebind case)."""
    def fake(host, *a, **k):
        addrs = {"good.example": "93.184.216.34", "rebind.example": "169.254.169.254"}
        if host not in addrs:
            raise OSError("no such host")
        return [(2, 1, 6, "", (addrs[host], 0))]
    monkeypatch.setattr(ng.socket, "getaddrinfo", fake)
    assert ng.pin_ip("good.example") == "93.184.216.34"
    assert ng.pin_ip("rebind.example") is None
    assert ng.pin_ip("nxdomain.example") is None            # unresolvable -> fail closed


def test_safe_client_blocks_internal_literal_host():
    # No DNS needed: a private literal target must be refused by the transport itself.
    with ng.safe_client(timeout=2) as c:
        with pytest.raises(httpx.ConnectError):
            c.get("http://127.0.0.1:1/")


def test_safe_client_rejects_non_http_scheme():
    with ng.safe_client(timeout=2) as c:
        with pytest.raises(httpx.ConnectError):
            c.get("file:///etc/passwd")


def test_safe_client_pins_to_validated_ip(monkeypatch):
    """The connection must target the IP validated at resolve time, not re-resolve. We stub
    resolution to a public IP and assert the URL handed to the underlying transport carries
    that IP as its host while the SNI/Host stays the original name."""
    monkeypatch.setattr(ng, "pin_ip", lambda host: "93.184.216.34" if host == "up.example" else None)
    seen = {}

    def fake_handle(self, request):
        seen["host"] = request.url.host
        seen["sni"] = request.extensions.get("sni_hostname")
        seen["hdr_host"] = request.headers.get("host")
        return httpx.Response(200, request=request)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", fake_handle)
    with ng.safe_client(timeout=2) as c:
        r = c.get("https://up.example/v1/models")
    assert r.status_code == 200
    assert seen["host"] == "93.184.216.34"        # connected to the pinned IP
    assert seen["sni"] == "up.example"            # TLS SNI/cert still the hostname
    assert seen["hdr_host"] == "up.example"       # Host header unchanged
