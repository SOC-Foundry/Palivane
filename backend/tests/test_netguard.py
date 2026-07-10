"""SSRF guard: is_safe_url + its use in the alert webhook and gateway upstream config."""

from __future__ import annotations

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
