"""Operational endpoints: /livez, /readyz, and Prometheus /metrics."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import app.main as main


def test_livez(raw_client):
    r = raw_client.get("/livez")
    assert r.status_code == 200 and r.json()["status"] == "live"


def test_readyz_ok_when_db_reachable(raw_client):
    r = raw_client.get("/readyz")
    assert r.status_code == 200 and r.json()["status"] == "ready"


def test_metrics_exposition_and_request_counter(raw_client, monkeypatch):
    monkeypatch.setattr(main.settings, "metrics_token", "sekret")
    raw_client.get("/livez")   # generate at least one recorded request
    r = raw_client.get("/metrics", headers={"Authorization": "Bearer sekret"})
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    body = r.text
    assert "palivane_http_requests_total" in body
    assert "palivane_http_request_duration_seconds" in body
    # route is labelled by template (here the concrete /livez path)
    assert "/livez" in body


def test_metrics_token_gate(raw_client, monkeypatch):
    monkeypatch.setattr(main.settings, "metrics_token", "sekret")
    assert raw_client.get("/metrics").status_code == 401
    assert raw_client.get("/metrics", headers={"Authorization": "Bearer sekret"}).status_code == 200
    assert raw_client.get("/metrics?token=sekret").status_code == 200
    assert raw_client.get("/metrics?token=nope").status_code == 401
    assert raw_client.get("/metrics", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert raw_client.get("/metrics", headers={"Authorization": "Basic sekret"}).status_code == 401


@pytest.mark.parametrize("peer", ["203.0.113.7", "10.0.0.5", "127.0.0.1", "::1"])
def test_metrics_is_404_without_a_token_from_any_peer(db_factory, monkeypatch, peer):
    """No token configured = no exposition, for every caller (SEC-04). Same as the
    /api/admin/* operator routes. Loopback gets no carve-out: behind a same-host proxy
    that doesn't add X-Forwarded-For every request arrives from 127.0.0.1."""
    monkeypatch.setattr(main.settings, "metrics_token", "")
    c = TestClient(main.app, client=(peer, 50000))
    r = c.get("/metrics")
    assert r.status_code == 404
    assert "palivane_http_requests_total" not in r.text
    # A spoofed forwarding header changes nothing, and neither does a stray token.
    assert c.get("/metrics", headers={"X-Forwarded-For": "127.0.0.1"}).status_code == 404
    assert c.get("/metrics?token=anything").status_code == 404
