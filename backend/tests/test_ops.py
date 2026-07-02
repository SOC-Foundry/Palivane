"""Operational endpoints: /livez, /readyz, and Prometheus /metrics."""

from __future__ import annotations

import app.main as main


def test_livez(raw_client):
    r = raw_client.get("/livez")
    assert r.status_code == 200 and r.json()["status"] == "live"


def test_readyz_ok_when_db_reachable(raw_client):
    r = raw_client.get("/readyz")
    assert r.status_code == 200 and r.json()["status"] == "ready"


def test_metrics_exposition_and_request_counter(raw_client):
    raw_client.get("/livez")   # generate at least one recorded request
    r = raw_client.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    body = r.text
    assert "warden_http_requests_total" in body
    assert "warden_http_request_duration_seconds" in body
    # route is labelled by template (here the concrete /livez path)
    assert "/livez" in body


def test_metrics_token_gate(raw_client, monkeypatch):
    monkeypatch.setattr(main.settings, "metrics_token", "sekret")
    assert raw_client.get("/metrics").status_code == 401
    assert raw_client.get("/metrics", headers={"Authorization": "Bearer sekret"}).status_code == 200
    assert raw_client.get("/metrics?token=sekret").status_code == 200
    assert raw_client.get("/metrics?token=nope").status_code == 401