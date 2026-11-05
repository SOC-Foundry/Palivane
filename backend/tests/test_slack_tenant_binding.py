"""Slack data lands only in the org it belongs to (security review H1/H2). An install
completes only in the browser that asked for the link, one org holds a workspace, and
events route to exactly one connector installed through the published app. Inert values."""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import slack_events, slack_install
from app.config import settings
from app.database import Base
from app.models import SaasConnector


@pytest.fixture
def db(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    monkeypatch.setattr(settings, "slack_client_id", "cid")
    monkeypatch.setattr(settings, "slack_client_secret", "csecret")
    monkeypatch.setattr("app.saas_connectors.store_credentials",
                        lambda row, creds, db=None: setattr(row, "credentials_enc", "sealed"))
    monkeypatch.setattr("app.audit_log.record", lambda *a, **k: None)
    yield s
    s.close()


def _slack_says(monkeypatch, team="T1", app="A1", enterprise=None):
    data = {"ok": True, "access_token": "bot-placeholder", "app_id": app,
            "team": {"id": team, "name": f"ws-{team}"} if team else None,
            "enterprise": {"id": enterprise, "name": "grid"} if enterprise else None}
    monkeypatch.setattr("app.saas_connectors._http_json", lambda *a, **k: data)


def _state_for(tenant_id):
    url, nonce = slack_install.install_url(tenant_id, "https://app.example/cb")
    from urllib.parse import parse_qs, urlsplit
    return parse_qs(urlsplit(url).query)["state"][0], nonce


def test_install_needs_the_browser_that_asked_for_the_link(db, monkeypatch):
    _slack_says(monkeypatch)
    state, nonce = _state_for(1)
    for wrong in ("", "someone-elses-nonce"):
        with pytest.raises(slack_install.InstallError):
            slack_install.complete_install(db, "code", state, "https://app.example/cb", wrong)
    row = slack_install.complete_install(db, "code", state, "https://app.example/cb", nonce)
    assert row.tenant_id == 1
    assert row.state["team_id"] == "T1" and row.state["api_app_id"] == "A1"
    assert row.state["app_installed"] is True


def test_one_org_per_workspace(db, monkeypatch):
    _slack_says(monkeypatch)
    state, nonce = _state_for(1)
    slack_install.complete_install(db, "code", state, "https://app.example/cb", nonce)
    state2, nonce2 = _state_for(2)
    with pytest.raises(slack_install.InstallError, match="another org"):
        slack_install.complete_install(db, "code", state2, "https://app.example/cb", nonce2)
    # the same org reinstalling is fine
    state3, nonce3 = _state_for(1)
    slack_install.complete_install(db, "code", state3, "https://app.example/cb", nonce3)


def _row(db, tenant_id, **state):
    r = SaasConnector(tenant_id=tenant_id, platform="slack_messages", label=f"c{tenant_id}",
                      active=True, state=state)
    db.add(r)
    db.commit()
    return r


def test_events_go_only_to_the_app_install_for_that_app(db):
    mine = _row(db, 1, team_id="T1", app_installed=True, api_app_id="A1")
    _row(db, 2, team_id="T1")                                   # pasted token, same workspace
    assert slack_events._connector_for_team(db, "T1", "", "A1").id == mine.id
    assert slack_events._connector_for_team(db, "T1", "", "A9") is None   # another app's event
    assert slack_events._connector_for_team(db, "T1", "", "") is None


def test_pasted_connectors_get_no_events_where_the_published_app_runs(db):
    _row(db, 2, team_id="T1")
    assert slack_events._connector_for_team(db, "T1", "", "A1") is None


def test_self_host_pasted_connector_needs_to_be_the_only_claim(db, monkeypatch):
    monkeypatch.setattr(settings, "slack_client_id", "")        # no published app
    only = _row(db, 1, team_id="T1")
    assert slack_events._connector_for_team(db, "T1").id == only.id
    _row(db, 2, team_id="T1")                                   # a second org claims it
    assert slack_events._connector_for_team(db, "T1") is None


def test_grid_install_routes_by_enterprise_id(db):
    grid = _row(db, 1, team_id="", enterprise_id="E1", app_installed=True, api_app_id="A1")
    assert slack_events._connector_for_team(db, "T7", "E1", "A1").id == grid.id
