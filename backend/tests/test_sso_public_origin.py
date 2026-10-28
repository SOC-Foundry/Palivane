"""Tenant SSO tells IdPs, and checks against, the deployment's configured public origin.

Behind the edge Worker the request arrives on the Cloud Run origin over http, so building the
OIDC redirect_uri or the SAML entity ID / ACS from the request gave IdPs an address that is
neither the one the console tells admins to register nor one a Host header should pick.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

import app.oidc as oidc_mod
import app.saml as saml_mod
from app.config import settings

PUBLIC = "https://app.example.com"
SPOOFED = {"host": "palivane-origin.a.run.app"}


@pytest.fixture
def public_url(monkeypatch):
    monkeypatch.setattr(settings, "public_base_url", PUBLIC)


def _saml(client):
    r = client.put("/api/saml", json={"idp_entity_id": "https://idp.example/entity",
                                      "idp_sso_url": "https://idp.example/sso",
                                      "idp_x509_cert": "MIIC-fake-cert-body-for-storage-only",
                                      "enabled": True})
    assert r.status_code == 200, r.text


def test_saml_metadata_advertises_the_public_origin(client, raw_client, public_url):
    _saml(client)
    r = raw_client.get("/api/auth/saml/acme/metadata", headers=SPOOFED)
    assert r.status_code == 200
    assert f"{PUBLIC}/api/auth/saml/acme/acs" in r.text
    assert "run.app" not in r.text and "http://app.example.com" not in r.text


def test_saml_login_builds_the_request_from_the_public_origin(client, raw_client, public_url,
                                                              monkeypatch):
    _saml(client)
    seen = {}

    def _capture(req, cfg, sp_entity, acs, relay_state=""):
        seen.update(req=req, sp_entity=sp_entity, acs=acs)
        return "https://idp.example/sso?SAMLRequest=abc", "_req_1"
    monkeypatch.setattr(saml_mod, "login_request", _capture)
    r = raw_client.get("/api/auth/saml/acme/login", headers=SPOOFED, follow_redirects=False)
    assert r.status_code == 302
    assert seen["acs"] == f"{PUBLIC}/api/auth/saml/acme/acs"
    assert seen["sp_entity"] == f"{PUBLIC}/api/auth/saml/acme/metadata"
    # python3-saml checks the response's Destination against this URL: it must be the same
    # origin the metadata gave the IdP, whatever Host the request came in on.
    assert seen["req"]["https"] == "on" and seen["req"]["http_host"] == "app.example.com"
    assert seen["req"]["script_name"] == "/api/auth/saml/acme/login"


def test_oidc_redirect_uri_uses_the_public_origin(client, raw_client, public_url, monkeypatch):
    r = client.put("/api/oidc", json={"issuer": "https://idp.example", "client_id": "cid",
                                      "client_secret": "s", "enabled": True})
    assert r.status_code == 200, r.text
    monkeypatch.setattr(oidc_mod, "discover",
                        lambda issuer: {"authorization_endpoint": "https://idp.example/auth"})
    r = raw_client.get("/api/auth/oidc/acme/login", headers=SPOOFED, follow_redirects=False)
    assert r.status_code == 307
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["redirect_uri"] == [f"{PUBLIC}/api/auth/oidc/acme/callback"]


def test_without_a_public_url_the_request_origin_still_works(client, raw_client, monkeypatch):
    # Local dev / self-host with no PALIVANE_PUBLIC_URL: unchanged behaviour.
    monkeypatch.setattr(settings, "public_base_url", "")
    _saml(client)
    r = raw_client.get("/api/auth/saml/acme/metadata", headers={"host": "palivane.example.com"})
    assert r.status_code == 200
    assert "http://palivane.example.com/api/auth/saml/acme/acs" in r.text
