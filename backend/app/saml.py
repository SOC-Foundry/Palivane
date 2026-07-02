"""SAML 2.0 SP helpers for per-tenant SSO — thin wrapper over python3-saml (xmlsec).

We are the Service Provider. Given a tenant's IdP config (entity id, SSO URL, signing
cert) and our SP URLs (derived from the request), this builds the redirect for
SP-initiated login and validates the SAMLResponse at the ACS. Signature/audience/
conditions are enforced by python3-saml with strict=True + wantAssertionsSigned.
"""
from __future__ import annotations

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
_EMAIL_ATTRS = ("email", "mail", "emailAddress",
                "urn:oid:0.9.2342.19200300.100.1.3",
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")


class SAMLError(Exception):
    """Any failure building or validating a SAML exchange — surfaced as an auth error."""


def _settings(cfg, sp_entity_id: str, acs_url: str) -> dict:
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": sp_entity_id,
            "assertionConsumerService": {"url": acs_url, "binding": _POST},
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": cfg.idp_entity_id,
            "singleSignOnService": {"url": cfg.idp_sso_url, "binding": _REDIRECT},
            "x509cert": cfg.idp_x509_cert,
        },
        "security": {
            "authnRequestsSigned": False,
            "wantMessagesSigned": False,
            "wantAssertionsSigned": True,   # the IdP must sign the assertion
            "requestedAuthnContext": False,
        },
    }


def _auth(req: dict, cfg, sp_entity_id: str, acs_url: str) -> OneLogin_Saml2_Auth:
    return OneLogin_Saml2_Auth(req, old_settings=_settings(cfg, sp_entity_id, acs_url))


def login_url(req: dict, cfg, sp_entity_id: str, acs_url: str, relay_state: str = "") -> str:
    """The IdP redirect URL for SP-initiated login (HTTP-Redirect binding)."""
    try:
        return _auth(req, cfg, sp_entity_id, acs_url).login(return_to=relay_state or None)
    except Exception as e:
        raise SAMLError(f"could not build SAML request: {e}")


def _pick_email(attributes: dict, nameid: str) -> str:
    for k in _EMAIL_ATTRS:
        v = attributes.get(k)
        if v:
            return (v[0] if isinstance(v, list) else v)
    return nameid if nameid and "@" in nameid else ""


def process_acs(req: dict, cfg, sp_entity_id: str, acs_url: str) -> dict:
    """Validate a SAMLResponse posted to the ACS; return {email, nameid, attributes}."""
    try:
        auth = _auth(req, cfg, sp_entity_id, acs_url)
        auth.process_response()
    except Exception as e:
        raise SAMLError(f"SAML response error: {e}")
    errors = auth.get_errors()
    if errors:
        raise SAMLError(f"SAML validation failed: {', '.join(errors)}")
    if not auth.is_authenticated():
        raise SAMLError("SAML response not authenticated")
    attrs = auth.get_attributes() or {}
    nameid = auth.get_nameid() or ""
    email = _pick_email(attrs, nameid)
    if not email:
        raise SAMLError("no email in SAML assertion")
    return {"email": email, "nameid": nameid, "attributes": attrs}


def sp_metadata(cfg, sp_entity_id: str, acs_url: str) -> str:
    settings = OneLogin_Saml2_Settings(_settings(cfg, sp_entity_id, acs_url),
                                       sp_validation_only=True)
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    if errors:
        raise SAMLError(f"invalid SP metadata: {', '.join(errors)}")
    return metadata.decode() if isinstance(metadata, bytes) else metadata
