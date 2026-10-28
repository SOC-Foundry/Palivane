"""SAML 2.0 SP helpers for per-tenant SSO — thin wrapper over python3-saml (xmlsec).

We are the Service Provider. Given a tenant's IdP config (entity id, SSO URL, signing
cert) and our SP URLs (derived from the request), this builds the redirect for
SP-initiated login and validates the SAMLResponse at the ACS. Signature/audience/
conditions are enforced by python3-saml with strict=True + wantAssertionsSigned.
"""
from __future__ import annotations

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML

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


def login_request(req: dict, cfg, sp_entity_id: str, acs_url: str,
                  relay_state: str = "") -> tuple[str, str]:
    """(IdP redirect URL, AuthnRequest ID) for SP-initiated login (HTTP-Redirect binding).
    The caller keeps the ID so the ACS can insist the response answers THIS request."""
    try:
        auth = _auth(req, cfg, sp_entity_id, acs_url)
        url = auth.login(return_to=relay_state or None)
        return url, auth.get_last_request_id() or ""
    except Exception as e:
        raise SAMLError(f"could not build SAML request: {e}")


def login_url(req: dict, cfg, sp_entity_id: str, acs_url: str, relay_state: str = "") -> str:
    """The IdP redirect URL for SP-initiated login (HTTP-Redirect binding)."""
    return login_request(req, cfg, sp_entity_id, acs_url, relay_state)[0]


def in_response_to(saml_response: str) -> str:
    """The InResponseTo of a posted SAMLResponse, read WITHOUT validation — "" when absent
    (IdP-initiated) or unparseable. Only for routing the ACS; process_acs still validates."""
    try:
        root = OneLogin_Saml2_XML.to_etree(OneLogin_Saml2_Utils.b64decode(saml_response))
        return root.get("InResponseTo") or ""
    except Exception:
        return ""


def _pick_email(attributes: dict, nameid: str) -> str:
    for k in _EMAIL_ATTRS:
        v = attributes.get(k)
        if v:
            return (v[0] if isinstance(v, list) else v)
    return nameid if nameid and "@" in nameid else ""


def process_acs(req: dict, cfg, sp_entity_id: str, acs_url: str,
                request_id: str | None = None) -> dict:
    """Validate a SAMLResponse posted to the ACS; return {email, nameid, attributes}.
    With `request_id`, the SDK also checks the response's InResponseTo against it."""
    try:
        auth = _auth(req, cfg, sp_entity_id, acs_url)
        auth.process_response(request_id=request_id)
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
    # Replay protection material: the assertion id is unique per assertion, and its
    # NotOnOrAfter bounds how long a captured response could be re-POSTed. The caller caches
    # accepted ids until they expire and rejects reuse (the SDK checks signature/conditions
    # but not single-use). get_last_assertion_not_on_or_after() is a list of unix timestamps.
    noa = auth.get_last_assertion_not_on_or_after() or []
    return {"email": email, "nameid": nameid, "attributes": attrs,
            "assertion_id": auth.get_last_assertion_id() or "",
            "not_on_or_after": max(noa) if noa else 0}


def sp_metadata(cfg, sp_entity_id: str, acs_url: str) -> str:
    settings = OneLogin_Saml2_Settings(_settings(cfg, sp_entity_id, acs_url),
                                       sp_validation_only=True)
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    if errors:
        raise SAMLError(f"invalid SP metadata: {', '.join(errors)}")
    return metadata.decode() if isinstance(metadata, bytes) else metadata
