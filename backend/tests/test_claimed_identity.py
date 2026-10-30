"""Claimed identities may only tighten policy.

A fleet key's per-request `user`, or a device-enrolled key's self-declared identity, is the
client's word: anyone holding such a key can name anyone. Attribution still follows the claim,
but per-user/group overrides and per-actor allowlist entries must not RELAX policy for it —
otherwise naming a colleague with a monitor-only override, a wider disabled-check set, or an
allowlist exemption inherits it. An override may still tighten (re-enable a check, switch
enforcement on) for a claimed actor, and applies in full to an identity the credential proves.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from app.main import _actor_claimed
from app.policies import resolve_disabled, resolve_enforce
from app.service import RECORDED_WHILE_OFF

PII = "SSN 123-45-6789"


class _O:  # stand-in for a PolicyOverride row
    def __init__(self, scope, match, disabled="", enforce=None, channel=""):
        self.id, self.scope, self.match = 1, scope, match
        self.disabled_checks, self.enforce, self.channel = disabled, enforce, channel


def _cats(resp: dict) -> set:
    """Categories the checks flagged. A confirmed leak a turned-off check filtered out is put
    back for the record under RECORDED_WHILE_OFF (it blocks regardless); that isn't the check
    firing, so it doesn't count here."""
    return {s["category"] for s in resp["signals"] if s.get("check") != RECORDED_WHILE_OFF}


def _post(raw_client, key, user="", content=PII):
    r = raw_client.post("/api/ingest/ai-usage",
                        json={"content": content, "destination": "https://chatgpt.com/",
                              "user": user},
                        headers={"X-Palivane-Token": key})
    assert r.status_code == 200, r.text
    return r.json()


def _key(client, actor):
    r = client.post("/api/apikeys", json={"label": "fleet", "actor": actor})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _override(client, **body):
    r = client.post("/api/policies/overrides", json=body)
    assert r.status_code == 200, r.text


# --- resolution primitives ------------------------------------------------------------------

def test_claimed_override_can_only_remove_disabled_checks():
    base = {"secret_leak", "pii_exposure"}
    ovs = [_O("user", "bob@acme.com", "pii_exposure,source_code_leak")]
    # verified: the override replaces the tenant set outright
    assert resolve_disabled(base, "bob@acme.com", ovs)[0] == {"pii_exposure", "source_code_leak"}
    # claimed: source_code_leak isn't disabled tenant-wide, so a claim can't disable it;
    # secret_leak is re-enabled (tightening), which a claim may do
    d, m = resolve_disabled(base, "bob@acme.com", ovs, claimed=True)
    assert d == {"pii_exposure"} and m["match"] == "bob@acme.com"


def test_claimed_override_can_switch_enforcement_on_never_off():
    off = [_O("group", "*@acme.com", enforce=False)]
    on = [_O("group", "*@acme.com", enforce=True)]
    assert resolve_enforce(True, "x@acme.com", off)[0] is False
    assert resolve_enforce(True, "x@acme.com", off, claimed=True)[0] is True
    assert resolve_enforce(False, "x@acme.com", on, claimed=True)[0] is True
    assert resolve_enforce(False, "x@acme.com", off, claimed=True)[0] is False


def test_actor_claimed():
    assert _actor_claimed("", "", False) is False                       # nobody named
    assert _actor_claimed("e@acme.com", "e@acme.com", False) is False   # the key's own identity
    assert _actor_claimed("E@Acme.com ", "e@acme.com", False) is False  # same, normalized
    assert _actor_claimed("dave@acme.com", "e@acme.com", False) is True  # someone else
    assert _actor_claimed("dave@acme.com", "", False) is True           # shared ingest token
    assert _actor_claimed("e@acme.com", "e@acme.com", True) is True     # self-enrolled identity


def test_claimed_actor_gets_only_everyone_allowlist_entries(db_factory):
    from app import allowlist
    from app.models import AllowEntry
    db = db_factory()
    later = datetime.utcnow() + timedelta(days=1)
    db.add_all([AllowEntry(tenant_id=1, pattern="make deploy", actor="dave@acme.com",
                           expires_at=later),
                AllowEntry(tenant_id=1, pattern="make test", actor="", expires_at=later)])
    db.commit()
    mine = {e.pattern for e in allowlist.active_entries(db, 1, "dave@acme.com", "")}
    claimed = {e.pattern for e in allowlist.active_entries(db, 1, "dave@acme.com", "",
                                                            claimed=True)}
    assert mine == {"make deploy", "make test"} and claimed == {"make test"}
    db.close()


# --- end to end -----------------------------------------------------------------------------

def test_fleet_key_claim_cannot_borrow_a_relaxing_override(client, raw_client):
    _override(client, scope="group", match="*@svc.acme.com", disabled_checks=["pii_exposure"])
    fleet = _key(client, "fleet@acme.com")
    # Naming a service account doesn't inherit its exemption...
    resp = _post(raw_client, fleet, user="bot@svc.acme.com")
    assert "pii_exposure" in _cats(resp)
    # ...while a key that IS that identity gets it.
    assert "pii_exposure" not in _cats(_post(raw_client, _key(client, "bot@svc.acme.com")))


def test_fleet_key_claim_still_gets_a_tightening_override(client, raw_client):
    # The org disables PII tenant-wide; one user's override re-enables it. Tightening is safe
    # to honour on a claim — the worst a false claim does is make a scan stricter.
    assert client.patch("/api/tenant", json={"disabled_checks": ["pii_exposure"]}).status_code == 200
    _override(client, scope="user", match="dave@acme.com", disabled_checks=[])
    fleet = _key(client, "fleet@acme.com")
    assert "pii_exposure" not in _cats(_post(raw_client, fleet, user="carol@acme.com"))
    assert "pii_exposure" in _cats(_post(raw_client, fleet, user="dave@acme.com"))


def test_enrolled_device_identity_is_a_claim(client, raw_client):
    _override(client, scope="user", match="dave@acme.com", disabled_checks=["pii_exposure"])
    et = client.post("/api/enroll/tokens", json={"label": "fleet"}).json()["token"]
    r = raw_client.post("/api/enroll", json={"token": et, "device": "laptop-7",
                                             "user": "dave@acme.com"})
    assert r.status_code == 200, r.text
    device_key = r.json()["token"]
    # Attribution follows the declared identity; the exemption does not.
    resp = _post(raw_client, device_key)
    assert "pii_exposure" in _cats(resp)
    assert "pii_exposure" not in _cats(_post(raw_client, _key(client, "dave@acme.com")))


def test_claim_cannot_switch_enforcement_off(client, raw_client):
    assert client.patch("/api/tenant", json={"client_enforce": "on"}).status_code == 200
    _override(client, scope="user", match="pilot@acme.com", enforce="off")
    fleet = _key(client, "fleet@acme.com")
    assert _post(raw_client, fleet, user="pilot@acme.com")["enforce"] is True
    assert _post(raw_client, _key(client, "pilot@acme.com"))["enforce"] is False


def test_claim_can_switch_enforcement_on(client, raw_client):
    assert client.patch("/api/tenant", json={"client_enforce": "off"}).status_code == 200
    _override(client, scope="user", match="pilot@acme.com", enforce="on")
    fleet = _key(client, "fleet@acme.com")
    assert _post(raw_client, fleet, user="pilot@acme.com")["enforce"] is True
    assert _post(raw_client, fleet, user="other@acme.com")["enforce"] is False


# --- EMA: an identity read off a token the client hands us ----------------------------------

def _unsigned_jwt(claims: dict) -> str:
    import base64
    import json
    seg = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{seg({'alg': 'RS256', 'typ': 'JWT'})}.{seg(claims)}.c2ln"


def _mcp(raw_client, key, authorization):
    r = raw_client.post("/api/ingest/mcp", headers={"X-Palivane-Token": key},
                        json={"method": "tools/call", "server": "files.example", "tool": "read",
                              "args_text": "notes.txt", "authorization": authorization})
    assert r.status_code == 200, r.text
    return r.json()


def test_unverified_ema_identity_is_a_claim(client, raw_client):
    # Anyone can put a JWT with any email in the Authorization header the capture plane
    # forwards. Unverified, it names who to attribute to, never whose exemption applies.
    assert client.patch("/api/tenant", json={"client_enforce": "on"}).status_code == 200
    _override(client, scope="user", match="pilot@acme.com", enforce="off")
    fleet = _key(client, "fleet@acme.com")
    forged = _unsigned_jwt({"iss": "https://idp.example", "email": "pilot@acme.com"})
    assert _mcp(raw_client, fleet, forged)["enforce"] is True


def test_verified_ema_identity_gets_its_override(client, raw_client, monkeypatch):
    import app.oidc as oidc_mod
    assert client.patch("/api/tenant", json={"client_enforce": "on"}).status_code == 200
    _override(client, scope="user", match="pilot@acme.com", enforce="off")
    monkeypatch.setattr(oidc_mod, "inspect_ema_token", lambda token, **k: {
        "kind": "jwt", "verified": True, "email": "pilot@acme.com", "sub": "pilot"})
    fleet = _key(client, "fleet@acme.com")
    assert _mcp(raw_client, fleet, "opaque-but-verified")["enforce"] is False
