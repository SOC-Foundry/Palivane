"""Need-to-know / LLM oversharing detection."""

from __future__ import annotations

from app.detectors.oversharing import OversharingDetector, parse_rules
from app.detectors.base import AnalysisInput, Surface

D = OversharingDetector()


def _item(content, actor, rules):
    return AnalysisInput(content=content, sender=actor, surface=Surface.OVERSHARING,
                         metadata={"oversharing_rules": rules})


def test_parse_rules():
    r = parse_rules("confidential_data = *@acme.com\nkw:salary = *@hr.acme.com,*@exec.acme.com")
    assert r[0] == ("confidential_data", ["*@acme.com"])
    assert r[1] == ("kw:salary", ["*@hr.acme.com", "*@exec.acme.com"])


def test_category_oversharing_flags_unauthorized():
    # A confidential (labeled) response returned to an outsider -> oversharing.
    content = "CONFIDENTIAL — Project roadmap and financials for FY26."
    rules = "confidential_data = *@hr.acme.com"
    sig = D.analyze(_item(content, "sales@acme.com", rules))
    assert any(s.category.value == "data_oversharing" for s in sig)


def test_authorized_recipient_not_flagged():
    content = "CONFIDENTIAL — Project roadmap and financials for FY26."
    rules = "confidential_data = *@acme.com"
    assert not D.analyze(_item(content, "anyone@acme.com", rules))


def test_keyword_rule():
    content = "The salary bands for the engineering team are attached."
    rules = "kw:salary = *@hr.acme.com"
    assert any(s.check == "data_oversharing" for s in D.analyze(_item(content, "dev@acme.com", rules)))
    # HR recipient is fine
    assert not D.analyze(_item(content, "ann@hr.acme.com", rules))


def test_no_rules_no_signals():
    assert D.analyze(_item("CONFIDENTIAL stuff", "x@acme.com", "")) == []


def test_endpoint_records_and_respects_toggle(client, raw_client):
    client.patch("/api/tenant", json={"oversharing_rules": "kw:salary = *@hr.acme.com"})
    key = client.post("/api/apikeys", json={"label": "copilot", "actor": "c@acme.com"}).json()["token"]
    body = {"content": "Here are the salary figures you asked for.", "user": "dev@acme.com",
            "source": "m365-copilot"}
    r = raw_client.post("/api/scan/oversharing", json=body, headers={"X-Warden-Token": key})
    assert r.status_code == 200
    assert any(s["category"] == "data_oversharing" for s in r.json()["signals"])

    # Disabling the check turns it off.
    client.patch("/api/tenant", json={"disabled_checks": ["data_oversharing"]})
    r2 = raw_client.post("/api/scan/oversharing", json=body, headers={"X-Warden-Token": key})
    assert not any(s["category"] == "data_oversharing" for s in r2.json()["signals"])
    client.patch("/api/tenant", json={"disabled_checks": []})
