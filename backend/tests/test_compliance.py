"""Compliance-framework mapping + the /api/compliance/report export."""

from __future__ import annotations

from app.policies import (CATALOG, FRAMEWORK_LABELS, FRAMEWORK_MAP, VALID_KEYS,
                          compliance_report, frameworks_for)


def test_every_check_is_mapped_and_uses_known_codes():
    # every catalog check has a mapping (the module-level assert also guards this)
    assert set(FRAMEWORK_MAP) == VALID_KEYS
    for key in VALID_KEYS:
        fw = frameworks_for(key)
        assert fw, f"{key} has no framework mapping"
        for family, codes in fw.items():
            known = FRAMEWORK_LABELS[family]          # KeyError if the family is bogus
            for code in codes:
                assert code in known, f"{key}: unknown {family} code {code}"


def test_catalog_endpoint_carries_frameworks(client):
    cat = client.get("/api/policies").json()
    pi = next(c for c in cat["checks"] if c["key"] == "prompt_injection")
    assert pi["frameworks"]["owasp_llm"] == ["LLM01"]


def _control(report, family, code):
    fw = next(f for f in report["frameworks"] if f["framework"] == family)
    return next(c for c in fw["controls"] if c["code"] == code)


def test_report_marks_enabled_control_covered_and_disabled_as_gap(client):
    # LLM07 (System Prompt Leakage) is mapped by exactly one check (data_exfiltration), so
    # disabling that check turns the control covered -> gap. A control with several mapped
    # checks (e.g. LLM01) would stay covered until they're all off — that's the point.
    llm07 = _control(client.get("/api/compliance/report").json(), "owasp_llm", "LLM07")
    assert llm07["checks"] == ["data_exfiltration"] and llm07["status"] == "covered"

    assert client.patch("/api/tenant", json={"disabled_checks": ["data_exfiltration"]}).status_code == 200
    llm07b = _control(client.get("/api/compliance/report").json(), "owasp_llm", "LLM07")
    assert llm07b["status"] == "gap" and llm07b["enabled_checks"] == []
    assert "data_exfiltration" in llm07b["checks"]          # still mapped, just off


def test_report_has_all_four_frameworks_and_counts(client):
    r = client.get("/api/compliance/report").json()
    families = {f["framework"] for f in r["frameworks"]}
    assert families == {"owasp_llm", "owasp_agentic", "nist_ai_rmf", "eu_ai_act"}
    for f in r["frameworks"]:
        assert f["covered"] <= f["mapped"] <= f["total"]
    assert r["checks_enabled"] == len(CATALOG)     # default: all on


def test_report_csv_export(client):
    r = client.get("/api/compliance/report?format=csv")
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    body = r.text
    assert "framework,control,control_name,status" in body.splitlines()[0]
    assert "LLM01" in body and "Prompt Injection" in body


def test_report_is_admin_only(client, db_factory):
    from app import users as users_cli
    db = db_factory()
    users_cli.create_user(db, "acme", "analyst@acme.com", "password123", "analyst")
    db.close()
    from fastapi.testclient import TestClient
    from app.main import app
    c = TestClient(app)
    tok = c.post("/api/auth/login", json={"email": "analyst@acme.com",
                                          "password": "password123"}).json()["access_token"]
    c.headers.update({"Authorization": f"Bearer {tok}"})
    assert c.get("/api/compliance/report").status_code == 403
