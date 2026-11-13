"""The other direction: a model's reply that overlaps a document scanned at rest is the org's
own data coming back out, whether or not it carries a secret or PII. Every product inspects
what goes to the model; this watches what comes back."""
from __future__ import annotations

import app.content_origin as co
from app.detectors.base import AnalysisInput, Surface
from app.models import Finding, Tenant
from app.service import run_analysis

DOC = (
    "Confidential Q3 forecast. Customer accounts and revenue by segment follow. "
    "Enterprise segment closed twelve deals this quarter with total contract value "
    "of four point two million dollars. Key accounts include northwind, globex, and "
    "initech. The production database credentials for the billing service are stored "
    "in the infrastructure vault and rotated every ninety days without exception. "
    "Projected churn for the mid-market segment is running near eleven percent."
)
EXCERPT = ("Enterprise segment closed twelve deals this quarter with total contract value "
           "of four point two million dollars. Key accounts include northwind, globex, and "
           "initech. Projected churn for the mid-market segment is running near eleven percent.")


def _tid(db_factory):
    db = db_factory()
    try:
        return db.query(Tenant).filter(Tenant.slug == "acme").one().id
    finally:
        db.close()


def _doc(db_factory, tid, sensitive=False):
    db = db_factory()
    co.store_fingerprint(db, tid, "gdrive", "file-1", "Q3-forecast.docx", "finance@acme.com", DOC,
                         sensitive=sensitive)
    db.commit()
    db.close()


def _response(db, tid, text, actor="dev@acme.com"):
    """What the gateway records for a model's output (gateway._capture_response_dlp)."""
    return run_analysis(AnalysisInput(content=text, subject="LLM response (claude)", sender=actor,
                                      channel="claude-code", surface=Surface.AI_USAGE,
                                      metadata={"direction": "response"}),
                        persist=True, db=db, tenant_id=tid)


def test_a_reply_that_quotes_an_org_document_is_a_finding_without_any_pii(client, db_factory):
    tid = _tid(db_factory)
    _doc(db_factory, tid)
    db = db_factory()
    r = _response(db, tid, EXCERPT)
    assert r["finding_id"], r
    sig = r["signals"][0]
    assert sig["title"] == "Model returned org data" and sig["check"] == "model_regurgitation"
    assert sig["evidence"] == "Q3-forecast.docx" and "Nobody typed it" in sig["detail"]
    assert r["severity"] == "high" and r["origin"]["title"] == "Q3-forecast.docx"
    f = db.get(Finding, r["finding_id"])
    assert f.origin["ref"] == "file-1" and f.subject == "LLM response (claude)"
    db.close()


def test_a_known_sensitive_document_coming_back_is_critical(client, db_factory):
    tid = _tid(db_factory)
    _doc(db_factory, tid, sensitive=True)
    db = db_factory()
    r = _response(db, tid, EXCERPT)
    assert r["signals"][0]["title"] == "Model returned a known sensitive document"
    assert r["severity"] == "critical" and r["recommended_action"] == "block"
    db.close()


def test_the_same_text_in_a_prompt_is_not_a_finding_on_its_own(client, db_factory):
    # Outbound keeps its gate: with no data-loss signal there is nothing to boost, and a
    # person quoting a company document to an approved assistant is not a leak by itself.
    tid = _tid(db_factory)
    _doc(db_factory, tid)
    db = db_factory()
    r = run_analysis(AnalysisInput(content=EXCERPT, sender="dev@acme.com", channel="claude-code",
                                   surface=Surface.AI_USAGE, subject="prompt"),
                     persist=True, db=db, tenant_id=tid)
    assert not r.get("origin") and not any(s.get("check") == "model_regurgitation" for s in r["signals"])
    db.close()


def test_an_ordinary_reply_matches_nothing(client, db_factory):
    tid = _tid(db_factory)
    _doc(db_factory, tid)
    db = db_factory()
    r = _response(db, tid, "Here is a Python function that reverses a list in place, with a short "
                           "explanation of why slicing creates a copy and the two-pointer swap does not.")
    assert not r.get("origin") and r["severity"] == "benign"
    db.close()


def test_another_orgs_document_is_not_matched(client, db_factory):
    from app import users as users_cli
    tid = _tid(db_factory)
    db = db_factory()
    users_cli.create_tenant(db, "beta", "Beta")
    other = db.query(Tenant).filter(Tenant.slug == "beta").one().id
    co.store_fingerprint(db, other, "gdrive", "file-9", "Beta-plan.docx", "x@beta.com", DOC)
    db.commit()
    r = _response(db, tid, EXCERPT)
    assert not r.get("origin")
    db.close()
