"""The AI Exposure Assessment payload — /api/reports/summary.

This is the deliverable the entry offer is sold on, so the two things it adds beyond
counters are tested as product, not as plumbing: the recommendations must be DERIVED from
what actually fired (a canned checklist would be worse than none, because a reader can check
it against the numbers on the same page), and the coverage gap must be counted as a subset
of the people already reported rather than as additional ones.
"""

from __future__ import annotations


def _report(client, days=30):
    r = client.get(f"/api/reports/summary?days={days}")
    assert r.status_code == 200, r.text
    return r.json()


def test_an_empty_window_recommends_nothing(client):
    """No findings, no advice. A report that always lists the same seven policies is a
    template, and the first reader who notices stops believing the rest of it."""
    d = _report(client)
    assert d["recommendations"] == []
    assert d["shadow"]["unsanctioned_tools"] == 0


def test_recommendations_follow_what_actually_fired(client):
    """Each entry names its own evidence, and only categories present in the window appear."""
    client.post("/api/analyze", json={
        "content": "here is the key AKIA4YTGH2NBQF7XZP3K please use it",
        "subject": "t", "surface": "ai_usage", "persist": True})
    d = _report(client)
    cats = {r["category"] for r in d["recommendations"]}
    assert "secret_leak" in cats, cats
    # Categories that did not fire must not be advised on.
    assert "phi_exposure" not in cats, cats
    rec = next(r for r in d["recommendations"] if r["category"] == "secret_leak")
    assert "1 finding" in rec["evidence"], rec["evidence"]
    assert rec["why"] and rec["policy"]


def test_the_coverage_gap_is_a_subset_not_an_addition(client):
    """actors_with_findings minus covered_actors is how many of THOSE people lack a sensor.

    The first draft of the report's opening line read "a further N people", which stated a
    population twice its real size — the exact kind of number a security lead repeats to
    their board before anyone checks it.
    """
    client.post("/api/analyze", json={
        "content": "AKIA4YTGH2NBQF7XZP3K", "subject": "t",
        "surface": "ai_usage", "persist": True})
    d = _report(client)
    gap = next((r for r in d["recommendations"] if r["category"] == "coverage"), None)
    if gap is not None:
        assert d["actors_with_findings"] >= d["covered_actors"]
        n = d["actors_with_findings"] - d["covered_actors"]
        assert str(n) in gap["policy"], gap["policy"]
        assert str(d["actors_with_findings"]) in gap["evidence"]


def test_coverage_advice_leads_when_present(client):
    """It is the line a reader cannot get any other way, so it sits first."""
    client.post("/api/analyze", json={
        "content": "AKIA4YTGH2NBQF7XZP3K", "subject": "t",
        "surface": "ai_usage", "persist": True})
    d = _report(client)
    if any(r["category"] == "coverage" for r in d["recommendations"]):
        assert d["recommendations"][0]["category"] == "coverage"


def test_shadow_section_is_shaped_even_when_empty(client):
    """The console hides the section when there is nothing in it, which only works if the
    keys are always present — an undefined read would blank the whole page."""
    d = _report(client)
    for k in ("unsanctioned_tools", "people_using_unsanctioned", "top"):
        assert k in d["shadow"], k
    assert isinstance(d["shadow"]["top"], list)
