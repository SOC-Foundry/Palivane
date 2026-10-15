"""The org around the demo's findings: every page that used to be empty reads something.

Each test reads the page the way the console does, through the endpoint that feeds it, as the demo admin.
That is the point: the pages derive their numbers from tables the findings alone never filled (discovery,
the document index, the sensor ledger, agents, keys, the audit trail), and a seed that fills a table the
page does not read, or writes a state the product would not, proves nothing. So these also pin that the
pieces agree with each other (Discovery with the findings, Exposure with the documents, the audit trail
with what the seed did) and that nothing is a working credential."""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import ai_catalog, content_origin, seed, seed_history, seed_org
from app.database import Base, get_db
from app.detectors import AnalysisInput
from app.distribution import client_versions
from app.engine import engine
from app.main import app
from app.models import (Agent, AgentRole, AllowEntry, ApiKey, AuditLog, ContentFingerprint, DiscoveredUsage,
                        EnrollmentToken, Finding, JoinRequest, OAuthClient, OAuthToken, SensorHeartbeat,
                        Tenant, TenantDomain, User)
from app.security import API_KEY_PREFIX

ADMIN = seed.DEMO_ADMIN_EMAIL
TABLES = (Finding, AllowEntry, User, TenantDomain, JoinRequest, ApiKey, EnrollmentToken, OAuthToken,
          Agent, AgentRole, SensorHeartbeat, DiscoveredUsage, ContentFingerprint, AuditLog)


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _fresh_db(path):
    eng = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    return eng, sessionmaker(bind=eng)


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    """One seeded database for the read-only tests (the seed is the slow part)."""
    eng, Session = _fresh_db(tmp_path_factory.mktemp("org") / "org.db")
    db = Session()
    now = _now()
    seed.populate(db, now=now)
    tenant = db.query(Tenant).filter(Tenant.slug == seed.DEMO_SLUG).one()
    yield Session, db, tenant, now
    db.close()
    eng.dispose()


@pytest.fixture
def api(seeded):
    """The console's API over the seeded database, signed in as the demo admin. Set up and torn down per
    test (not per module): another module's fixtures replace the dependency override."""
    Session, db, tenant, now = seeded

    def _override():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _override
    client = TestClient(app)
    r = client.post("/api/auth/login", json={"email": ADMIN, "password": seed.DEMO_ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    client.headers.update({"Authorization": f"Bearer {r.json()['access_token']}"})
    yield client
    app.dependency_overrides.pop(get_db, None)


def _events():
    """Every event the seed scores, in the order its findings are written."""
    return (list(seed.SAMPLES) + [h["event"] for h in seed_history.HISTORY]
            + [x[3] for x in seed_org.LEAKS] + [x[3] for x in seed_org.A2A])


def _findings(db, tenant):
    return db.query(Finding).filter(Finding.tenant_id == tenant.id).order_by(Finding.id).all()


# --- Discovery -------------------------------------------------------------------------------------------

def test_every_destination_in_the_logs_is_one_the_catalog_knows():
    for dest in seed_org._LOG:
        assert ai_catalog.classify(dest), dest
    for who in {w for lines in seed_org._LOG.values() for w, *_ in lines}:
        assert seed_org._team(who), who             # every actor has a team, or the page files them under "Unassigned"


def test_discovery_has_an_inventory(api):
    inv = api.get("/api/discovery/inventory").json()
    s = inv["summary"]
    assert s["tools"] >= 12 and s["users"] >= 12 and s["teams"] >= 5
    assert s["unsanctioned_tools"] >= 5 and s["sensitive_events"] > 0
    assert s["personal_account_users"] == len(seed_org.PERSONAL)         # free-mail identities, caught as such
    by_tool = {t["tool"]: t for t in inv["tools"]}
    assert by_tool["Claude"]["sanctioned"] and not by_tool["ChatGPT"]["sanctioned"]
    assert by_tool["Claude"]["personal_user_count"] >= 1                 # a sanctioned tool on a personal account
    assert {"capture", "log"} <= {src for t in inv["tools"] for src in t["sources"]}


def test_discovery_agrees_with_the_findings(seeded, api):
    """Every finding a capture plane would have named a tool for is in the inventory as seen by that plane,
    so the page cannot say a tool was never used when the findings say it was."""
    Session, db, tenant, now = seeded
    seen = {(u.actor, u.tool): u for u in db.query(DiscoveredUsage).filter(DiscoveredUsage.tenant_id == tenant.id)}
    checked = 0
    for event, row in zip(_events(), _findings(db, tenant)):
        hit = seed_org._hit_for(event)
        if not hit:
            continue
        u = seen[(row.sender.lower(), hit["tool"])]
        assert u.source == "capture" and u.event_count >= 1 and (u.max_risk or 0) >= row.risk_score, (row.sender, hit)
        checked += 1
    assert checked >= 25


# --- Exposure ----------------------------------------------------------------------------------------------

def test_exposure_traces_leaks_to_the_documents_they_came_from(seeded, api):
    Session, db, tenant, now = seeded
    docs = api.get("/api/exposure").json()["documents"]
    assert {d["title"] for d in docs} == {d[2] for d in seed_org.DOCS}
    refs = {d[1] for d in seed_org.DOCS}
    leaks = _findings(db, tenant)[len(seed.SAMPLES) + len(seed_history.HISTORY):][:len(seed_org.LEAKS)]
    for f in leaks:
        assert f.origin and f.origin["ref"] in refs and f.origin["containment"] >= 0.5, f.subject
        assert f.signals[0]["detector"] == "content_origin"              # the boost names its source, as live
        assert f.severity in ("high", "critical") and f.status == "open"
    for d in docs:
        mine = [f for f in leaks if f.origin["ref"] == d["ref"]]
        assert d["leaks"] == sum(f.seen_count for f in mine) and d["user_count"] == len({f.sender for f in mine})
        assert d["max_severity"] in ("high", "critical") and d["max_containment"] >= 0.5
    assert sum(len(d["tools"]) > 1 for d in docs) >= 2                    # a blast radius, not one tool


def test_nothing_else_is_traced_to_a_document(seeded):
    """The open queue, the history and the agent messages were written before and beside the documents and
    must not have been pulled into them: their verdicts are the ones they had."""
    Session, db, tenant, now = seeded
    rows = _findings(db, tenant)
    others = rows[:len(seed.SAMPLES) + len(seed_history.HISTORY)] + rows[-len(seed_org.A2A):]
    assert all(f.origin is None for f in others)


def test_the_documents_are_sensitive_and_recently_scanned(seeded):
    Session, db, tenant, now = seeded
    docs = db.query(ContentFingerprint).filter(ContentFingerprint.tenant_id == tenant.id).all()
    assert len(docs) == len(seed_org.DOCS) and all(d.sensitive and d.shingles for d in docs)
    assert all(timedelta(0) <= now - d.updated_at <= timedelta(days=7) for d in docs)
    for source, ref, title, owner, sentences, days in seed_org.DOCS:
        assert content_origin.fingerprint(" ".join(sentences)), title


# --- Agents ------------------------------------------------------------------------------------------------

def test_agents_have_roles_and_one_is_disabled(api):
    agents = api.get("/api/agents").json()["agents"]
    assert {a["name"] for a in agents} == {a[0] for a in seed_org.AGENTS}
    roles = {r["name"]: r for r in api.get("/api/agent-roles").json()["roles"]}
    assert set(roles) == {r[0] for r in seed_org.ROLES}
    assert {a["role"] for a in agents if a["role"]} <= set(roles)           # no agent points at a role that is not there
    assert [a["name"] for a in agents if not a["active"]] == ["legacy-summarizer"]
    assert any(r["enforce"] for r in roles.values()) and any(not r["enforce"] for r in roles.values())
    assert next(a for a in agents if a["name"] == "release-bot")["oidc_subject"].startswith("system:serviceaccount:")


def test_the_agent_graph_shows_where_risk_crossed_a_hop(seeded, api):
    Session, db, tenant, now = seeded
    g = api.get("/api/agents/a2a-graph").json()
    names = {a[0] for a in seed_org.AGENTS}
    assert g["total_flows"] == len({(x[3]["metadata"]["from_agent"], x[3]["metadata"]["to_agent"]) for x in seed_org.A2A})
    assert {n["agent"] for n in g["nodes"]} <= names                        # every hop is a registered agent
    assert {e["worst_severity"] for e in g["edges"]} <= {"high", "critical"} and "critical" in {e["worst_severity"] for e in g["edges"]}
    assert g["total_messages"] == sum(x[1] for x in seed_org.A2A)


# --- Fleet -------------------------------------------------------------------------------------------------

def test_the_fleet_has_every_kind_of_sensor(api):
    f = api.get("/api/fleet").json()
    s = f["summary"]
    assert s["fresh"] >= 5 and s["stale"] >= 2 and s["dark"] >= 2
    assert s["retired_clients"] == 1 and s["dead_keys"] == 1
    old_builds = [x for x in f["sensors"] if not x["client_current"] and not x["client_retired"]]
    assert len(old_builds) >= 2 and s["stale_clients"] == len(old_builds) + s["retired_clients"]   # behind, not just gone
    assert any(x["parse_miss_count"] > 0 for x in f["sensors"])             # shape drift, the failure that looks healthy
    assert {x["plane"] for x in f["sensors"]} >= {"ai-usage", "mcp", "posture", "ci", "a2a"}
    for x in f["sensors"]:
        if x["client"] in client_versions():
            assert x["client_current"] == (x["client_version"] == client_versions()[x["client"]]), x
    assert [k["label"] for k in f["dead_keys"]] == ["Old laptop (bob-mbp)"]


# --- Connections -------------------------------------------------------------------------------------------

def test_connections_list_keys_tokens_and_apps(seeded, api):
    Session, db, tenant, now = seeded
    keys = {k["label"]: k for k in api.get("/api/apikeys").json()["api_keys"]}
    assert set(keys) == {k[0] for k in seed_org.KEYS}
    assert all("token" not in k for k in keys.values())                      # the plaintext is never kept
    assert [k["label"] for k in keys.values() if not k["active"]] == ["Old laptop (bob-mbp)"]
    assert keys["Old laptop (bob-mbp)"]["last_failed_at"] and keys["CI scanner"]["expires_at"]
    morgan = db.query(User).filter(User.email == seed_org.ADMIN2).one()
    assert keys["SIEM pull (Splunk)"]["scope"] == "console_read" and keys["SIEM pull (Splunk)"]["user_id"] == morgan.id
    tokens = {t["label"]: t for t in api.get("/api/enroll/tokens").json()["enrollment_tokens"]}
    assert tokens["Contractor onboarding"]["uses"] == tokens["Contractor onboarding"]["max_uses"]   # used up
    assert datetime.fromisoformat(tokens["Contractor onboarding"]["expires_at"]) < now                # and expired
    assert not tokens["Pilot team (revoked)"]["active"] and tokens["Q4 laptop rollout"]["uses"] < tokens["Q4 laptop rollout"]["max_uses"]
    grants = api.get("/api/oauth/grants").json()["grants"]
    assert {g["client_name"] for g in grants} == {a[1] for a in seed_org.APPS}
    assert {g["granted_by"] for g in grants} <= {u.email for u in db.query(User).filter(User.tenant_id == tenant.id)}
    assert {g["scopes"] for g in grants} == {"palivane:read"}


def test_no_credential_in_the_demo_can_authenticate_anyone(seeded):
    """Keys, tokens and agents hold a hash of a secret that was generated and dropped. The only way into the
    demo org is the seed admin's password and the public demo's own session."""
    Session, db, tenant, now = seeded
    hashes = []
    for model, prefix in ((ApiKey, API_KEY_PREFIX), (Agent, "ag_"), (EnrollmentToken, "et_")):
        for row in db.query(model).filter(model.tenant_id == tenant.id):
            assert re.fullmatch(r"[0-9a-f]{64}", row.token_hash) and row.prefix.startswith(prefix), (model, row.id)
            hashes.append(row.token_hash)
    assert len(hashes) == len(set(hashes)) == len(seed_org.KEYS) + len(seed_org.ENROLL) + len(seed_org.AGENTS)
    for u in db.query(User).filter(User.tenant_id == tenant.id, User.email.in_([x[0] for x in seed_org.USERS])):
        assert u.password_hash and not u.mfa_enabled


# --- Audit -------------------------------------------------------------------------------------------------

def test_the_audit_trail_records_what_the_seed_did(seeded, api):
    Session, db, tenant, now = seeded
    entries = api.get("/api/audit?limit=500").json()["entries"]
    by = Counter(e["action"] for e in entries)
    assert len(entries) < 500, "the page reads the newest 500: the seed must stay well inside it"
    rows = _findings(db, tenant)
    manual = [f for f in rows if f.reviewed_at and f.review_via != "bulk"]
    bulk = Counter(f.reviewed_at for f in rows if f.review_via == "bulk")
    assert by["finding.status"] == len(manual) and by["finding.bulk_status"] == len(bulk)
    assert by["allowlist.create"] == len(seed_history.ALLOW)
    assert by["allowlist.revoke"] == sum(1 for a in seed_history.ALLOW if a.get("revoked"))
    assert by["user.create"] == len(seed_org.USERS) and by["apikey.create"] == len(seed_org.KEYS)
    assert by["agent.create"] == len(seed_org.AGENTS) and by["agentrole.upsert"] == len(seed_org.ROLES)
    assert by["device.enroll"] == len(seed_org.DEVICES) and by["domain.claim"] == by["domain.verify"] == 1
    status = {e["target"]: e for e in entries if e["action"] == "finding.status"}
    for f in manual:
        e = status[str(f.id)]
        assert datetime.fromisoformat(e["created_at"]) == f.reviewed_at and e["actor"] == f.reviewed_by
        assert e["detail"]["status"] == f.status and e["detail"].get("reason", "") == f.review_reason
    assert sorted(e["detail"]["count"] for e in entries if e["action"] == "finding.bulk_status") == sorted(bulk.values())
    for a in db.query(AllowEntry).filter(AllowEntry.tenant_id == tenant.id):      # an entry, when it was made and by whom
        e = next(x for x in entries if x["action"] == "allowlist.create" and x["target"] == str(a.id))
        assert datetime.fromisoformat(e["created_at"]) == a.created_at and e["actor"] == a.created_by
        assert e["detail"]["pattern"] == a.pattern and e["detail"]["finding_id"] == a.finding_id
    assert all(datetime.fromisoformat(e["created_at"]) <= now for e in entries)


def test_audit_rows_name_people_and_devices_that_exist(seeded, api):
    Session, db, tenant, now = seeded
    people = {u.email for u in db.query(User).filter(User.tenant_id == tenant.id)}
    devices = {d[1] for d in seed_org.DEVICES}
    for e in api.get("/api/audit?limit=500").json()["entries"]:
        assert e["actor"] in people | devices, e
    keys = {k.label: k for k in db.query(ApiKey).filter(ApiKey.tenant_id == tenant.id)}
    for e in api.get("/api/audit?limit=500&action=apikey.create").json()["entries"]:
        assert datetime.fromisoformat(e["created_at"]) == keys[e["target"]].created_at


# --- People ------------------------------------------------------------------------------------------------

def test_users_domain_and_a_waiting_signup(seeded, api):
    Session, db, tenant, now = seeded
    users = {u["email"]: u for u in api.get("/api/users").json()["users"]}
    assert {u[0] for u in seed_org.USERS} <= set(users) and ADMIN in users
    assert [e for e, u in users.items() if not u["active"]] == ["temp.analyst@demo.local"]
    assert sum(u["role"] == "admin" for u in users.values()) >= 2
    doms = api.get("/api/domains").json()["domains"]
    assert [(d["domain"], d["verified"]) for d in doms] == [(seed_org.DOMAIN, True)]
    assert db.query(JoinRequest).filter(JoinRequest.tenant_id == tenant.id, JoinRequest.status == "pending").count() == 1


# --- running it again, and around other people's things ---------------------------------------------------------

def _counts(db, tenant):
    out = {}
    for m in TABLES:
        q = db.query(m)
        if hasattr(m, "tenant_id"):
            q = q.filter(m.tenant_id == tenant.id)
        out[m.__name__] = q.count()
    return out


def test_running_the_seed_again_starts_from_the_same_place(tmp_path):
    eng, Session = _fresh_db(tmp_path / "again.db")
    db = Session()
    seed.populate(db)
    tenant = db.query(Tenant).filter(Tenant.slug == seed.DEMO_SLUG).one()
    before, clients = _counts(db, tenant), db.query(OAuthClient).count()
    seed.populate(db)
    assert _counts(db, tenant) == before and db.query(OAuthClient).count() == clients == len(seed_org.APPS)
    assert all(n > 0 for k, n in before.items() if k != "JoinRequest") and before["JoinRequest"] == 1
    db.close()
    eng.dispose()


def test_a_rerun_replaces_what_it_derived_and_leaves_what_somebody_made_alone(tmp_path):
    eng, Session = _fresh_db(tmp_path / "hand.db")
    db = Session()
    seed.populate(db)
    t = db.query(Tenant).filter(Tenant.slug == seed.DEMO_SLUG).one()
    db.add_all([ApiKey(tenant_id=t.id, label="my own console key", prefix="ak_mine", token_hash="0" * 64),
                Agent(tenant_id=t.id, name="my-own-agent", prefix="ag_mine", token_hash="1" * 64),
                AgentRole(tenant_id=t.id, name="my-own-role"),
                EnrollmentToken(tenant_id=t.id, label="my own token", prefix="et_mine", token_hash="2" * 64),
                User(tenant_id=t.id, email="hand@demo.local", password_hash="x", role="analyst"),
                SensorHeartbeat(tenant_id=t.id, actor="stray", plane="ai-usage", tool="x"),
                AuditLog(tenant_id=t.id, actor="stray", action="x.y")])
    db.commit()
    seed.populate(db)
    assert db.query(ApiKey).filter(ApiKey.label == "my own console key").count() == 1
    assert db.query(Agent).filter(Agent.name == "my-own-agent").count() == 1
    assert db.query(AgentRole).filter(AgentRole.name == "my-own-role").count() == 1
    assert db.query(EnrollmentToken).filter(EnrollmentToken.label == "my own token").count() == 1
    assert db.query(User).filter(User.email == "hand@demo.local").count() == 1
    assert db.query(SensorHeartbeat).filter(SensorHeartbeat.actor == "stray").count() == 0     # derived: replaced
    assert db.query(AuditLog).filter(AuditLog.actor == "stray").count() == 0
    assert db.query(ApiKey).filter(ApiKey.tenant_id == t.id).count() == len(seed_org.KEYS) + 1
    db.close()
    eng.dispose()


def test_another_orgs_claim_on_the_domain_does_not_fail_the_seed(tmp_path):
    eng, Session = _fresh_db(tmp_path / "claim.db")
    db = Session()
    other = Tenant(slug="other", name="Other")
    db.add(other)
    db.commit()
    db.add(TenantDomain(tenant_id=other.id, domain=seed_org.DOMAIN, token="t" * 8, verified=False))
    db.commit()
    seed.populate(db)
    t = db.query(Tenant).filter(Tenant.slug == seed.DEMO_SLUG).one()
    assert db.query(TenantDomain).filter(TenantDomain.tenant_id == t.id).count() == 0
    assert db.query(JoinRequest).filter(JoinRequest.tenant_id == t.id).count() == 0
    assert db.query(AuditLog).filter(AuditLog.tenant_id == t.id, AuditLog.action.like("domain.%")).count() == 0
    assert db.query(User).filter(User.tenant_id == t.id).count() >= len(seed_org.USERS)
    db.close()
    eng.dispose()


def test_a_real_orgs_findings_and_agents_are_untouched(tmp_path):
    eng, Session = _fresh_db(tmp_path / "other.db")
    db = Session()
    other = Tenant(slug="acme", name="Acme")
    db.add(other)
    db.commit()
    db.add_all([Agent(tenant_id=other.id, name="support-bot", prefix="ag_x", token_hash="3" * 64),
                ApiKey(tenant_id=other.id, label="Corporate proxy (SWG)", prefix="ak_x", token_hash="4" * 64),
                SensorHeartbeat(tenant_id=other.id, actor="a@acme.com", plane="mcp", tool="Bash"),
                AuditLog(tenant_id=other.id, actor="a@acme.com", action="x.y")])
    db.commit()
    before = _counts(db, other)
    seed.populate(db)
    assert _counts(db, other) == before            # same names as the demo's, and still theirs
    db.close()
    eng.dispose()


def test_the_agent_messages_are_flagged_by_the_engine():
    """The graph is built from flagged messages only, so a message the engine stops flagging would quietly
    drop an edge. This says which."""
    for age, events, last, event in seed_org.A2A:
        item = AnalysisInput(content=event["content"], subject=event["subject"], sender=event["sender"],
                             channel=event["channel"], surface=event["surface"], metadata=event["metadata"])
        assert engine.analyze(item).severity in ("high", "critical"), event["subject"]
