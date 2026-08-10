"""Personal-vs-corporate account distinction in shadow-AI discovery."""

from __future__ import annotations

from app import discovery
from app.models import DiscoveredUsage, TenantDomain


def _capture(db, actor, tool="ChatGPT", dest="https://chatgpt.com/"):
    discovery.record_capture(db, 1, actor, dest, tool, signals=[], risk=0)


def test_free_mail_actor_is_personal(client, db_factory):
    db = db_factory()
    _capture(db, "someone@gmail.com")
    row = db.query(DiscoveredUsage).filter(DiscoveredUsage.actor == "someone@gmail.com").one()
    assert row.account_type == "personal"
    db.close()


def test_verified_corp_domain_actor_is_corporate(client, db_factory):
    db = db_factory()
    db.add(TenantDomain(tenant_id=1, domain="acme.com", token="tok", verified=True))
    db.commit()
    _capture(db, "dana@acme.com")
    row = db.query(DiscoveredUsage).filter(DiscoveredUsage.actor == "dana@acme.com").one()
    assert row.account_type == "corporate"
    db.close()


def test_unclaimed_domain_and_non_email_are_unknown(client, db_factory):
    db = db_factory()
    _capture(db, "dana@notclaimed.io")
    _capture(db, "svc-bot")            # not an email at all
    a = db.query(DiscoveredUsage).filter(DiscoveredUsage.actor == "dana@notclaimed.io").one()
    b = db.query(DiscoveredUsage).filter(DiscoveredUsage.actor == "svc-bot").one()
    assert a.account_type == "unknown" and b.account_type == "unknown"
    db.close()


def test_inventory_counts_personal_accounts_and_personal_on_unsanctioned(client, db_factory):
    db = db_factory()
    # chatgpt.com is unsanctioned by default; a personal account using it is the headline risk
    _capture(db, "alice@gmail.com", tool="ChatGPT", dest="https://chatgpt.com/")
    _capture(db, "bob@gmail.com", tool="ChatGPT", dest="https://chatgpt.com/")
    inv = discovery.build_inventory(db, 1, sanctioned_raw="")
    assert inv["summary"]["personal_account_users"] == 2
    assert inv["summary"]["personal_on_unsanctioned_tools"] == 1
    tool = next(t for t in inv["tools"] if t["tool"] == "ChatGPT")
    assert tool["personal_user_count"] == 2 and tool["corporate_user_count"] == 0
    db.close()
