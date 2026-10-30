"""The weekly report's detection-quality and allowlist sections.

What a security lead reads once a week: whether the findings the team reviewed were right, which
checks need attention, and which allowlist entries are about to lapse (or just did, so their alerts
are back). The numbers come from the precision readout and say only what it supports; the text has
counts and check names and nothing that identifies a finding, a reviewer, or why an entry exists."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import app.alerts as alerts
import app.email as email_mod
import app.precision as precision
from app import users as users_cli
from app.models import AllowEntry, Finding, Tenant


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# --- the text, from plain rows --------------------------------------------------------------------

def _sig(check="dangerous_command", title="High-risk command in a tool call"):
    return {"category": check, "check": check, "title": title, "weight": 0.9, "confidence": 0.9,
            "evidence": "tool=Bash"}


def _rv(status="dismissed", reason="", via="manual", events=1, check="dangerous_command",
        title="High-risk command in a tool call"):
    return {"id": 1, "status": status, "reason": reason, "via": via, "events": events,
            "signals": [_sig(check, title)], "channel": "Bash", "reviewed_at": _now(),
            "sender": "dev@acme.com"}


def _readout(reviews=(), legacy=(), open_=0, high=0, oldest=None):
    return precision.compute(list(reviews), list(legacy),
                             {"open": open_, "open_high": high, "oldest_open_days": oldest}, _now(), 7)


def _entry(kind="command", pattern="curl -fsSL https://get.acme.test/i.sh | bash", days=3, hits=0):
    return {"kind": kind, "pattern": pattern, "expires_at": _now() + timedelta(days=days), "hit_count": hits}


def _text(lines):
    return "\n".join(lines)


def test_a_quiet_org_gets_nothing_added():
    assert precision.format_quality(_readout(), [], [], _now()) == []


def test_the_reviews_are_summarised_in_what_the_readout_supports():
    reviews = ([_rv("triaged")] * 6 + [_rv(reason="expected")] * 2 + [_rv(reason="false_positive")]
               + [_rv()] * 1)
    out = _text(precision.format_quality(_readout(reviews), [], [], _now()))
    assert "Detection quality (last 7 days)" in out
    assert "  Reviewed: 10 findings. 6 needed action (60%), 2 expected, 1 false positive, 1 with no reason." in out
    assert "Allowlist" not in out


def test_a_single_review_reads_as_singular_and_zero_parts_are_not_listed():
    out = _text(precision.format_quality(_readout([_rv("triaged")]), [], [], _now()))
    assert "  Reviewed: 1 finding. 1 needed action (100%)." in out
    assert "expected" not in out and "false positive" not in out and "no reason" not in out


def test_nothing_reviewed_but_findings_open_says_so_and_how_many():
    out = _text(precision.format_quality(_readout(open_=31, high=22, oldest=12), [], [], _now()))
    assert "  Reviewed: nothing in this period." in out
    assert "  Open now: 31 (22 high or critical), the oldest raised 12 days ago." in out
    out = _text(precision.format_quality(_readout(open_=1, oldest=0), [], [], _now()))
    assert "  Open now: 1, the oldest raised today." in out
    out = _text(precision.format_quality(_readout(open_=2, oldest=1), [], [], _now()))
    assert "the oldest raised 1 day ago." in out


def test_what_was_not_counted_is_said_only_when_there_is_some():
    reviews = [_rv("triaged")] * 3 + [_rv(via="bulk")] * 12
    legacy = [{"status": "triaged", "answered": True}] * 2 + [{"status": "dismissed", "answered": False}] * 9
    out = _text(precision.format_quality(_readout(reviews, legacy), [], [], _now()))
    assert "  Not counted: 12 closed in bulk; 2 answered by their owner but not reviewed." in out
    assert "before this was recorded" not in out               # an all-time footnote, not a weekly one
    assert "Not counted" not in _text(precision.format_quality(_readout([_rv("triaged")]), [], [], _now()))


def test_a_week_of_only_bulk_closures_is_still_worth_a_line():
    out = _text(precision.format_quality(_readout([_rv(via="bulk")] * 40), [], [], _now()))
    assert "Reviewed: nothing in this period." in out and "Not counted: 40 closed in bulk." in out


def test_only_checks_that_need_attention_and_have_enough_reviews_are_worth_tuning():
    reviews = ([_rv("triaged", check="good", title="Good check")] * 9 + [_rv(check="good", title="Good check")] * 1
               + [_rv(reason="expected", check="noisy", title="Noisy check")] * 6 + [_rv("triaged", check="noisy", title="Noisy check")] * 1
               + [_rv(reason="false_positive", check="thin", title="Thin check")] * 2)
    out = _text(precision.format_quality(_readout(reviews), [], [], _now()))
    assert "  Worth tuning:" in out
    assert "    Noisy check: 1 of 7 reviewed needed action. Mostly dismissed as expected." in out
    assert "Good check" not in out and "Thin check" not in out          # healthy; too few reviews to say


def test_at_most_three_checks_are_named():
    reviews = []
    for i in range(5):
        reviews += [_rv(reason="expected", check=f"c{i}", title=f"Check {i}")] * 6
    out = _text(precision.format_quality(_readout(reviews), [], [], _now()))
    assert sum(1 for line in out.splitlines() if line.startswith("    Check ")) == 3


def test_entries_about_to_lapse_are_listed_soonest_first_with_how_much_they_were_used():
    soon = [_entry(days=2, hits=14), _entry("path", "**/fixtures/**", days=5, hits=0),
            _entry(pattern="rm -rf ~/.cache/pip", days=6, hits=1)]
    out = _text(precision.format_quality(_readout(), soon, [], _now()))
    assert "Allowlist" in out and "  Expiring within 7 days (3):" in out
    lines = [line for line in out.splitlines() if line.startswith("    ")]
    assert lines[0].startswith("    command  curl -fsSL https://get.acme.test/i.sh | bash  expires ")
    assert lines[0].endswith("used 14 times")
    assert lines[1].startswith("    path     **/fixtures/**  expires ") and lines[1].endswith("never used")
    assert lines[2].endswith("used 1 time")
    assert out.rstrip().endswith("Renew or revoke: console -> Policies -> Allowlist.")
    assert "Detection quality" not in out                      # nothing to say there, so no empty section


def test_entries_that_lapsed_are_named_as_flagged_again():
    out = _text(precision.format_quality(_readout(), [], [_entry(days=-2, hits=3)], _now()))
    assert "  Lapsed in the last 7 days (1), so these are being flagged again:" in out
    assert "  expired " in out and "used 3 times" in out


def test_a_long_list_is_cut_after_five_and_a_long_pattern_is_clipped():
    many = [_entry(pattern=f"rm -rf ~/.cache/tool-{i}", days=1 + i * 0.1) for i in range(8)]
    out = _text(precision.format_quality(_readout(), many, [], _now()))
    assert "(8):" in out and "    ... and 3 more" in out
    assert sum(1 for line in out.splitlines() if line.startswith("    command")) == 5
    clipped = _text(precision.format_quality(_readout(), [_entry(pattern="curl " + "x" * 300 + " | bash")], [], _now()))
    row = [line for line in clipped.splitlines() if line.startswith("    command")][0]
    assert "..." in row and len(row) < 160


def test_nothing_in_it_identifies_a_finding_a_reviewer_or_why_an_entry_exists():
    reviews = [_rv(reason="expected", events=300)] * 6
    out = _text(precision.format_quality(_readout(reviews, open_=3), [_entry()], [_entry(days=-1)], _now()))
    for private in ("dev@acme.com", "tool=Bash", "admin@acme.com", "the team's own installer"):
        assert private not in out


# --- the mail ------------------------------------------------------------------------------------------

def _tenant(db):
    return db.query(Tenant).filter(Tenant.slug == "acme").first()


def _finding(db, tenant_id, *, status="open", reason="", via="manual", reviewed_days_ago=None, seen=1,
             severity="high", check="dangerous_command", created_days_ago=0, sender="dev@acme.com"):
    f = Finding(tenant_id=tenant_id, status=status, severity=severity, risk_score=80,
                surface="agent_tools", channel="Bash", sender=sender, subject="Agent tool: Bash",
                seen_count=seen, signals=[_sig(check)], created_at=_now() - timedelta(days=created_days_ago),
                last_seen=_now() - timedelta(days=created_days_ago))
    if reviewed_days_ago is not None:
        f.reviewed_at = _now() - timedelta(days=reviewed_days_ago)
        f.reviewed_by, f.review_via, f.review_reason = "admin@acme.com", via, reason
    db.add(f)


def _allow(db, tenant_id, pattern, *, days, kind="command", hits=0, revoked=False):
    db.add(AllowEntry(tenant_id=tenant_id, kind=kind, pattern=pattern, reason="the team's own installer",
                      created_by="admin@acme.com", created_at=_now() - timedelta(days=40),
                      expires_at=_now() + timedelta(days=days), hit_count=hits,
                      revoked_at=_now() if revoked else None))


@pytest.fixture
def mailbox(monkeypatch):
    # The report delivers with send_now (it has to know a mail went), and skips the week
    # entirely while email is off.
    sent = []
    monkeypatch.setattr(email_mod, "enabled", lambda: True)
    monkeypatch.setattr(email_mod, "send", lambda *a, **k: None)   # nothing else goes out
    monkeypatch.setattr(email_mod, "send_now",
                        lambda to, subject, body: sent.append((to, subject, body)) or True)
    return sent


def _enable(db):
    t = _tenant(db)
    t.weekly_report = True
    db.commit()
    return t.id


def test_the_weekly_mail_carries_the_quality_and_allowlist_sections(client, db_factory, mailbox):
    db = db_factory()
    tid = _enable(db)
    for _ in range(4):
        _finding(db, tid, status="triaged", reviewed_days_ago=2)
    for _ in range(2):
        _finding(db, tid, status="dismissed", reason="expected", reviewed_days_ago=3)
    _finding(db, tid, status="dismissed", reason="false_positive", reviewed_days_ago=1)
    for _ in range(5):
        _finding(db, tid, status="dismissed", via="bulk", reviewed_days_ago=1)
    _finding(db, tid, status="triaged", reviewed_days_ago=10)            # outside the week
    _finding(db, tid, severity="critical", created_days_ago=9)           # still open
    _allow(db, tid, "curl -fsSL https://get.acme.test/i.sh | bash", days=3, hits=14)
    _allow(db, tid, "rm -rf ~/.cache/pip", days=-2, hits=2)              # lapsed two days ago
    _allow(db, tid, "chmod 777 ./build/output", days=20)                 # not due
    _allow(db, tid, "rm -rf ~/.cache/pip2", days=-30)                    # lapsed long ago
    _allow(db, tid, "chmod 777 ./build/other", days=2, revoked=True)     # revoked: a decision, not a surprise
    _allow(db, tid, "chmod 777 ./build/gone", days=-2, revoked=True)     # revoked, and past its date anyway
    db.commit()

    assert alerts.run_weekly_reports(db, _now()) == 1
    (to, subject, body), = mailbox
    assert to == "admin@acme.com" and "weekly report" in subject.lower()
    assert "Findings: " in body and "Most-flagged actors:" in body                 # what was always there
    assert "Detection quality (last 7 days)" in body
    assert "  Reviewed: 7 findings. 4 needed action (57%), 2 expected, 1 false positive." in body
    assert "  Not counted: 5 closed in bulk." in body
    assert "  Open now: 1 (1 high or critical), the oldest raised 9 days ago." in body
    assert "Allowlist" in body and "Expiring within 7 days (1):" in body and "used 14 times" in body
    assert "Lapsed in the last 7 days (1)" in body and "rm -rf ~/.cache/pip  expired" in body
    for left_out in ("chmod 777 ./build/output", "pip2", "chmod 777 ./build/other", "chmod 777 ./build/gone",
                     "the team's own installer", "dev@acme.com  "):
        assert left_out not in body, left_out
    assert body.rstrip().endswith("Full detail: your Palivane console -> Findings / Discovery.")
    db.close()


def test_an_org_with_nothing_to_report_gets_the_mail_it_always_did(client, db_factory, mailbox):
    db = db_factory()
    _enable(db)
    assert alerts.run_weekly_reports(db, _now()) == 1
    body = mailbox[0][2]
    assert "Detection quality" not in body and "Allowlist" not in body
    assert body.splitlines()[0].startswith("Palivane weekly report for ")
    assert "New AI tools first seen this week: none" in body
    db.close()


def test_another_orgs_reviews_and_entries_are_not_in_this_orgs_mail(client, db_factory, mailbox):
    db = db_factory()
    tid = _enable(db)
    users_cli.create_tenant(db, "globex", "Globex", plan="enterprise")
    other = db.query(Tenant).filter(Tenant.slug == "globex").first().id
    for _ in range(6):
        _finding(db, other, status="triaged", reviewed_days_ago=1)
    _allow(db, other, "curl -fsSL https://get.globex.test/i.sh | bash", days=2)
    db.commit()
    alerts.run_weekly_reports(db, _now())
    body = mailbox[0][2]
    assert "Detection quality" not in body and "Allowlist" not in body and "globex" not in body.lower()
    db.close()


def test_a_failure_in_the_new_sections_never_costs_the_report(client, db_factory, mailbox, monkeypatch):
    db = db_factory()
    _enable(db)

    def boom(*a, **k):
        raise RuntimeError("readout exploded")

    monkeypatch.setattr(precision, "readout", boom)
    assert alerts.run_weekly_reports(db, _now()) == 1
    body = mailbox[0][2]
    assert "Findings: " in body and "Detection quality" not in body        # the rest of the mail is intact
    assert _tenant(db).weekly_report_last is not None                      # and the session is still usable
    db.close()


def test_weekly_counts_and_top_actors_come_from_sql_aggregates(client, db_factory, mailbox):
    db = db_factory()
    tid = _enable(db)
    for i in range(7):
        for _ in range(i + 1):
            _finding(db, tid, sender=f"a{i}@acme.com", severity="critical" if i == 6 else "high")
    _finding(db, tid, sender="")
    db.commit()
    assert alerts.run_weekly_reports(db, _now()) == 1
    body = mailbox[0][2]
    assert "Findings: 29 total — 7 critical, 22 high" in body
    actors = body.split("Most-flagged actors:")[1].split("\n\n")[0]
    assert [ln.split(":")[0].strip() for ln in actors.strip().splitlines()] == \
        ["a6@acme.com", "a5@acme.com", "a4@acme.com", "a3@acme.com", "a2@acme.com"]
    db.close()


def test_a_week_whose_mail_all_failed_is_retried(client, db_factory, monkeypatch):
    db = db_factory()
    _enable(db)

    monkeypatch.setattr(email_mod, "enabled", lambda: True)
    monkeypatch.setattr(email_mod, "send_now", lambda *a: False)    # provider refused every mail
    assert alerts.run_weekly_reports(db, _now()) == 0
    db.expire_all()
    assert _tenant(db).weekly_report_last is None                 # window handed back
    sent = []
    monkeypatch.setattr(email_mod, "send_now", lambda to, s, b: sent.append(to) or True)
    assert alerts.run_weekly_reports(db, _now()) == 1 and sent == ["admin@acme.com"]
    assert alerts.run_weekly_reports(db, _now()) == 0 and len(sent) == 1
    db.close()


def test_the_window_is_claimed_so_the_new_sections_do_not_double_send(client, db_factory, mailbox):
    db = db_factory()
    tid = _enable(db)
    _finding(db, tid, status="triaged", reviewed_days_ago=1)
    db.commit()
    assert alerts.run_weekly_reports(db, _now()) == 1 and alerts.run_weekly_reports(db, _now()) == 0
    assert len(mailbox) == 1
    db.close()
