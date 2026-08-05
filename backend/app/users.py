"""Admin CLI for bootstrapping tenants and users (no API auth needed).

    python -m app.users create-tenant --slug acme --name "Acme Corp"
    python -m app.users create-user --tenant acme --email soc@acme.com --role admin --password ...
    python -m app.users list-tenants
    python -m app.users list-users --tenant acme
    python -m app.users set-quota --tenant acme --users 100 --api-keys 500 --ingest-per-day 200000
    python -m app.users set-plan --tenant acme --plan enterprise   # licensing tier
    python -m app.users suspend --tenant acme            # blocks logins/ingest/gateway
    python -m app.users resume --tenant acme
    python -m app.users purge-empty --older-than-days 30 # delete abandoned signups (--yes to apply)

If --password is omitted on create-user, it is read interactively (not echoed).
"""

from __future__ import annotations

import argparse
import getpass
import secrets
import sys

from .database import Base, SessionLocal, engine as db_engine
from .models import Tenant, User
from .security import hash_password


def _get_tenant(db, ref: str) -> Tenant | None:
    t = db.query(Tenant).filter(Tenant.slug == ref).first()
    if t is None and ref.isdigit():
        t = db.get(Tenant, int(ref))
    return t


def create_tenant(db, slug: str, name: str, plan: str = "free") -> Tenant:
    if _get_tenant(db, slug):
        raise SystemExit(f"tenant '{slug}' already exists")
    t = Tenant(slug=slug.lower().strip(), name=name or slug, plan=plan)
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


def create_user(db, tenant_ref: str, email: str, password: str, role: str) -> User:
    tenant = _get_tenant(db, tenant_ref)
    if tenant is None:
        raise SystemExit(f"tenant '{tenant_ref}' not found (create it first)")
    email = email.lower().strip()
    if db.query(User).filter(User.tenant_id == tenant.id, User.email == email).first():
        raise SystemExit(f"user '{email}' already exists in tenant '{tenant.slug}'")
    if len(password) < 8:
        raise SystemExit("password must be at least 8 characters")
    u = User(tenant_id=tenant.id, email=email, password_hash=hash_password(password), role=role)
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def main(argv: list[str]) -> int:
    Base.metadata.create_all(bind=db_engine)
    p = argparse.ArgumentParser(prog="app.users", description="Palivane tenant/user admin")
    sub = p.add_subparsers(dest="cmd", required=True)

    ct = sub.add_parser("create-tenant")
    ct.add_argument("--slug", required=True)
    ct.add_argument("--name", default="")
    ct.add_argument("--plan", choices=["free", "team", "enterprise"], default="free")

    cu = sub.add_parser("create-user")
    cu.add_argument("--tenant", required=True)
    cu.add_argument("--email", required=True)
    cu.add_argument("--password")
    cu.add_argument("--role", choices=["admin", "analyst"], default="analyst")

    sub.add_parser("list-tenants")
    lu = sub.add_parser("list-users")
    lu.add_argument("--tenant", required=True)

    # Quota overrides are operator-only on purpose: there is no API for a tenant admin
    # to raise their own caps. 0 (or omitted) = inherit the PALIVANE_QUOTA_* global.
    sq = sub.add_parser("set-quota")
    sq.add_argument("--tenant", required=True)
    sq.add_argument("--users", type=int, default=None)
    sq.add_argument("--api-keys", type=int, default=None)
    sq.add_argument("--ingest-per-day", type=int, default=None)

    # Plan changes are operator-only: upgrades are sales-led (contact-us), so there is
    # deliberately no tenant-facing API for this.
    spl = sub.add_parser("set-plan")
    spl.add_argument("--tenant", required=True)
    spl.add_argument("--plan", choices=["trial", "free", "team", "enterprise"], required=True)

    for name in ("suspend", "resume"):
        sp = sub.add_parser(name)
        sp.add_argument("--tenant", required=True)

    pe = sub.add_parser("purge-empty")
    pe.add_argument("--older-than-days", type=int, default=30)
    pe.add_argument("--yes", action="store_true",
                    help="actually delete (default is a dry-run listing)")

    fn = sub.add_parser("funnel", help="signup→activation product-analytics funnel")
    fn.add_argument("--days", type=int, default=None, help="only orgs created in the last N days")
    fn.add_argument("--all", action="store_true", help="include internal orgs (tachtech, demo)")

    sub.add_parser("plans", help="operator plan roster: every org and its plan")

    # Self-hosted license lifecycle (SaaS uses set-plan instead). Issue records to the
    # registry so licenses can be seen and revoked; renewal is served by /api/license/renew.
    li = sub.add_parser("license-issue", help="sign a self-hosted license AND record it")
    li.add_argument("--key", required=True, help="vendor signing key PEM (file path, or '-' for stdin)")
    li.add_argument("--org", required=True)
    li.add_argument("--plan", choices=["team", "enterprise"], required=True)
    li.add_argument("--seats", type=int, default=0)
    li.add_argument("--term-days", type=int, default=None,
                    help="license term (default: the short renewal term)")
    li.add_argument("--contract-months", type=int, default=12,
                    help="hard stop: renewals refused past this many months (0 = no stop)")
    li.add_argument("--note", default="")

    sub.add_parser("license-list", help="the license registry: every issued license + status")

    lr = sub.add_parser("license-revoke", help="revoke a license (renewals stop; instance drops to Free at term end)")
    lr.add_argument("--id", required=True)

    args = p.parse_args(argv)
    db = SessionLocal()
    try:
        if args.cmd == "create-tenant":
            t = create_tenant(db, args.slug, args.name, args.plan)
            print(f"created tenant #{t.id} '{t.slug}' ({t.name}) plan={t.plan}")
        elif args.cmd == "create-user":
            password = args.password or getpass.getpass("password: ")
            u = create_user(db, args.tenant, args.email, password, args.role)
            print(f"created user #{u.id} {u.email} role={u.role} tenant_id={u.tenant_id}")
        elif args.cmd == "list-tenants":
            for t in db.query(Tenant).all():
                print(f"#{t.id} {t.slug} — {t.name} [{t.plan or 'free'}]")
        elif args.cmd == "set-plan":
            tenant = _get_tenant(db, args.tenant)
            if tenant is None:
                raise SystemExit(f"tenant '{args.tenant}' not found")
            tenant.plan = args.plan
            db.commit()
            print(f"tenant '{tenant.slug}' is now on the {tenant.plan} plan")
        elif args.cmd == "list-users":
            tenant = _get_tenant(db, args.tenant)
            if tenant is None:
                raise SystemExit(f"tenant '{args.tenant}' not found")
            for u in db.query(User).filter(User.tenant_id == tenant.id).all():
                print(f"#{u.id} {u.email} role={u.role} active={u.active}")
        elif args.cmd == "set-quota":
            tenant = _get_tenant(db, args.tenant)
            if tenant is None:
                raise SystemExit(f"tenant '{args.tenant}' not found")
            if args.users is not None:
                tenant.quota_users = args.users
            if args.api_keys is not None:
                tenant.quota_api_keys = args.api_keys
            if args.ingest_per_day is not None:
                tenant.quota_ingest_per_day = args.ingest_per_day
            db.commit()
            print(f"tenant '{tenant.slug}' quotas: users={tenant.quota_users or 'default'} "
                  f"api_keys={tenant.quota_api_keys or 'default'} "
                  f"ingest_per_day={tenant.quota_ingest_per_day or 'default'}")
        elif args.cmd in ("suspend", "resume"):
            tenant = _get_tenant(db, args.tenant)
            if tenant is None:
                raise SystemExit(f"tenant '{args.tenant}' not found")
            tenant.status = "suspended" if args.cmd == "suspend" else "active"
            db.commit()
            print(f"tenant '{tenant.slug}' is now {tenant.status}")
        elif args.cmd == "purge-empty":
            from .lifecycle import purgeable_empty_tenants, purge_tenant
            victims = purgeable_empty_tenants(db, args.older_than_days)
            if not victims:
                print("no purgeable tenants")
            for t in victims:
                if args.yes:
                    counts = purge_tenant(db, t)
                    print(f"purged #{t.id} '{t.slug}' ({sum(counts.values())} rows)")
                else:
                    print(f"would purge #{t.id} '{t.slug}' (created {t.created_at:%Y-%m-%d}) "
                          "— rerun with --yes")
        elif args.cmd == "funnel":
            from . import funnel
            f = funnel.compute(db, days=args.days, include_internal=args.all)
            s, c = f["stages"], f["conversion"]
            scope = f"last {args.days}d" if args.days else "all time"
            print(f"Signup → activation funnel ({scope}"
                  f"{'' if args.all else ', external orgs'}):")
            print(f"  1. signed up   {s['signed_up']:>5}")
            print(f"  2. verified    {s['verified']:>5}  ({c['verified_of_signed_up']}% of signups)")
            print(f"  3. connected   {s['connected']:>5}  ({c['connected_of_verified']}% of verified)")
            print(f"  4. activated   {s['activated']:>5}  ({c['activated_of_connected']}% of connected"
                  f"; {c['activated_of_signed_up']}% end-to-end)")
            print(f"  5. retained 7d {s['retained']:>5}  ({c['retained_of_activated']}% of activated)")
            mdta = f["median_days_to_activate"]
            print(f"  median days to activate: {mdta if mdta is not None else 'n/a'}")
            stuck = f["stuck_orgs"]
            if stuck:
                print(f"  stuck (verified, never activated) — {len(stuck)}, reach out oldest first:")
                for o in stuck[:15]:
                    tag = "connected-a-source" if o["connected"] else "no source yet"
                    print(f"    - {o['slug']}  {o['age_days']}d old  ({tag})")
        elif args.cmd == "plans":
            from .plans import PLANS, plan_of
            from .models import Finding
            activated = {r[0] for r in db.query(Finding.tenant_id).distinct().all()}
            counts = {p: 0 for p in PLANS}
            rows = db.query(Tenant).order_by(Tenant.plan, Tenant.slug).all()
            for t in rows:
                counts[plan_of(t)] = counts.get(plan_of(t), 0) + 1
            print("Plan roster:", ", ".join(f"{PLANS[p]['label']}={counts[p]}" for p in PLANS),
                  f"(total {len(rows)})")
            for t in rows:
                p = plan_of(t)
                flags = []
                if (t.status or "active") != "active":
                    flags.append(t.status)
                flags.append("activated" if t.id in activated else "not activated")
                print(f"  {t.slug:<24} {PLANS[p]['label']:<11} {', '.join(flags)}")
        elif args.cmd == "license-issue":
            import sys as _sys
            from datetime import date, datetime, timedelta, timezone
            from . import licensing
            from .models import License
            pem = _sys.stdin.buffer.read() if args.key == "-" else open(args.key, "rb").read()
            term = args.term_days or licensing.DEFAULT_TERM_DAYS
            expires = date.today() + timedelta(days=term)
            lic_id = f"lic_{secrets.token_hex(4)}"
            blob = licensing.issue(pem, args.org, args.plan, args.seats, expires.isoformat(),
                                   lic_id=lic_id)
            _now = datetime.now(timezone.utc).replace(tzinfo=None)
            contract = _now + timedelta(days=30 * args.contract_months) if args.contract_months else None
            db.add(License(id=lic_id, org=args.org.strip(), plan=args.plan, seats=args.seats,
                           expires_at=datetime(expires.year, expires.month, expires.day),
                           contract_until=contract, note=args.note))
            db.commit()
            print(f"issued {lic_id} — {args.org} / {args.plan} / {args.seats or 'plan-default'} seats"
                  f", term {term}d"
                  f"{', contract ' + contract.strftime('%Y-%m-%d') if contract else ''}")
            print("send the customer this PALIVANE_LICENSE value:")
            print(blob)
        elif args.cmd == "license-list":
            from .models import License
            rows = db.query(License).order_by(License.issued_at.desc()).all()
            if not rows:
                print("no licenses issued")
            for L in rows:
                exp = L.expires_at.strftime("%Y-%m-%d") if L.expires_at else "?"
                extra = f", renewed {L.renew_count}x" if L.renew_count else ""
                print(f"  {L.id}  {L.org:<24} {L.plan:<11} {L.status:<8} term→{exp}{extra}")
        elif args.cmd == "license-revoke":
            from .models import License
            L = db.get(License, args.id)
            if L is None:
                raise SystemExit(f"license '{args.id}' not found")
            L.status = "revoked"
            db.commit()
            print(f"revoked {L.id} ({L.org}) — renewals will be refused; the instance drops "
                  "to Free when its current term expires.")
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
