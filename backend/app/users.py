"""Admin CLI for bootstrapping tenants and users (no API auth needed).

    python -m app.users create-tenant --slug acme --name "Acme Corp"
    python -m app.users create-user --tenant acme --email soc@acme.com --role admin --password ...
    python -m app.users list-tenants
    python -m app.users list-users --tenant acme

If --password is omitted on create-user, it is read interactively (not echoed).
"""

from __future__ import annotations

import argparse
import getpass
import sys

from .database import Base, SessionLocal, engine as db_engine
from .models import Tenant, User
from .security import hash_password


def _get_tenant(db, ref: str) -> Tenant | None:
    t = db.query(Tenant).filter(Tenant.slug == ref).first()
    if t is None and ref.isdigit():
        t = db.get(Tenant, int(ref))
    return t


def create_tenant(db, slug: str, name: str) -> Tenant:
    if _get_tenant(db, slug):
        raise SystemExit(f"tenant '{slug}' already exists")
    t = Tenant(slug=slug.lower().strip(), name=name or slug)
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
    p = argparse.ArgumentParser(prog="app.users", description="Warden tenant/user admin")
    sub = p.add_subparsers(dest="cmd", required=True)

    ct = sub.add_parser("create-tenant")
    ct.add_argument("--slug", required=True)
    ct.add_argument("--name", default="")

    cu = sub.add_parser("create-user")
    cu.add_argument("--tenant", required=True)
    cu.add_argument("--email", required=True)
    cu.add_argument("--password")
    cu.add_argument("--role", choices=["admin", "analyst"], default="analyst")

    sub.add_parser("list-tenants")
    lu = sub.add_parser("list-users")
    lu.add_argument("--tenant", required=True)

    args = p.parse_args(argv)
    db = SessionLocal()
    try:
        if args.cmd == "create-tenant":
            t = create_tenant(db, args.slug, args.name)
            print(f"created tenant #{t.id} '{t.slug}' ({t.name})")
        elif args.cmd == "create-user":
            password = args.password or getpass.getpass("password: ")
            u = create_user(db, args.tenant, args.email, password, args.role)
            print(f"created user #{u.id} {u.email} role={u.role} tenant_id={u.tenant_id}")
        elif args.cmd == "list-tenants":
            for t in db.query(Tenant).all():
                print(f"#{t.id} {t.slug} — {t.name}")
        elif args.cmd == "list-users":
            tenant = _get_tenant(db, args.tenant)
            if tenant is None:
                raise SystemExit(f"tenant '{args.tenant}' not found")
            for u in db.query(User).filter(User.tenant_id == tenant.id).all():
                print(f"#{u.id} {u.email} role={u.role} active={u.active}")
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
