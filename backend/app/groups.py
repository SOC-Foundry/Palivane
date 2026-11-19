"""Identity-provider groups → console role and Discovery team.

Okta and Entra (and any IdP that speaks the same claims) tell us which groups a person
is in through three channels that all land here:

  * SCIM Groups membership (the group push Okta and Entra actually send)
  * a `groups` attribute on the SCIM User
  * the `groups` claim on an OIDC ID token or a SAML assertion (parsed in oidc.py / saml.py)

An admin maps a group name or id onto a console role and a team. The group string is
whatever the IdP sends — an Okta group name, an Entra display name, or an Entra object
id — matched case-insensitively. A person in several mapped groups gets the highest role
(admin, then analyst, then auditor, then member). A mapping that doesn't name a role is
member. The team stamped on them is the one from the highest-role mapping that sets a
team, and Discovery copies it onto that actor's rows so the inventory can filter and
group by team.

Groups are authoritative only when a mapping matches. A console role with no mapped
group is left alone, so turning the feature on doesn't demote anyone the IdP never
mentioned. Once a mapping has set the role, leaving every mapped group returns the
person to member. The last active admin is never removed this way.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from .models import AuditLog, DiscoveredUsage, GroupMapping, ScimGroup, ScimGroupMember, User

# Highest privilege wins when a person is in more than one mapped group.
ROLE_RANK = {"admin": 3, "analyst": 2, "auditor": 1, "member": 0}
CONSOLE_ROLES = ("admin", "analyst", "auditor", "member")


def collapse_groups(value) -> list[str]:
    """Flatten a groups claim or SCIM multi-valued attribute into display strings.

    Accepts a string, a list of strings, or SCIM values shaped `{value, display}`.
    Order is kept, duplicates (case-insensitive) are dropped.
    """
    out: list[str] = []

    def walk(v) -> None:
        if v is None or isinstance(v, bool):
            return
        if isinstance(v, str):
            s = v.strip()
            if s:
                out.append(s)
            return
        if isinstance(v, dict):
            picked = v.get("value") or v.get("display") or v.get("displayName")
            if picked is not None and picked is not v:
                walk(picked)
            return
        if isinstance(v, (list, tuple)):
            for item in v:
                walk(item)

    walk(value)
    seen: set[str] = set()
    uniq: list[str] = []
    for s in out:
        key = s.lower()
        if key in seen:
            continue
        seen.add(key)
        uniq.append(s)
    return uniq


def overage_only(names: list[str]) -> bool:
    """Entra replaces the groups claim with a Graph URL when the token would be too
    large. That URL is not a group, and treating it as one would wipe a real role."""
    return bool(names) and all(n.lower().startswith(("http://", "https://")) for n in names)


def groups_from_scim_user(body: dict) -> list[str] | None:
    """The groups attribute on a SCIM User, top-level or inside a schema extension.

    None when the payload doesn't mention groups (leave the stored set alone). An
    empty list is an explicit 'in no groups'.
    """
    if not isinstance(body, dict):
        return None
    if "groups" in body:
        return collapse_groups(body.get("groups"))
    for value in body.values():
        if isinstance(value, dict) and "groups" in value:
            return collapse_groups(value.get("groups"))
    return None


def _sources(user: User) -> dict:
    raw = user.group_sources or {}
    return dict(raw) if isinstance(raw, dict) else {}


def effective_groups(db: Session, user: User) -> set[str]:
    """Lowercased group names and ids currently asserted for this user."""
    found: set[str] = set()
    for values in _sources(user).values():
        for name in collapse_groups(values):
            found.add(name.lower())
    if user.id is None:
        return found
    rows = (db.query(ScimGroup.display_name, ScimGroup.external_id)
              .join(ScimGroupMember, ScimGroupMember.group_id == ScimGroup.id)
              .filter(ScimGroupMember.user_id == user.id)
              .all())
    for display_name, external_id in rows:
        if display_name:
            found.add(display_name.strip().lower())
        if external_id:
            found.add(external_id.strip().lower())
    return found


def group_labels(db: Session, user: User) -> list[str]:
    """Group names for the console, original case, one per distinct group."""
    labels: list[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        text = (name or "").strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            labels.append(text)

    for values in _sources(user).values():
        for name in collapse_groups(values):
            add(name)
    if user.id is not None:
        rows = (db.query(ScimGroup.display_name)
                  .join(ScimGroupMember, ScimGroupMember.group_id == ScimGroup.id)
                  .filter(ScimGroupMember.user_id == user.id)
                  .all())
        for (display_name,) in rows:
            add(display_name or "")
    return labels


def resolve_grants(mappings: list[GroupMapping], groups: set[str]) -> tuple[str, str] | None:
    """(role, team) from the mappings this group set hits, or None when none match.

    Role is the highest match. Team comes from the highest-role match that names a
    team (lowest id breaks a tie) so a member-level 'Everyone' group doesn't override
    the team on the admin group.
    """
    matched = [m for m in mappings if (m.group_key or "") in groups]
    if not matched:
        return None
    role = max(matched, key=lambda m: ROLE_RANK.get(m.role or "member", 0)).role or "member"
    if role not in ROLE_RANK:
        role = "member"
    with_team = [m for m in matched if (m.team or "").strip()]
    if not with_team:
        return role, ""
    best = max(with_team, key=lambda m: (ROLE_RANK.get(m.role or "member", 0), -m.id))
    return role, best.team.strip()


def _keep_last_admin(db: Session, user: User, new_role: str) -> bool:
    """True when applying new_role would remove the org's only active admin."""
    if user.role != "admin" or new_role == "admin" or not user.active:
        return False
    from .auth import lock_admin_changes
    lock_admin_changes(db, user.tenant_id)
    others = (db.query(User)
                .filter(User.tenant_id == user.tenant_id, User.role == "admin",
                        User.active.is_(True), User.id != user.id)
                .count())
    return others < 1


def _stamp_discovery(db: Session, user: User, previous: str) -> None:
    """Copy the directory team onto this person's discovery rows.

    A non-empty team replaces whatever a log line said. Clearing a directory team
    only clears rows that still show that team, so a team that came from a log and
    was never the directory's is left alone.
    """
    actor = (user.email or "").strip().lower()
    if not actor or user.tenant_id is None:
        return
    new = (user.team or "").strip()
    q = (db.query(DiscoveredUsage)
           .filter(DiscoveredUsage.tenant_id == user.tenant_id,
                   DiscoveredUsage.actor == actor))
    if new:
        q.update({DiscoveredUsage.team: new}, synchronize_session=False)
    elif previous:
        q.filter(DiscoveredUsage.team == previous).update(
            {DiscoveredUsage.team: ""}, synchronize_session=False)


def apply_group_grants(db: Session, user: User, *, actor: str = "directory") -> None:
    """Recompute role and team from this user's current groups. Does not commit."""
    if user.id is None:
        db.flush()
    mappings = (db.query(GroupMapping)
                  .filter(GroupMapping.tenant_id == user.tenant_id)
                  .all())
    groups = effective_groups(db, user)
    resolved = resolve_grants(mappings, groups)
    previous_team = user.team or ""
    old_role = user.role
    if resolved is None:
        if not user.role_from_groups:
            return
        # The directory used to grant a role and no longer does.
        new_role, new_team = "member", ""
    else:
        new_role, new_team = resolved
    if _keep_last_admin(db, user, new_role):
        new_role = user.role
    changed = user.role != new_role or (user.team or "") != new_team
    user.role = new_role
    user.team = new_team
    # True while a mapping matches, including when the last-admin guard kept the
    # role: the next sync demotes them once another admin exists. False once the
    # directory no longer matches anything, so a later console role sticks until
    # a mapping matches again.
    user.role_from_groups = resolved is not None
    _stamp_discovery(db, user, previous_team)
    if changed:
        db.add(AuditLog(
            tenant_id=user.tenant_id, actor=actor or "directory",
            action="user.group_role", target=user.email or "",
            detail={"from": old_role, "to": user.role, "team": user.team or "",
                    "groups": sorted(groups)[:20]}))


def set_group_source(db: Session, user: User, source: str, groups: list[str] | None,
                     *, actor: str = "directory") -> None:
    """Replace one channel's groups (sso, scim_attr) and recompute. None = not asserted."""
    if groups is None:
        return
    data = _sources(user)
    data[source] = collapse_groups(groups)
    user.group_sources = data
    apply_group_grants(db, user, actor=actor)


def recompute_tenant(db: Session, tenant_id: int, *, actor: str = "directory") -> None:
    """Re-apply mappings for everyone the directory has ever described, and for anyone
    whose role currently comes from a mapping (so deleting a mapping demotes them)."""
    users = db.query(User).filter(User.tenant_id == tenant_id).all()
    member_ids = {row[0] for row in db.query(ScimGroupMember.user_id)
                  .filter(ScimGroupMember.tenant_id == tenant_id).all()}
    for user in users:
        if user.id in member_ids or _sources(user) or user.role_from_groups:
            apply_group_grants(db, user, actor=actor)
