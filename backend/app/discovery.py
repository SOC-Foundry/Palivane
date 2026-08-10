"""Shadow-AI discovery: turn observed AI usage into an inventory.

Two intake paths feed one store (DiscoveredUsage):
  - record_capture(): called when a capture plane scored content bound for an AI tool, so
    we know the destination AND whether it carried sensitive data.
  - ingest_logs(): classifies AI usage from CASB / SWG / proxy / DNS logs — attribution
    only (no content), which is how you discover usage on unmanaged devices.

build_inventory() rolls the store up two ways — by tool and by team/department — and marks
each tool sanctioned/unsanctioned against the tenant's live allowlist. Unlike a log-only
tool, Palivane knows the *actual* sensitive data each tool received (sensitive_count), because
it inspects content at the capture planes — that's the exposure column competitors can't fill.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .ai_catalog import CATEGORY_LABEL, classify, classify_name
from .detectors.shadow_ai import _PERSONAL_EMAIL_DOMAINS
from .models import DiscoveredUsage, TenantDomain


def _account_type(db, tenant_id, actor: str) -> str:
    """Classify the identity an actor used to reach an AI tool: corporate (email on one of
    the tenant's DNS-verified domains), personal (a free-mail domain), or unknown. Best
    proxy for personal-vs-corporate ACCOUNT without OAuth introspection — a sanctioned tool
    reached from a personal account is still shadow AI."""
    at = (actor or "").strip().lower()
    if "@" not in at:
        return "unknown"
    domain = at.rsplit("@", 1)[-1]
    if not domain:
        return "unknown"
    if domain in _PERSONAL_EMAIL_DOMAINS:
        return "personal"
    if tenant_id is not None and db.query(TenantDomain).filter(
            TenantDomain.tenant_id == tenant_id,
            TenantDomain.domain == domain).first() is not None:
        return "corporate"
    return "unknown"

_SENSITIVE = {"secret_leak", "pii_exposure", "source_code_leak", "confidential_data", "credential_at_rest"}


def _norm(s: str) -> str:
    return (s or "").strip().lower()


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _sanctioned_set(raw: str) -> set[str]:
    """Approved destinations, lowercased — names or domains, comma/newline separated."""
    out: set[str] = set()
    for part in (raw or "").replace("\n", ",").split(","):
        p = part.strip().lower()
        if p:
            out.add(p)
    return out


def _is_sanctioned(tool: str, domain: str, sanctioned: set[str]) -> bool:
    # Exact tool match, or exact/suffix domain match — NOT a bare substring (which would
    # let "ai" sanction "openai" or "corp.com" sanction "evilcorp.com.attacker.net").
    t, d = tool.lower(), (domain or "").lower()
    if t in sanctioned or (d and d in sanctioned):
        return True
    return any(s and (d == s or d.endswith("." + s)) for s in sanctioned)


def _upsert(db, tenant_id, actor, hit, *, source, inc=1, sensitive=False, risk=0, team="", when=None):
    """Increment (or create) the (actor, tool) row. Flushes a freshly-created row so a
    subsequent lookup in the same request sees it (no duplicate-insert on the unique key)."""
    actor_n = _norm(actor) or "unknown"
    row = (db.query(DiscoveredUsage)
             .filter(DiscoveredUsage.tenant_id == tenant_id,
                     DiscoveredUsage.actor == actor_n,
                     DiscoveredUsage.tool == hit["tool"])
             .one_or_none())
    when = when or _now()
    if row is None:
        row = DiscoveredUsage(
            tenant_id=tenant_id, actor=actor_n, tool=hit["tool"], domain=hit["domain"],
            category=hit["category"], source=source, event_count=0, sensitive_count=0,
            max_risk=0, first_seen=when, last_seen=when, team=team or "",
        )
        db.add(row)
        db.flush()
    if not row.account_type:                # classify once; cheap, and stable per actor
        row.account_type = _account_type(db, tenant_id, actor_n)
    row.event_count = (row.event_count or 0) + inc
    if sensitive:
        row.sensitive_count = (row.sensitive_count or 0) + 1
    if risk and risk > (row.max_risk or 0):
        row.max_risk = risk
    if team and not row.team:
        row.team = team
    if source == "capture":               # capture is higher-signal than a log line
        row.source = "capture"
    if when and (row.last_seen is None or when > row.last_seen):
        row.last_seen = when
    return row


def record_capture(db, tenant_id, actor, destination, tool_channel, signals, risk) -> None:
    """Record that a capture plane saw content go to an AI tool. Best-effort — never raises
    into the request path."""
    try:
        hit = classify(destination or "") or classify(tool_channel or "")
        if not hit:
            return
        cats = {s.get("category") for s in (signals or [])}
        sensitive = bool(cats & _SENSITIVE)
        _upsert(db, tenant_id, actor, hit, source="capture", sensitive=sensitive, risk=int(risk or 0))
        db.commit()
    except Exception:
        db.rollback()


def record_capture_client(db, tenant_id, actor, hit, signals, risk) -> None:
    """Record an MCP-surface capture whose tool is already resolved from the plane identity
    (ai_catalog.classify_client) rather than a destination domain. Best-effort — never raises
    into the request path. `hit` may be None (unrecognized plane), in which case we skip."""
    try:
        if not hit:
            return
        cats = {s.get("category") for s in (signals or [])}
        sensitive = bool(cats & _SENSITIVE)
        _upsert(db, tenant_id, actor, hit, source="capture", sensitive=sensitive, risk=int(risk or 0))
        db.commit()
    except Exception:
        db.rollback()


def ingest_logs(db, tenant_id, events) -> dict:
    """Classify AI usage from log events. Each event has .actor and one of
    .destination/.domain/.tool, plus optional .team, .count, .last_seen. Returns a summary."""
    matched = new_actors_tools = unknown = 0
    seen_before = {(r.actor, r.tool) for r in
                   db.query(DiscoveredUsage.actor, DiscoveredUsage.tool)
                     .filter(DiscoveredUsage.tenant_id == tenant_id).all()}
    tools: set[str] = set()
    for e in events:
        dest = getattr(e, "destination", "") or getattr(e, "domain", "") or getattr(e, "tool", "")
        hit = classify(dest)
        if not hit:
            unknown += 1
            continue
        matched += 1
        tools.add(hit["tool"])
        actor_n = _norm(getattr(e, "actor", "")) or "unknown"
        if (actor_n, hit["tool"]) not in seen_before:
            new_actors_tools += 1
            seen_before.add((actor_n, hit["tool"]))
        when = None
        ls = getattr(e, "last_seen", "") or ""
        if ls:
            try:
                when = datetime.fromisoformat(ls.replace("Z", "+00:00")).replace(tzinfo=None)
            except ValueError:
                when = None
        n = max(1, min(int(getattr(e, "count", 1) or 1), 100000))
        _upsert(db, tenant_id, actor_n, hit, source="log", inc=n,
                team=getattr(e, "team", "") or "", when=when)
    db.commit()
    return {"events": len(events), "matched": matched, "unrecognized": unknown,
            "tools_seen": sorted(tools), "new_pairs": new_actors_tools}


# OAuth scopes that give a third-party app broad reach into the SaaS tenant's data —
# an AI app holding these is reading mail/files/chat, not just a name/email.
_BROAD_SCOPE_MARKERS = ("mail", "gmail", "drive", "files.read", "files.readwrite",
                        "documents", "spreadsheets", "calendar", "contacts", "chat",
                        "channels:history", "im:history", "sites.read", "full_access")


def ingest_oauth_grants(db, tenant_id, grants) -> dict:
    """Discover AI tools reached via OAuth grants into a SaaS platform — the channel a
    proxy/extension can't see. Classify each granted app against the catalog; an AI app is
    recorded as discovered usage (source='oauth'), flagged as sensitive when it holds broad
    data scopes. Returns a summary."""
    matched = unknown = broad = 0
    for g in grants:
        name = (getattr(g, "app_name", "") or "").strip()
        hit = classify_name(name)
        if not hit:
            unknown += 1
            continue
        matched += 1
        scopes = [str(s).lower() for s in (getattr(g, "scopes", []) or [])]
        is_broad = any(any(m in s for m in _BROAD_SCOPE_MARKERS) for s in scopes)
        if is_broad:
            broad += 1
        actor_n = _norm(getattr(g, "user", "")) or "unknown"
        # A broad-scope AI grant is the sensitive case — it's actively reading SaaS data.
        _upsert(db, tenant_id, actor_n, hit, source="oauth",
                sensitive=is_broad, risk=70 if is_broad else 0)
    db.commit()
    return {"grants": len(grants), "ai_apps": matched, "broad_scope": broad, "unknown": unknown}


def build_inventory(db, tenant_id, sanctioned_raw: str) -> dict:
    """Roll the store up into the discovery inventory: summary + by-tool + by-team."""
    rows = db.query(DiscoveredUsage).filter(DiscoveredUsage.tenant_id == tenant_id).all()
    sanctioned = _sanctioned_set(sanctioned_raw)

    tools: dict[str, dict] = {}
    teams: dict[str, dict] = {}
    for r in rows:
        san = _is_sanctioned(r.tool, r.domain, sanctioned)
        t = tools.setdefault(r.tool, {
            "tool": r.tool, "category": r.category, "category_label": CATEGORY_LABEL.get(r.category, r.category),
            "domain": r.domain, "sanctioned": san, "users": set(), "events": 0,
            "sensitive_events": 0, "max_risk": 0, "sources": set(), "last_seen": "",
            "personal_users": set(), "corporate_users": set(),
        })
        t["users"].add(r.actor)
        if r.account_type == "personal":
            t["personal_users"].add(r.actor)
        elif r.account_type == "corporate":
            t["corporate_users"].add(r.actor)
        t["events"] += r.event_count or 0
        t["sensitive_events"] += r.sensitive_count or 0
        t["max_risk"] = max(t["max_risk"], r.max_risk or 0)
        t["sources"].add(r.source)
        ls = r.last_seen.isoformat() if r.last_seen else ""
        if ls > t["last_seen"]:
            t["last_seen"] = ls

        team_name = r.team or "Unassigned"
        g = teams.setdefault(team_name, {
            "team": team_name, "users": set(), "tools": set(), "unsanctioned_tools": set(),
            "events": 0, "sensitive_events": 0, "max_risk": 0,
        })
        g["users"].add(r.actor)
        g["tools"].add(r.tool)
        if not san:
            g["unsanctioned_tools"].add(r.tool)
        g["events"] += r.event_count or 0
        g["sensitive_events"] += r.sensitive_count or 0
        g["max_risk"] = max(g["max_risk"], r.max_risk or 0)

    def _tool_risk(t):
        # Prioritize: unsanctioned + carried sensitive data + high peak severity.
        score = t["max_risk"]
        if not t["sanctioned"]:
            score += 25
        if t["sensitive_events"]:
            score += 20
        return min(100, score)

    tool_list = []
    for t in tools.values():
        t["user_count"] = len(t["users"])
        t["personal_user_count"] = len(t["personal_users"])
        t["corporate_user_count"] = len(t["corporate_users"])
        t["risk"] = _tool_risk(t)
        t["sources"] = sorted(t["sources"])
        del t["users"], t["personal_users"], t["corporate_users"]
        tool_list.append(t)
    tool_list.sort(key=lambda x: (not x["sanctioned"], x["risk"], x["events"]), reverse=True)

    team_list = []
    for g in teams.values():
        team_list.append({
            "team": g["team"], "user_count": len(g["users"]),
            "tool_count": len(g["tools"]), "unsanctioned_count": len(g["unsanctioned_tools"]),
            "events": g["events"], "sensitive_events": g["sensitive_events"], "max_risk": g["max_risk"],
        })
    team_list.sort(key=lambda x: (x["unsanctioned_count"], x["sensitive_events"], x["max_risk"]), reverse=True)

    unsanctioned = [t for t in tool_list if not t["sanctioned"]]
    # The Netskope-style headline: distinct actors reaching ANY tool via a personal account,
    # and the sharper risk — personal accounts on UNsanctioned tools.
    personal_actors = {r.actor for r in rows if r.account_type == "personal"}
    personal_on_unsanctioned = len([t for t in unsanctioned if t["personal_user_count"]])
    return {
        "summary": {
            "tools": len(tool_list),
            "unsanctioned_tools": len(unsanctioned),
            "users": len({r.actor for r in rows}),
            "sensitive_events": sum(t["sensitive_events"] for t in tool_list),
            "teams": len([g for g in team_list if g["team"] != "Unassigned"]),
            "personal_account_users": len(personal_actors),
            "personal_on_unsanctioned_tools": personal_on_unsanctioned,
        },
        "tools": tool_list,
        "teams": team_list,
    }
