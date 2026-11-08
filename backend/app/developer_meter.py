"""The developer meter: how many people each protection plane covered, per calendar month.

Per-developer pricing needs a count the product can stand behind, and nothing counted
protected people before this: Stripe seats are console logins, and the fleet ledger
(sensor_heartbeats) keeps only each sensor's last contact and is pruned once a device goes
dark. This records the first report of each person on each plane in each month, so a month
stays countable after the fact.

Kinds, from the heartbeat a capture call already writes:
  agent              coding-tool hooks (Claude Code, Cursor, Codex, Gemini CLI, Copilot),
                     MCP tool calls, and the proxy when it identified a coding assistant
  desktop            the egress proxy, for desktop AI apps and sidebar extensions
  browser            the browser extension
  claude_enterprise  Anthropic Inference hooks (claude.ai users, not necessarily developers)
  ci                 a repository scanned in CI: counted per repo, since its actor is no person
Posture scans and agent-to-agent traffic are not metered: they describe devices and agents.

Writes are cheap by construction: a process remembers what it already recorded this month,
so a person costs one INSERT per process per month, not one per prompt. The hourly
maintenance loop also backfills from the heartbeat ledger, which catches anything a
best-effort write missed before a dark sensor is pruned.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import DeveloperActivity, SensorHeartbeat

log = logging.getLogger("palivane.developer_meter")

KINDS = ("agent", "desktop", "browser", "claude_enterprise", "ci")

# Our own hook clients (User-Agent names) and the coding assistants they report as.
_AGENT_CLIENTS = frozenset({
    "palivane-hook", "palivane-cursor-hook", "palivane-codex-hook", "palivane-gemini-hook",
    "palivane-copilot-hook", "palivane-mcp", "palivane-otel",
})
_CODING_TOOLS = frozenset({"claude-code", "cursor", "codex-cli", "gemini-cli", "copilot"})

# What this process has already written: {(tenant, month, kind, identity)}. Cleared when the
# month turns or it grows past the cap, after which the unique constraint keeps rows single.
_SEEN: set[tuple] = set()
_SEEN_CAP = 50_000
_seen_month = ""


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def month_of(dt: datetime) -> str:
    return f"{dt.year:04d}-{dt.month:02d}"


def classify(plane: str, tool: str = "", client: str = "") -> str | None:
    """The metered kind for one heartbeat, or None when it is not about a person's plane."""
    tool = (tool or "").lower()
    if plane == "mcp":
        return "agent"
    if plane == "ai-usage":
        if client in _AGENT_CLIENTS or tool in _CODING_TOOLS:
            return "agent"
        if client == "palivane-proxy":
            return "desktop"
        if client in ("", "palivane-extension"):
            return "browser"
        return None
    if plane == "inference-hooks":
        return "claude_enterprise"
    if plane == "ci":
        return "ci"
    return None


def identity_of(tenant_id: int | None, kind: str, actor: str, tool: str = "") -> str:
    """A keyed hash of who this is, the same for one person on every plane so the planes can
    be compared (a CI row hashes its repository instead); "" when the report named nobody."""
    who = ((tool or "").strip().lower() and "repo:" + tool.strip().lower()) if kind == "ci" \
        else (actor or "").strip().lower()
    if not who:
        return ""
    return hmac.new(_key(), f"{tenant_id}:{who}".encode(), hashlib.sha256).hexdigest()[:32]


def _key() -> bytes:
    # The app secret, separated by purpose so this hash can never double as a token MAC.
    from .security import _secret
    return hmac.new(_secret(), b"palivane-developer-meter", hashlib.sha256).digest()


def _insert(db: Session, tenant_id: int, month: str, kind: str, ident: str, when: datetime) -> bool:
    """Record one (tenant, month, kind, identity); True when the row is new. Commits."""
    exists = (db.query(DeveloperActivity.id)
                .filter(DeveloperActivity.tenant_id == tenant_id, DeveloperActivity.month == month,
                        DeveloperActivity.kind == kind, DeveloperActivity.identity == ident)
                .first())
    if exists:
        return False
    db.add(DeveloperActivity(tenant_id=tenant_id, month=month, kind=kind, identity=ident,
                             first_seen=when))
    try:
        db.commit()
        return True
    except IntegrityError:          # another worker wrote it first
        db.rollback()
        return False


def record(db: Session, tenant_id: int | None, actor: str, plane: str, tool: str = "",
           client: str = "") -> None:
    """Meter one capture call. Best-effort: never raises into the capture path."""
    global _seen_month
    if tenant_id is None:
        return
    kind = classify(plane, tool, client)
    if kind is None:
        return
    try:
        now = _now()
        month = month_of(now)
        if month != _seen_month or len(_SEEN) > _SEEN_CAP:
            _SEEN.clear()
            _seen_month = month
        ident = identity_of(tenant_id, kind, actor, tool)
        key = (tenant_id, month, kind, ident)
        if key in _SEEN:
            return
        _insert(db, tenant_id, month, kind, ident, now)
        _SEEN.add(key)
    except Exception:
        db.rollback()
        log.debug("developer meter write failed", exc_info=True)


def backfill_from_heartbeats(db: Session, now: datetime | None = None) -> int:
    """Make sure every sensor seen this month (and last month, for the days around the turn)
    is metered. Idempotent; run before dark sensors are pruned. Returns rows added."""
    now = now or _now()
    this = month_of(now)
    first = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    prev_start = (first.replace(year=first.year - 1, month=12) if first.month == 1
                  else first.replace(month=first.month - 1))
    added = 0
    rows = (db.query(SensorHeartbeat.tenant_id, SensorHeartbeat.actor, SensorHeartbeat.plane,
                     SensorHeartbeat.tool, SensorHeartbeat.client, SensorHeartbeat.last_seen)
              .filter(SensorHeartbeat.last_seen >= prev_start).all())
    for r in rows:
        kind = classify(r.plane, r.tool, r.client or "")
        if kind is None or r.tenant_id is None:
            continue
        month = month_of(r.last_seen) if r.last_seen < first else this
        added += _insert(db, r.tenant_id, month, kind,
                         identity_of(r.tenant_id, kind, r.actor, r.tool), r.last_seen)
    return added


def summary(db: Session, tenant_id: int, months: int = 3, now: datetime | None = None) -> dict:
    """Per-month counts for the console, newest first:
    {month, agent, desktop, browser, browser_only, claude_enterprise, ci_repos, unattributed}.
    `browser_only` is people seen in the browser or on desktop and NOT on the agent plane;
    `unattributed` counts the kinds that had reports naming nobody."""
    now = now or _now()
    want, y, m = [], now.year, now.month
    for _ in range(max(1, min(months, 24))):
        want.append(f"{y:04d}-{m:02d}")
        y, m = (y - 1, 12) if m == 1 else (y, m - 1)
    rows = (db.query(DeveloperActivity.month, DeveloperActivity.kind, DeveloperActivity.identity)
              .filter(DeveloperActivity.tenant_id == tenant_id,
                      DeveloperActivity.month.in_(want)).all())
    out = []
    for month in want:
        by_kind: dict[str, set[str]] = {k: set() for k in KINDS}
        unattributed = 0
        for r in rows:
            if r.month != month or r.kind not in by_kind:
                continue
            if r.identity:
                by_kind[r.kind].add(r.identity)
            else:
                unattributed += 1
        out.append({"month": month,
                    "agent": len(by_kind["agent"]), "desktop": len(by_kind["desktop"]),
                    "browser": len(by_kind["browser"]),
                    "browser_only": len((by_kind["browser"] | by_kind["desktop"]) - by_kind["agent"]),
                    "claude_enterprise": len(by_kind["claude_enterprise"]),
                    "ci_repos": len(by_kind["ci"]), "unattributed": unattributed})
    return {"months": out}
