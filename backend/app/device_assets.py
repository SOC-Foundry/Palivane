"""Per-device AI-asset inventory: which devices have which MCP servers, IDE/browser
extensions, coding agents, skills and plugins.

Detection answers "is this item bad"; this answers the follow-up an incident needs — "which
devices have it" — the day an extension or MCP package turns out to be trojaned. The
posture scans write it as a side effect (best-effort: a failure here never fails the scan
it rides on), and GET /api/fleet/assets reads it.

Replace semantics: a report is authoritative for the slice of the device it covers, so an
uninstalled item drops out instead of lingering. The slice is usually (device, kind); MCP
servers are reported per config FILE, so there it is (device, kind, file), with a server
declared in two files kept until both stop declaring it.

Metadata only: names, versions, publishers and where an item was found. The posture client
never sends file contents for inventory, and nothing here stores argv, env or URL paths.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

from .models import DeviceAsset

KINDS = ("mcp_server", "ide_extension", "browser_extension", "agent", "skill", "plugin")
# What /api/scan/device-inventory may report. The other kinds come from their own scans
# (which carry the full list anyway); two writers for one slice would fight.
INVENTORY_KINDS = ("agent", "skill", "plugin")

_log = logging.getLogger("palivane.device_assets")


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _cut(v, n: int) -> str:
    return str(v or "").strip()[:n]


def _norm_items(items: list[dict]) -> dict[str, dict]:
    """name → item, last one wins; names are case-sensitive but trimmed."""
    out: dict[str, dict] = {}
    for it in items:
        name = _cut(it.get("name"), 255)
        if name:
            out[name] = it
    return out


def _device_rows(db, tenant_id: int, device: str, kind: str) -> dict[str, DeviceAsset]:
    return {r.name: r for r in db.query(DeviceAsset).filter(
        DeviceAsset.tenant_id == tenant_id, DeviceAsset.device == device,
        DeviceAsset.kind == kind)}


def _apply(row: DeviceAsset, it: dict, actor: str, now: datetime) -> None:
    row.actor = _cut(actor, 320)
    row.version = _cut(it.get("version"), 64)
    row.source = _cut(it.get("source"), 255)
    extra = it.get("extra")
    row.extra = extra if isinstance(extra, dict) and extra else None
    row.last_seen = now


def _guarded(fn):
    """Inventory rides on scans that must not fail because of it: log, roll back, move on."""
    def wrapper(db, *a, **kw):
        try:
            return fn(db, *a, **kw)
        except Exception:                                          # noqa: BLE001
            db.rollback()
            _log.warning("device inventory write failed", exc_info=True)
            return 0
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


@_guarded
def replace_assets(db, tenant_id: int | None, device: str, actor: str, kind: str,
                   items: list[dict], keep=None) -> int:
    """Make `device`'s rows of `kind` exactly `items` (dicts of name/version/source/extra):
    upsert what is listed, delete what isn't. `keep(row)` marks existing rows OUTSIDE this
    report's scope (left untouched — e.g. another project's skills). Commits; returns the
    number of items recorded. No-op without a tenant or device."""
    if tenant_id is None or not device or kind not in KINDS:
        return 0
    device = _cut(device, 128)
    now = _now()
    current = _norm_items(items)
    rows = _device_rows(db, tenant_id, device, kind)
    for name, row in rows.items():
        if name not in current and not (keep and keep(row)):
            db.delete(row)
    for name, it in current.items():
        row = rows.get(name)
        if row is None:
            row = DeviceAsset(tenant_id=tenant_id, device=device, kind=kind, name=name,
                              first_seen=now)
            db.add(row)
        _apply(row, it, actor, now)
    db.commit()
    return len(current)


def mcp_server_items(servers: list[dict], packages: dict[str, list]) -> list[dict]:
    """Inventory items for the servers parsed from one MCP config: name, the registry
    package it launches (where resolvable — the version is that pin), transport, and an
    http server's host. Never argv, env or the URL path: those are where tokens sit."""
    out = []
    for s in servers:
        name = s.get("name", "")
        url = s.get("url") or s.get("serverUrl") or ""
        extra: dict = {"transport": "http" if url else "stdio"}
        if url:
            extra["host"] = _cut(urlparse(str(url)).hostname, 255)
        else:
            extra["command"] = _cut(str(s.get("command") or "").replace("\\", "/").split("/")[-1], 64)
        version = ""
        pkgs = packages.get(name) or []
        if pkgs:
            eco, pname, ver = pkgs[0]
            extra["package"] = _cut(f"{eco}:{pname}", 255)
            version = ver
        out.append({"name": name, "version": version, "extra": extra})
    return out


@_guarded
def record_mcp_servers(db, tenant_id: int | None, device: str, actor: str, source: str,
                       items: list[dict]) -> int:
    """Replace the MCP servers `device` declares in ONE config file (`source`). A server's
    row remembers every file declaring it (extra.sources); it is deleted only when the last
    one drops it. Commits; returns the number of items recorded."""
    if tenant_id is None or not device:
        return 0
    device, source = _cut(device, 128), _cut(source, 255) or "mcp config"
    now = _now()
    current = _norm_items(items)
    rows = _device_rows(db, tenant_id, device, "mcp_server")
    for name, row in rows.items():
        if name in current:
            continue
        sources = [s for s in _sources(row) if s != source]
        if len(sources) == len(_sources(row)):
            continue                                   # not this file's server
        if sources:
            row.extra = {**(row.extra or {}), "sources": sources}
            row.source = ", ".join(sources)[:255]
        else:
            db.delete(row)
    for name, it in current.items():
        row = rows.get(name)
        if row is None:
            row = DeviceAsset(tenant_id=tenant_id, device=device, kind="mcp_server",
                              name=name, first_seen=now)
            db.add(row)
            sources = [source]
        else:
            sources = _sources(row)
            if source not in sources:
                sources.append(source)
        _apply(row, {**it, "source": ", ".join(sources)}, actor, now)
        row.extra = {**(row.extra or {}), "sources": sources[:20]}
    db.commit()
    return len(current)


def _sources(row: DeviceAsset) -> list[str]:
    srcs = (row.extra or {}).get("sources")
    if isinstance(srcs, list):
        return [str(s) for s in srcs]
    return [row.source] if row.source else []


@_guarded
def touch_device(db, tenant_id: int | None, device: str, kinds: tuple | list) -> int:
    """Mark `device`'s rows of `kinds` as seen now — the device is alive and has not
    reported a change. The scans behind those kinds only post on change, so without this
    a device whose extensions never change would age out of the inventory. Commits."""
    if tenant_id is None or not device or not kinds:
        return 0
    n = (db.query(DeviceAsset)
           .filter(DeviceAsset.tenant_id == tenant_id, DeviceAsset.device == _cut(device, 128),
                   DeviceAsset.kind.in_(list(kinds)))
           .update({DeviceAsset.last_seen: _now()}, synchronize_session=False))
    db.commit()
    return n
