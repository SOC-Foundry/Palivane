"""Per-device AI-asset inventory: the posture scans record what is on each device
(replace semantics per kind / per MCP config file), GET /api/fleet/assets answers "which
devices have X" tenant-scoped, and rows age out with the device."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app import users as users_cli
from app.lifecycle import TENANT_TABLES, prune_dark_sensors, purge_tenant
from app.main import app
from app.models import DeviceAsset, Tenant


def _ingest_key(client, actor="fleet@acme.com"):
    r = client.post("/api/apikeys", json={"label": "fleet", "actor": actor, "scope": "ingest"})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _ide(raw, key, exts, device="dev@lap1", versions=None):
    r = raw.post("/api/scan/ide-extensions", headers={"X-Palivane-Token": key},
                 json={"extensions": exts, "device": device, "user": "dev",
                       "versions": versions or {}})
    assert r.status_code == 200, r.text


def _mcp(raw, key, path, servers, device="dev@lap1"):
    r = raw.post("/api/scan/mcp-config", headers={"X-Palivane-Token": key},
                 json={"content": json.dumps({"mcpServers": servers}), "path": path,
                       "device": device, "user": "dev"})
    assert r.status_code == 200, r.text


def _inventory(raw, key, items, device="dev@lap1", project="", kinds=("agent", "skill", "plugin")):
    r = raw.post("/api/scan/device-inventory", headers={"X-Palivane-Token": key},
                 json={"device": device, "user": "dev", "kinds": list(kinds),
                       "project": project, "items": items})
    assert r.status_code == 200, r.text
    return r.json()


def _rows(db_factory, kind=None):
    db = db_factory()
    try:
        q = db.query(DeviceAsset)
        if kind:
            q = q.filter(DeviceAsset.kind == kind)
        return {(r.device, r.name): r for r in q.all()}
    finally:
        db.close()


def _second_tenant_client(db_factory):
    db = db_factory()
    users_cli.create_tenant(db, "globex", "Globex", plan="enterprise")
    users_cli.create_user(db, "globex", "admin@globex.com", "password123", "admin")
    db.close()
    c = TestClient(app)
    tok = c.post("/api/auth/login", json={"email": "admin@globex.com",
                                          "password": "password123"}).json()["access_token"]
    c.headers.update({"Authorization": f"Bearer {tok}"})
    return c


# --- recording: replace semantics ---------------------------------------------------------

def test_ide_extensions_replace_device_set(client, raw_client, db_factory):
    key = _ingest_key(client)
    _ide(raw_client, key, ["ms-python.python", "acme.helper"], versions={"acme.helper": "1.0.0"})
    rows = _rows(db_factory, "ide_extension")
    assert set(rows) == {("dev@lap1", "ms-python.python"), ("dev@lap1", "acme.helper")}
    assert rows[("dev@lap1", "acme.helper")].version == "1.0.0"
    assert rows[("dev@lap1", "acme.helper")].source == "acme"            # publisher
    first = rows[("dev@lap1", "ms-python.python")].first_seen

    _ide(raw_client, key, ["ms-python.python", "other.tool"])
    rows = _rows(db_factory, "ide_extension")
    assert set(rows) == {("dev@lap1", "ms-python.python"), ("dev@lap1", "other.tool")}
    assert rows[("dev@lap1", "ms-python.python")].first_seen == first   # kept, not re-created

    # Another device's report leaves this one alone.
    _ide(raw_client, key, ["x.y"], device="dev@lap2")
    assert ("dev@lap1", "other.tool") in _rows(db_factory, "ide_extension")


def test_ide_extensions_without_device_records_no_inventory(client, raw_client, db_factory):
    """CI / an older client sends no device: vetting still runs, no inventory rows."""
    key = _ingest_key(client)
    r = raw_client.post("/api/scan/ide-extensions", headers={"X-Palivane-Token": key},
                        json={"extensions": ["ms-python.python"]})
    assert r.status_code == 200
    assert _rows(db_factory) == {}


def test_mcp_servers_replace_per_config_file(client, raw_client, db_factory):
    key = _ingest_key(client)
    _mcp(raw_client, key, "~/.claude.json", {
        "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@1.2.0"]},
        "shared": {"command": "uvx", "args": ["shared-mcp"]}})
    _mcp(raw_client, key, "~/.cursor/mcp.json", {
        "shared": {"command": "uvx", "args": ["shared-mcp"]},
        "remote": {"url": "https://mcp.example.com/sse/path?x=1"}})
    rows = _rows(db_factory, "mcp_server")
    assert {n for _, n in rows} == {"github", "shared", "remote"}
    gh = rows[("dev@lap1", "github")]
    assert gh.version == "1.2.0" and gh.extra["package"] == "npm:@modelcontextprotocol/server-github"
    assert gh.extra["command"] == "npx"
    remote = rows[("dev@lap1", "remote")].extra
    assert remote["host"] == "mcp.example.com" and "path" not in json.dumps(remote)
    assert sorted(rows[("dev@lap1", "shared")].extra["sources"]) == ["~/.claude.json",
                                                                     "~/.cursor/mcp.json"]

    # The first file drops `shared` and `github`: shared stays (the cursor file still has it).
    _mcp(raw_client, key, "~/.claude.json", {})
    rows = _rows(db_factory, "mcp_server")
    assert {n for _, n in rows} == {"shared", "remote"}
    assert rows[("dev@lap1", "shared")].extra["sources"] == ["~/.cursor/mcp.json"]

    # An unparseable file is not "declares nothing": it must not wipe the file's servers.
    r = raw_client.post("/api/scan/mcp-config", headers={"X-Palivane-Token": key},
                        json={"content": "{not json", "path": "~/.cursor/mcp.json",
                              "device": "dev@lap1"})
    assert r.status_code == 200
    assert {n for _, n in _rows(db_factory, "mcp_server")} == {"shared", "remote"}

    _mcp(raw_client, key, "~/.cursor/mcp.json", {})
    assert _rows(db_factory, "mcp_server") == {}


def test_browser_extensions_feed_inventory(client, raw_client, db_factory):
    key = _ingest_key(client)
    ext_id = "a" * 32
    body = {"device": "install-1", "record": True,
            "extensions": [{"id": ext_id, "name": "Some Helper", "version": "2.0"}]}
    assert raw_client.post("/api/scan/browser-extensions", json=body,
                           headers={"X-Palivane-Token": key}).status_code == 200
    rows = _rows(db_factory, "browser_extension")
    row = rows[("install-1", ext_id)]
    assert row.source == "Some Helper" and row.version == "2.0"
    body["extensions"] = []
    raw_client.post("/api/scan/browser-extensions", json=body, headers={"X-Palivane-Token": key})
    assert _rows(db_factory, "browser_extension") == {}


def test_device_inventory_replaces_each_kind(client, raw_client, db_factory):
    key = _ingest_key(client)
    out = _inventory(raw_client, key, [
        {"kind": "agent", "name": "claude-code", "version": "2.1.0", "source": "path",
         "extra": {"palivane_hooks": "installed", "hooks_enabled": True}},
        {"kind": "agent", "name": "codex", "version": "0.9.0"},
        {"kind": "plugin", "name": "lsp@official", "version": "1.0.0", "source": "official"},
        {"kind": "skill", "name": "deploy", "source": "user"},
        # Not this endpoint's to write (the mcp-config scan owns it): ignored.
        {"kind": "mcp_server", "name": "sneaky"},
    ])
    assert out["recorded"] == {"agent": 2, "skill": 1, "plugin": 1}
    rows = _rows(db_factory)
    assert {(r.kind, r.name) for r in rows.values()} == {
        ("agent", "claude-code"), ("agent", "codex"), ("plugin", "lsp@official"),
        ("skill", "deploy")}
    assert rows[("dev@lap1", "claude-code")].extra == {"palivane_hooks": "installed",
                                                       "hooks_enabled": True}

    _inventory(raw_client, key, [{"kind": "agent", "name": "claude-code", "version": "2.2.0"}])
    rows = _rows(db_factory)
    assert {(r.kind, r.name) for r in rows.values()} == {("agent", "claude-code")}
    assert rows[("dev@lap1", "claude-code")].version == "2.2.0"

    # A kind the report doesn't claim is left alone.
    _inventory(raw_client, key, [], kinds=("plugin",))
    assert ("dev@lap1", "claude-code") in _rows(db_factory)


def test_project_skills_scoped_to_the_reporting_project(client, raw_client, db_factory):
    key = _ingest_key(client)
    _inventory(raw_client, key, [{"kind": "skill", "name": "user-skill", "source": "user"},
                                 {"kind": "skill", "name": "a-skill", "source": "project:repo-a"}],
               project="repo-a", kinds=("skill",))
    # A session in another repo: repo-a's skill is kept, the user skill set is replaced.
    _inventory(raw_client, key, [{"kind": "skill", "name": "b-skill", "source": "project:repo-b"}],
               project="repo-b", kinds=("skill",))
    assert {n for _, n in _rows(db_factory, "skill")} == {"a-skill", "b-skill"}
    # Back in repo-a with its skill removed: gone.
    _inventory(raw_client, key, [], project="repo-a", kinds=("skill",))
    assert {n for _, n in _rows(db_factory, "skill")} == {"b-skill"}


def test_inventory_report_keeps_unchanged_scan_rows_alive(client, raw_client, db_factory):
    key = _ingest_key(client)
    _ide(raw_client, key, ["ms-python.python"])
    db = db_factory()
    old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=30)
    db.query(DeviceAsset).update({DeviceAsset.last_seen: old})
    db.commit()
    db.close()
    _inventory(raw_client, key, [])
    assert _rows(db_factory, "ide_extension")[("dev@lap1", "ms-python.python")].last_seen > old


def test_inventory_validation_bounds(client, raw_client):
    key = _ingest_key(client)
    h = {"X-Palivane-Token": key}
    too_wide = {f"k{i}": "v" for i in range(40)}
    r = raw_client.post("/api/scan/device-inventory", headers=h, json={
        "device": "d", "kinds": ["agent"], "items": [{"kind": "agent", "name": "x",
                                                      "extra": too_wide}]})
    assert r.status_code == 422
    r = raw_client.post("/api/scan/device-inventory", headers=h, json={
        "device": "d", "kinds": ["agent"], "items": [{"kind": "agent", "name": "x",
                                                      "extra": {"nested": {"a": 1}}}]})
    assert r.status_code == 422
    assert raw_client.post("/api/scan/device-inventory", json={"device": "d"}).status_code == 401


# --- API -----------------------------------------------------------------------------------

def _seed_fleet(client, raw_client):
    key = _ingest_key(client)
    _ide(raw_client, key, ["evil.ext", "ms-python.python"], device="a@1",
         versions={"evil.ext": "1.0.1"})
    _ide(raw_client, key, ["evil.ext"], device="b@2", versions={"evil.ext": "1.0.2"})
    _ide(raw_client, key, ["ms-python.python"], device="c@3")
    _mcp(raw_client, key, "~/.claude.json", {"evil-mcp": {"command": "npx", "args": ["evil-mcp"]}},
         device="a@1")
    _inventory(raw_client, key, [{"kind": "agent", "name": "claude-code", "version": "2.1.0"}],
               device="a@1")
    return key


def test_fleet_assets_rollup_filters_and_pagination(client, raw_client):
    _seed_fleet(client, raw_client)
    r = client.get("/api/fleet/assets")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["total"] == 4 and d["summary"]["devices"] == 3
    assert d["summary"]["kinds"] == {"ide_extension": 2, "mcp_server": 1, "agent": 1}
    top = d["assets"][0]
    assert top["device_count"] == 2 and top["kind"] == "ide_extension"
    evil = next(a for a in d["assets"] if a["name"] == "evil.ext")
    assert evil["versions"] == ["1.0.1", "1.0.2"] and evil["sources"] == ["evil"]

    d = client.get("/api/fleet/assets", params={"name": "EVIL"}).json()
    assert {(a["kind"], a["name"]) for a in d["assets"]} == {("ide_extension", "evil.ext"),
                                                            ("mcp_server", "evil-mcp")}
    d = client.get("/api/fleet/assets", params={"name": "evil", "kind": "mcp_server"}).json()
    assert [a["name"] for a in d["assets"]] == ["evil-mcp"]
    # LIKE metacharacters are literal.
    assert client.get("/api/fleet/assets", params={"name": "%"}).json()["total"] == 0
    d = client.get("/api/fleet/assets", params={"device": "c@3"}).json()
    assert [a["name"] for a in d["assets"]] == ["ms-python.python"]

    p1 = client.get("/api/fleet/assets", params={"limit": 3}).json()
    p2 = client.get("/api/fleet/assets", params={"limit": 3, "offset": 3}).json()
    assert p1["total"] == p2["total"] == 4
    assert len(p1["assets"]) == 3 and len(p2["assets"]) == 1
    names = {(a["kind"], a["name"]) for a in p1["assets"] + p2["assets"]}
    assert len(names) == 4


def test_fleet_asset_devices_lists_who_has_it(client, raw_client):
    _seed_fleet(client, raw_client)
    r = client.get("/api/fleet/assets/devices", params={"kind": "ide_extension",
                                                        "name": "evil.ext"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["total"] == 2
    assert {(x["device"], x["version"]) for x in d["devices"]} == {("a@1", "1.0.1"),
                                                                   ("b@2", "1.0.2")}
    one = client.get("/api/fleet/assets/devices", params={
        "kind": "ide_extension", "name": "evil.ext", "limit": 1, "offset": 1}).json()
    assert one["total"] == 2 and len(one["devices"]) == 1
    # Exact match, not substring.
    assert client.get("/api/fleet/assets/devices", params={
        "kind": "ide_extension", "name": "evil"}).json()["total"] == 0


def test_fleet_assets_tenant_isolation(client, raw_client, db_factory):
    _seed_fleet(client, raw_client)
    other = _second_tenant_client(db_factory)
    d = other.get("/api/fleet/assets").json()
    assert d["total"] == 0 and d["assets"] == [] and d["summary"]["devices"] == 0
    assert other.get("/api/fleet/assets/devices", params={
        "kind": "ide_extension", "name": "evil.ext"}).json()["total"] == 0

    # The other tenant's own device report lands in its own inventory only.
    r = other.post("/api/apikeys", json={"label": "f", "actor": "x@globex.com", "scope": "ingest"})
    gkey = r.json()["token"]
    _ide(raw_client, gkey, ["evil.ext"], device="a@1")
    assert other.get("/api/fleet/assets/devices", params={
        "kind": "ide_extension", "name": "evil.ext"}).json()["total"] == 1
    acme = client.get("/api/fleet/assets/devices", params={
        "kind": "ide_extension", "name": "evil.ext"}).json()
    assert acme["total"] == 2                                  # unchanged by globex's report
    # Same device id in two tenants: two rows, neither overwrote the other.
    rows = [r for r in _rows_all(db_factory) if r.name == "evil.ext" and r.device == "a@1"]
    assert len({r.tenant_id for r in rows}) == 2


def _rows_all(db_factory):
    db = db_factory()
    try:
        return db.query(DeviceAsset).all()
    finally:
        db.close()


def test_fleet_assets_admin_only(client, raw_client, db_factory):
    db = db_factory()
    users_cli.create_user(db, "acme", "member@acme.com", "password123", "analyst")
    db.close()
    tok = raw_client.post("/api/auth/login", json={"email": "member@acme.com",
                                                   "password": "password123"}).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    assert raw_client.get("/api/fleet/assets", headers=h).status_code == 403
    assert raw_client.get("/api/fleet/assets").status_code == 401
    key = _ingest_key(client)
    # A capture key cannot read the inventory either.
    assert raw_client.get("/api/fleet/assets",
                          headers={"X-Palivane-Token": key}).status_code in (401, 403)


# --- lifecycle -----------------------------------------------------------------------------

def test_prune_ages_out_device_assets(client, raw_client, db_factory, monkeypatch):
    from app.config import settings
    _seed_fleet(client, raw_client)
    db = db_factory()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    db.query(DeviceAsset).filter(DeviceAsset.device == "c@3").update(
        {DeviceAsset.last_seen: now - timedelta(days=200)})
    db.commit()
    monkeypatch.setattr(settings, "sensor_forget_days", 0)
    prune_dark_sensors(db)                                     # 0 = never forget
    assert db.query(DeviceAsset).filter(DeviceAsset.device == "c@3").count() == 1
    monkeypatch.setattr(settings, "sensor_forget_days", 90)
    assert prune_dark_sensors(db) >= 1
    assert db.query(DeviceAsset).filter(DeviceAsset.device == "c@3").count() == 0
    assert db.query(DeviceAsset).filter(DeviceAsset.device == "a@1").count() == 4
    db.close()


def test_device_assets_in_tenant_purge(client, raw_client, db_factory):
    assert ("device_assets", DeviceAsset) in TENANT_TABLES
    _seed_fleet(client, raw_client)
    db = db_factory()
    tenant = db.query(Tenant).filter(Tenant.slug == "acme").one()
    counts = purge_tenant(db, tenant)
    assert counts["device_assets"] == 6
    assert db.query(DeviceAsset).count() == 0
    db.close()
