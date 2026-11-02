"""MCP reputation dataset: the generator's scoring rules (tools/mcp_feed_build.py), its
truncation guard, and the loader's handling of the reserved `_meta` key. No network: the
generator takes an injected HTTP client, and every fixture here is synthetic."""
from __future__ import annotations

import importlib.util
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from app import mcp_feed
from app.config import BUNDLED_MCP_FEED, _mcp_feed_path, settings

_spec = importlib.util.spec_from_file_location(
    "mcp_feed_build", os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools",
                                   "mcp_feed_build.py"))
fb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fb)

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def _srv(name, packages=(), remotes=(), repo=None, status="active"):
    s = {"name": name, "version": "1.0.0"}
    if packages:
        s["packages"] = [{"registryType": e, "identifier": n, "version": "1.0.0"} for e, n in packages]
    if remotes:
        s["remotes"] = [{"type": "streamable-http", "url": u} for u in remotes]
    if repo:
        s["repository"] = {"url": repo, "source": "github"}
    return {"server": s, "official": {"status": status, "isLatest": True}}


def _info(age_days=400, last_days=10, repo="github.com/acme/acme-mcp", deprecated=False):
    return {"created": NOW - timedelta(days=age_days), "last_release": NOW - timedelta(days=last_days),
            "latest": "1.0.0", "deprecated": deprecated, "repo": repo}


def _score(entry, info=None, osv=None, famous=(), deny=()):
    return fb.score_server(entry, info or {}, osv or {}, NOW, set(famous), set(deny))


# --- scoring rules ---------------------------------------------------------------------

def test_trusted_needs_every_positive_check():
    e = _srv("com.acme/mcp", [("npm", "@acme/mcp")])
    s = _score(e, {("npm", "@acme/mcp"): _info()}, {("npm", "@acme/mcp"): {"mal": [], "vulns": []}})
    assert s["tier"] == "trusted"
    assert 80 <= s["score"] <= 95
    assert "domain-verified publisher acme.com" in s["reason"]
    assert s["keys"] == ["com.acme/mcp", "@acme/mcp"]


def test_github_namespace_trusted_only_when_it_owns_the_repo():
    e = _srv("io.github.alice/tool", [("pypi", "alice-tool")])
    own = _score(e, {("pypi", "alice-tool"): _info(repo="github.com/alice/tool")})
    assert own["tier"] == "trusted"
    other = _score(e, {("pypi", "alice-tool"): _info(repo="github.com/bob/tool")})
    assert other["tier"] == "caution"
    assert "does not own the source repo" in other["reason"]


@pytest.mark.parametrize("info,osv,expect", [
    (_info(age_days=5), None, "first published"),
    (_info(repo=None), None, "no source repository"),
    (_info(deprecated=True), None, "deprecated/yanked"),
    (_info(last_days=800), None, "no release since"),
    (_info(), {"mal": [], "vulns": ["GHSA-aaaa-bbbb-cccc"]}, "known advisories"),
])
def test_caution_signals(info, osv, expect):
    e = _srv("com.acme/mcp", [("npm", "@acme/mcp")])
    s = _score(e, {("npm", "@acme/mcp"): info}, {("npm", "@acme/mcp"): osv or {"mal": [], "vulns": []}})
    assert s["tier"] == "caution"
    assert expect in s["reason"]
    assert 10 <= s["score"] <= 65


def test_missing_package_and_unverified_types_are_caution():
    e = _srv("com.acme/mcp", [("npm", "@acme/gone")])
    assert "not found on npm" in _score(e, {("npm", "@acme/gone"): None})["reason"]
    oci = _srv("com.acme/img", [("oci", "docker.io/acme/img")])
    assert _score(oci)["tier"] == "caution"


def test_remote_only_is_never_trusted():
    on_domain = _score(_srv("com.acme/remote", remotes=["https://mcp.acme.com/mcp"]))
    assert on_domain["tier"] == "caution" and on_domain["score"] == 65
    off_domain = _score(_srv("com.acme/remote", remotes=["https://elsewhere.example/mcp"]))
    assert off_domain["tier"] == "caution" and off_domain["score"] < on_domain["score"]


def test_typosquat_of_well_known_name():
    famous = {"@modelcontextprotocol/server-memory", "firecrawl-mcp"}
    assert fb.typosquat_of("firecrawi-mcp", famous) == "firecrawl-mcp"
    # sharing only filler words ("mcp", "server") or a generic stem is not a squat
    assert fb.typosquat_of("ha-mcp-server", {"exa-mcp-server"}) is None
    assert fb.typosquat_of("@someone/server-memory", famous) is None
    assert fb.typosquat_of("@modelcontextprotoco1/server-memory", famous) is not None
    # same scope = only the scope owner can publish it, not a squat; exact match is the real thing
    assert fb.typosquat_of("@modelcontextprotocol/server-memroy", famous) is None
    assert fb.typosquat_of("@modelcontextprotocol/server-memory", famous) is None
    assert fb.typosquat_of("totally-different-name", famous) is None
    e = _srv("com.evil/mcp", [("npm", "@modelcontextprotoco1/server-memory")])
    s = _score(e, {("npm", "@modelcontextprotoco1/server-memory"): _info(repo="github.com/x/y")},
               famous=famous)
    assert s["tier"] == "caution" and "near-miss" in s["reason"]


def test_malicious_only_from_hard_evidence():
    e = _srv("com.acme/mcp", [("npm", "evil-mcp-pkg")])
    info = {("npm", "evil-mcp-pkg"): _info()}
    mal = _score(e, info, {("npm", "evil-mcp-pkg"): {"mal": ["MAL-2099-0001"], "vulns": []}})
    assert mal["tier"] == "malicious" and mal["score"] == 0 and "MAL-2099-0001" in mal["reason"]
    deny = _score(e, info, deny={"evil-mcp-pkg"})
    assert deny["tier"] == "malicious" and "denylist" in deny["reason"]
    # every soft signal at once is still only caution
    soft = _score(e, {("npm", "evil-mcp-pkg"): _info(age_days=1, repo=None, deprecated=True)},
                  {("npm", "evil-mcp-pkg"): {"mal": [], "vulns": ["GHSA-x", "GHSA-y"]}})
    assert soft["tier"] == "caution"


def test_past_only_malware_is_caution_not_malicious():
    e = _srv("com.acme/mcp", [("npm", "@acme/mcp")])
    s = _score(e, {("npm", "@acme/mcp"): _info()},
               {("npm", "@acme/mcp"): {"mal": [], "mal_past": ["MAL-2099-0003"], "vulns": []}})
    assert s["tier"] == "caution" and "earlier versions malicious" in s["reason"]


class _OsvHttp:
    """OSV batch stub: name-only queries see every advisory; versioned ones see only those
    affecting `bad_versions`."""

    def __init__(self, advisories, bad_versions):
        self.advisories, self.bad_versions = advisories, bad_versions

    def post_json(self, url, payload):
        res = []
        for q in payload["queries"]:
            ids = self.advisories.get(q["package"]["name"], [])
            if "version" in q and q["version"] not in self.bad_versions:
                ids = []
            res.append({"vulns": [{"id": i} for i in ids]} if ids else {})
        return {"results": res}


def test_osv_lookup_splits_current_and_past_malware():
    http = _OsvHttp({"hijacked": ["MAL-2099-0004"], "evil": ["MAL-2099-0005", "GHSA-q"],
                     "unversioned": ["MAL-2099-0006"]}, bad_versions={"6.6.6"})
    out = fb.osv_lookup(http, [("npm", "hijacked", "2.0.0"), ("npm", "evil", "6.6.6"),
                               ("npm", "unversioned", None), ("npm", "clean", "1.0.0")])
    assert out[("npm", "hijacked")] == {"mal": [], "mal_past": ["MAL-2099-0004"], "vulns": []}
    assert out[("npm", "evil")] == {"mal": ["MAL-2099-0005"], "mal_past": [], "vulns": ["GHSA-q"]}
    assert out[("npm", "unversioned")]["mal"] == ["MAL-2099-0006"]
    assert out[("npm", "clean")] == {"mal": [], "mal_past": [], "vulns": []}


def test_build_entries_collisions_and_curated_overlay():
    servers = [_srv("com.acme/a", [("npm", "shared-pkg")]),
               _srv("com.acme/b", [("npm", "shared-pkg"), ("npm", "bad-pkg")])]
    info = {("npm", "shared-pkg"): _info(), ("npm", "bad-pkg"): _info()}
    osv = {("npm", "shared-pkg"): {"mal": [], "vulns": []},
           ("npm", "bad-pkg"): {"mal": ["MAL-2099-0002"], "vulns": []}}
    curated = {"bad-pkg": {"tier": "trusted", "score": 90, "reason": "looked fine once"},
               "local-only": {"tier": "caution", "score": 40, "reason": "powerful by design"}}
    rows = fb.build_entries(servers, info, osv, NOW, curated, set())
    assert rows["shared-pkg"]["tier"] == "malicious"     # worst row wins a key collision
    assert rows["bad-pkg"]["tier"] == "malicious"        # curated never overrides hard evidence
    assert rows["local-only"]["reason"].startswith("curated: ")
    assert rows["com.acme/a"]["tier"] == "trusted"


def test_builtin_denylist_is_read_without_importing_the_app():
    assert fb.builtin_denylist()   # dep_guard's set, via ast


# --- output + loader -------------------------------------------------------------------

def test_render_is_deterministic_and_meta_first():
    rows = {"zeta": {"tier": "caution", "score": 50, "reason": "r"},
            "@scope/a": {"tier": "trusted", "score": 90, "reason": "r"}}
    a = fb.render({"scoring_version": "1"}, rows)
    b = fb.render({"scoring_version": "1"}, dict(reversed(list(rows.items()))))
    assert a == b
    assert a.splitlines()[1].startswith('"_meta":')
    assert list(json.loads(a)) == ["_meta", "@scope/a", "zeta"]


def _write(tmp_path, doc):
    p = tmp_path / "feed.json"
    p.write_text(json.dumps(doc))
    return str(p)


def test_loader_skips_reserved_keys_and_exposes_meta(tmp_path, monkeypatch):
    path = _write(tmp_path, {"_meta": {"tier": "malicious", "generated_at": "2026-10-01"},
                             "_comment": "free text",
                             "Evil-Pkg": {"tier": "malicious", "score": 3, "reason": "MAL-x"}})
    monkeypatch.setattr(settings, "mcp_reputation_feed", path)
    assert set(mcp_feed._load()) == {"evil-pkg"}
    assert mcp_feed.meta()["generated_at"] == "2026-10-01"
    assert mcp_feed.feed_signals(["_meta"]) == []
    [sig] = mcp_feed.feed_signals(["evil-pkg"])
    assert sig["title"] == "MCP server flagged malicious by reputation feed"


def test_loader_backward_compatible_without_meta(tmp_path, monkeypatch):
    path = _write(tmp_path, {"some-pkg": {"tier": "caution", "score": 40, "reason": "x"}})
    monkeypatch.setattr(settings, "mcp_reputation_feed", path)
    assert mcp_feed.meta() == {}
    assert mcp_feed.feed_signals(["some-pkg"])[0]["title"] == "MCP server rated low-reputation"


def test_feed_path_default_and_overrides(monkeypatch):
    for var in ("PALIVANE_MCP_REPUTATION_FEED", "MCP_REPUTATION_FEED"):
        monkeypatch.delenv(var, raising=False)
    assert _mcp_feed_path() == ""   # opt-in: off unless configured
    monkeypatch.setenv("MCP_REPUTATION_FEED", "bundled")
    assert _mcp_feed_path() == BUNDLED_MCP_FEED
    monkeypatch.setenv("MCP_REPUTATION_FEED", "/x/legacy.json")
    assert _mcp_feed_path() == "/x/legacy.json"
    monkeypatch.setenv("PALIVANE_MCP_REPUTATION_FEED", "/x/new.json")
    assert _mcp_feed_path() == "/x/new.json"
    for off in ("", "off", " OFF "):
        monkeypatch.setenv("PALIVANE_MCP_REPUTATION_FEED", off)
        assert _mcp_feed_path() == ""


@pytest.mark.skipif(not os.path.exists(BUNDLED_MCP_FEED),
                    reason="dataset not in git; fetched from GCS at deploy or built locally")
def test_bundled_dataset_loads(monkeypatch):
    monkeypatch.setattr(settings, "mcp_reputation_feed", BUNDLED_MCP_FEED)
    assert mcp_feed.loaded()
    meta = mcp_feed.meta()
    assert meta["scoring_version"] and meta["sources"]["registry_servers"] > 0
    assert set(meta["tiers"]) == {"trusted", "caution", "malicious"}


# --- main(): network handling ----------------------------------------------------------

class FakeHttp:
    """Routes the generator's calls to synthetic payloads. `fail_npm` makes npm lookups error."""

    def __init__(self, servers, fail_npm=False):
        self.servers, self.fail_npm = servers, fail_npm

    def get_json(self, url, headers=None):
        if url.startswith(fb.REGISTRY_URL):
            return {"servers": [{"server": s["server"], "_meta": {
                "io.modelcontextprotocol.registry/official": s["official"]}} for s in self.servers],
                "metadata": {"count": len(self.servers)}}
        if url.startswith(fb.NPM_URL):
            if self.fail_npm:
                raise fb.SourceError("boom")
            return {"time": {"created": "2024-01-01T00:00:00Z", "1.0.0": "2026-09-20T00:00:00Z"},
                    "dist-tags": {"latest": "1.0.0"},
                    "versions": {"1.0.0": {"repository": {"url": "git+https://github.com/acme/mcp.git"}}}}
        return None

    def post_json(self, url, payload):
        return {"results": [{} for _ in payload["queries"]]}


def _run(tmp_path, http, *extra):
    out = tmp_path / "out.json"
    curated = tmp_path / "curated.json"
    curated.write_text("{}")
    rc = fb.main(["--out", str(out), "--curated", str(curated), *extra], http=http, now=NOW)
    return rc, out


def test_main_writes_dataset_and_keeps_stamp_when_unchanged(tmp_path):
    servers = [_srv(f"com.acme/s{i}", [("npm", f"@acme/s{i}")]) for i in range(10)]
    rc, out = _run(tmp_path, FakeHttp(servers))
    assert rc == 0
    doc = json.loads(out.read_text())
    assert doc["_meta"]["sources"]["registry_servers"] == 10
    assert doc["@acme/s3"]["tier"] == "trusted"
    first = out.read_text()
    later = NOW + timedelta(hours=1)
    assert fb.main(["--out", str(out), "--curated", str(tmp_path / "curated.json")],
                   http=FakeHttp(servers), now=later) == 0
    assert out.read_text() == first   # same rows -> same bytes, no weekly churn


def test_main_refuses_a_truncated_registry(tmp_path):
    servers = [_srv(f"com.acme/s{i}", [("npm", f"@acme/s{i}")]) for i in range(10)]
    rc, out = _run(tmp_path, FakeHttp(servers))
    before = out.read_text()
    rc, _ = _run(tmp_path, FakeHttp(servers[:3]))
    assert rc == 1 and out.read_text() == before
    rc, _ = _run(tmp_path, FakeHttp(servers[:3]), "--allow-shrink")
    assert rc == 0


def test_main_fails_on_lookup_errors_instead_of_marking_not_found(tmp_path):
    servers = [_srv(f"com.acme/s{i}", [("npm", f"@acme/s{i}")]) for i in range(10)]
    rc, out = _run(tmp_path, FakeHttp(servers, fail_npm=True))
    assert rc == 1 and not out.exists()
