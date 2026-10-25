"""Browser-extension inventory: classification + /api/scan/browser-extensions + the
Discovery rollup at /api/discovery/browser-extensions."""

from __future__ import annotations

from app.detectors import ext_guard
from app.detectors.base import AnalysisInput, Category, Surface

CLAUDE = "fcoeoabgfenejglbffodgkkbkcdhcgfn"
MONICA = "ofpnmcalabcbjgholdjcjblkibolbppb"
UBLOCK = "ddkjiahejlhfcafbddmgiahcphecmpfh"   # not an AI extension


def _scan(exts, sanctioned=""):
    return ext_guard.BrowserExtGuardDetector().analyze(
        AnalysisInput(content="", subject="browser-extensions", surface=Surface.BROWSER_EXT,
                      metadata={"extensions": exts, "sanctioned": sanctioned}))


def _ext(eid, name="x", enabled=True, **kw):
    return {"id": eid, "name": name, "version": "1.0", "enabled": enabled,
            "install_type": kw.get("install_type", "normal"),
            "host_access": kw.get("host_access", "all sites")}


def test_every_listed_ai_extension_classifies():
    for eid, product in {
        "ofpnmcalabcbjgholdjcjblkibolbppb": "Monica",
        "difoiogjjojoaoomphldepapgpbgkhkb": "Sider",
        "camppjleccjaphfdbohjdohecfnoikec": "Merlin",
        "eanggfilgoajaocelnaflolkadkeghjp": "HARPA AI",
        "mhnlakgilnojmhinhkckjpncpbhabphi": "MaxAI",
        "fcoeoabgfenejglbffodgkkbkcdhcgfn": "Claude in Chrome",
        "ejcfepkfckglbgocfkanmcdngdijcgld": "ChatGPT search",
    }.items():
        assert ext_guard.classify_browser_extension(eid) == product
        assert ext_guard.classify_browser_extension(eid.upper()) == product
    assert ext_guard.classify_browser_extension(UBLOCK) == ""
    assert ext_guard.classify_browser_extension("") == ""


def test_ai_extension_flagged_and_others_silent():
    sigs = _scan([_ext(CLAUDE, "Claude"), _ext(UBLOCK, "uBlock Origin")])
    assert len(sigs) == 1
    assert sigs[0].category == Category.UNSANCTIONED_AI
    assert sigs[0].evidence == CLAUDE and "Claude in Chrome" in sigs[0].detail


def test_disabled_ai_extension_is_inventory_not_a_finding():
    assert _scan([_ext(MONICA, enabled=False)]) == []


def test_sanctioned_by_id_or_product_name_is_silent():
    assert _scan([_ext(CLAUDE)], sanctioned=f"chatgpt.com, {CLAUDE}") == []
    assert _scan([_ext(CLAUDE)], sanctioned="Claude in Chrome") == []
    # Sanctioning one leaves the others flagged.
    sigs = _scan([_ext(CLAUDE), _ext(MONICA)], sanctioned=CLAUDE)
    assert [s.evidence for s in sigs] == [MONICA]


def _key(client):
    return client.post("/api/apikeys", json={"label": "ext", "actor": "dana@acme.com"}).json()["token"]


def _report(raw_client, key, exts, device="chrome-1", record=True):
    return raw_client.post("/api/scan/browser-extensions", headers={"X-Palivane-Token": key},
                           json={"extensions": exts, "device": device, "record": record})


def test_endpoint_requires_a_capture_token(raw_client):
    assert _report(raw_client, "nope", [_ext(CLAUDE)]).status_code == 401


def test_endpoint_flags_ai_and_records_inventory(client, raw_client):
    key = _key(client)
    r = _report(raw_client, key, [_ext(CLAUDE, "Claude"), _ext(UBLOCK, "uBlock Origin")])
    assert r.status_code == 200
    body = r.json()
    assert [e["evidence"] for e in body["extensions"]] == [CLAUDE]

    inv = client.get("/api/discovery/browser-extensions").json()
    assert inv["summary"]["devices"] == 1
    assert inv["summary"]["extensions"] == 2
    assert inv["summary"]["ai_extensions"] == 1 and inv["summary"]["unsanctioned_ai"] == 1
    first = inv["extensions"][0]                       # unsanctioned AI sorts first
    assert first["id"] == CLAUDE and first["ai_product"] == "Claude in Chrome"
    assert first["sanctioned"] is False and first["all_sites"] is True
    assert first["users"] == ["dana@acme.com"]
    other = inv["extensions"][1]
    assert other["id"] == UBLOCK and other["ai_product"] == "" and other["sanctioned"] is None

    # The finding landed on the browser_ext surface, attributed to the key's actor.
    rows = client.get("/api/findings").json()["findings"]
    hits = [f for f in rows if f.get("surface") == "browser_ext"]
    assert len(hits) == 1 and hits[0]["sender"] == "dana@acme.com"

    # The daily re-report of the same list folds into that finding, not a new one.
    _report(raw_client, key, [_ext(CLAUDE, "Claude"), _ext(UBLOCK, "uBlock Origin")])
    rows = client.get("/api/findings").json()["findings"]
    assert len([f for f in rows if f.get("surface") == "browser_ext"]) == 1


def test_report_replaces_the_devices_inventory(client, raw_client):
    key = _key(client)
    _report(raw_client, key, [_ext(CLAUDE), _ext(MONICA)], device="chrome-a")
    _report(raw_client, key, [_ext(MONICA)], device="chrome-b")
    # chrome-a uninstalls Claude: it leaves the inventory; chrome-b is untouched.
    _report(raw_client, key, [_ext(MONICA)], device="chrome-a")
    inv = client.get("/api/discovery/browser-extensions").json()
    by_id = {x["id"]: x for x in inv["extensions"]}
    assert CLAUDE not in by_id
    assert by_id[MONICA]["device_count"] == 2


def test_sanctioning_on_discovery_silences_and_marks(client, raw_client):
    client.patch("/api/tenant", json={"sanctioned_ai_tools": CLAUDE})
    key = _key(client)
    body = _report(raw_client, key, [_ext(CLAUDE)]).json()
    assert body["extensions"] == [] and body["action"] == "allow"
    inv = client.get("/api/discovery/browser-extensions").json()
    assert inv["extensions"][0]["sanctioned"] is True
    assert inv["summary"]["unsanctioned_ai"] == 0


def test_sanctioned_extension_id_is_not_offered_as_an_approved_tool():
    # The block modal lists the sanctioned entries as places to go instead; an id isn't one.
    import app.main as main
    out = main._sanctioned_list(f"claude.ai, {CLAUDE}, Copilot")
    assert [x["label"] for x in out] == ["claude.ai", "Copilot"]


def test_without_record_nothing_is_stored(client, raw_client):
    key = _key(client)
    _report(raw_client, key, [_ext(CLAUDE)], record=False)
    assert client.get("/api/discovery/browser-extensions").json()["extensions"] == []


def test_inventory_is_admin_only(raw_client):
    assert raw_client.get("/api/discovery/browser-extensions").status_code == 401
