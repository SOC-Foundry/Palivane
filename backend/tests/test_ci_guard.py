"""CI-runner scanning: the ci_guard detector's workflow rules and POST /api/scan/ci."""

from __future__ import annotations

from app.detectors import AnalysisInput, CIGuardDetector, Surface
from app.models import DiscoveredUsage, Finding, SensorHeartbeat

det = CIGuardDetector()


def _analyze(yaml_text: str):
    return det.analyze(AnalysisInput(content=yaml_text, surface=Surface.CI,
                                     metadata={"kind": "ci_workflow"}))


def _checks(signals) -> set[str]:
    return {s.effective_check for s in signals}


SAFE_WF = """
name: ci
on: [push, pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: thirdparty/tool@2f3a4b5c6d7e8f901234567890abcdef12345678
      - run: make test
"""


def test_safe_workflow_is_clean():
    assert _analyze(SAFE_WF) == []


def test_pwn_request_pattern_and_bare_privileged_trigger():
    pwn = """
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
    sigs = _analyze(pwn)
    assert "ci_unsafe_trigger" in _checks(sigs)
    assert any(s.weight >= 0.85 for s in sigs if s.effective_check == "ci_unsafe_trigger")
    # trigger without a PR-head checkout: flagged, but softer
    bare = "on: pull_request_target\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    soft = _analyze(bare)
    assert "ci_unsafe_trigger" in _checks(soft)
    assert all(s.weight < 0.85 for s in soft)


def test_unpinned_third_party_action_flagged_sha_and_first_party_not():
    wf = """
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tj-actions/changed-files@v44
      - uses: pinned/action@2f3a4b5c6d7e8f901234567890abcdef12345678
      - uses: docker://alpine:3.20
"""
    sigs = [s for s in _analyze(wf) if s.effective_check == "ci_unpinned_action"]
    # one aggregated signal per workflow, not one per occurrence
    assert len(sigs) == 1
    ev = sigs[0].evidence
    assert "tj-actions/changed-files@v44" in ev and "docker://alpine:3.20" in ev
    assert "actions/checkout" not in ev and "pinned/action" not in ev


def test_unpinned_actions_are_deduped_and_capped_below_critical():
    """Many unpinned actions must not saturate into `critical` — that tier is for
    confirmed exposure. Repeats of the same action collapse to one mention."""
    from app.scoring import score
    many = "\n".join(f"      - uses: vendor{i}/act@v1" for i in range(8))
    wf = f"on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n{many}\n"
    sigs = _analyze(wf)
    assert len([s for s in sigs if s.effective_check == "ci_unpinned_action"]) == 1
    assert score(sigs).severity in ("suspicious", "high")

    dupes = "\n".join(["      - uses: vendor/act@v1"] * 4)
    wf2 = f"on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n{dupes}\n"
    ev = [s for s in _analyze(wf2) if s.effective_check == "ci_unpinned_action"][0].evidence
    assert ev == "vendor/act@v1"


def test_unpinned_escalates_only_when_the_workflow_holds_credentials():
    from app.scoring import score
    plain = """
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: vendor/act@v1
      - run: make lint
"""
    with_secrets = """
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: vendor/act@v1
        env:
          KEY: ${{ secrets.DEPLOY_KEY }}
"""
    oidc = """
on: push
permissions:
  id-token: write
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: vendor/act@v1
"""
    assert score(_analyze(plain)).severity == "suspicious"
    for privileged in (with_secrets, oidc):
        sev = score(_analyze(privileged)).severity
        assert sev == "high", sev


def test_write_all_permissions_workflow_and_job_level():
    wf = """
on: push
permissions: write-all
jobs:
  b:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: echo hi
"""
    sigs = [s for s in _analyze(wf) if s.effective_check == "ci_excessive_permissions"]
    assert len(sigs) == 2


def test_secrets_inherit_to_third_party_only():
    wf = """
on: push
jobs:
  third:
    uses: someorg/workflows/.github/workflows/deploy.yml@main
    secrets: inherit
  local:
    uses: ./.github/workflows/local.yml
    secrets: inherit
  firstparty:
    uses: actions/reusable/.github/workflows/x.yml@v1
    secrets: inherit
"""
    sigs = [s for s in _analyze(wf) if s.effective_check == "ci_secrets_inherit"]
    assert len(sigs) == 1 and "someorg" in sigs[0].evidence


def test_self_hosted_runner_flagged_only_on_pr_triggers():
    pr = """
on: [pull_request]
jobs:
  b:
    runs-on: [self-hosted, linux]
    steps: [{run: make}]
"""
    assert "ci_self_hosted_runner" in _checks(_analyze(pr))
    push_only = pr.replace("[pull_request]", "[push]")
    assert "ci_self_hosted_runner" not in _checks(_analyze(push_only))


def test_ai_agent_detection_action_and_cli():
    wf = """
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
      - run: |
          npx aider --help
"""
    sigs = [s for s in _analyze(wf) if s.effective_check == "ci_ai_agent"]
    assert {s.evidence for s in sigs} == {"Claude Code", "aider"}
    # a model API key handed to the AI step is expected — NOT a secrets-to-ai finding
    assert "ci_secrets_to_ai" not in _checks(_analyze(wf))


def test_non_model_secrets_handed_to_ai_step():
    wf = """
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - name: agent deploy
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: claude -p "deploy the app"
"""
    sigs = [s for s in _analyze(wf) if s.effective_check == "ci_secrets_to_ai"]
    assert len(sigs) == 1 and "AWS_SECRET_ACCESS_KEY" in sigs[0].evidence
    assert "ANTHROPIC_API_KEY" not in sigs[0].evidence


def test_autonomy_flags_in_ci():
    wf = """
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: claude -p "fix the tests" --dangerously-skip-permissions
"""
    assert "unsafe_autonomy" in _checks(_analyze(wf))


def test_unparseable_yaml_degrades_to_text_checks():
    broken = "on: pull_request_target\n\t[bad yaml\nref: ${{ github.event.pull_request.head.sha }}"
    sigs = _analyze(broken)
    assert "ci_unsafe_trigger" in _checks(sigs)


def test_non_ci_metadata_is_ignored():
    assert det.analyze(AnalysisInput(content=SAFE_WF, surface=Surface.CI)) == []


# --- endpoint ---------------------------------------------------------------------

PWN_WF = """
on: pull_request_target
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
      - uses: anthropics/claude-code-action@v1
"""


def _make_key(client) -> str:
    r = client.post("/api/apikeys", json={"label": "ci"})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def test_scan_ci_endpoint_records_and_feeds_discovery(client, raw_client, db_factory):
    key = _make_key(client)
    r = raw_client.post("/api/scan/ci", headers={"X-Palivane-Token": key}, json={
        "repo": "acme/api", "ref": "abc123",
        "workflows": [{"path": ".github/workflows/pwn.yml", "content": PWN_WF},
                      {"path": ".github/workflows/ok.yml", "content": SAFE_WF}],
        "record": True,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scanned"] == 2 and body["repo"] == "acme/api"
    assert body["action"] in ("warn", "block")
    flagged = {w["workflow"] for w in body["workflows"]}
    assert ".github/workflows/pwn.yml" in flagged and ".github/workflows/ok.yml" not in flagged
    assert any(w["remediation"] for w in body["workflows"])

    db = db_factory()
    f = db.query(Finding).filter(Finding.channel == "github-actions").first()
    assert f is not None and f.surface == "ci" and f.sender == "acme/api"
    # the Claude Code step joined the shadow-AI inventory, attributed to the repo
    d = db.query(DiscoveredUsage).filter(DiscoveredUsage.tool == "Claude Code").first()
    assert d is not None and d.actor == "acme/api"
    hb = db.query(SensorHeartbeat).filter(SensorHeartbeat.plane == "ci").first()
    assert hb is not None
    db.close()


def test_scan_ci_requires_token(raw_client):
    r = raw_client.post("/api/scan/ci", json={"workflows": []})
    assert r.status_code == 401


UNPINNED_PRIVILEGED = """
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: vendor/act@v1
        env:
          KEY: ${{ secrets.DEPLOY_KEY }}
"""


def _scan(raw_client, key, content=UNPINNED_PRIVILEGED):
    r = raw_client.post("/api/scan/ci", headers={"X-Palivane-Token": key}, json={
        "repo": "acme/api", "workflows": [{"path": "wf.yml", "content": content}],
        "record": False})
    assert r.status_code == 200, r.text
    return r.json()


def test_posture_findings_warn_by_default_and_org_can_tighten(client, raw_client):
    """Default ci_block_severity=critical: a `high` posture finding warns (so a PR gate
    doesn't fail on pre-existing debt), but the org can opt into the strict ratchet."""
    key = _make_key(client)
    body = _scan(raw_client, key)
    assert body["block_severity"] == "critical"
    assert body["workflows"][0]["severity"] == "high"
    assert body["action"] == "warn" and body["workflows"][0]["action"] == "warn"

    assert client.patch("/api/tenant",
                        json={"ci_block_severity": "high"}).status_code == 200
    strict = _scan(raw_client, key)
    assert strict["block_severity"] == "high"
    assert strict["action"] == "block" and strict["workflows"][0]["action"] == "block"


def test_confirmed_exposure_still_blocks_at_the_default_threshold(client, raw_client):
    # pwn-request is the confirmed-exposure class — it must fail a build out of the box.
    key = _make_key(client)
    body = _scan(raw_client, key, PWN_WF)
    assert body["block_severity"] == "critical"
    assert body["action"] == "block"


def test_ci_block_severity_is_validated(client):
    assert client.patch("/api/tenant",
                        json={"ci_block_severity": "nonsense"}).status_code == 400
    # "" clears the override -> inherit the global default
    assert client.patch("/api/tenant", json={"ci_block_severity": "high"}).status_code == 200
    assert client.patch("/api/tenant", json={"ci_block_severity": ""}).status_code == 200
    assert client.get("/api/auth/me").json()["tenant"]["ci_block_severity"] == ""


def test_scan_ci_policy_toggle_suppresses_check(client, raw_client):
    # disabling the ci_unpinned_action check drops those signals for the tenant
    assert client.patch("/api/tenant",
                        json={"disabled_checks": ["ci_unpinned_action"]}).status_code == 200
    key = _make_key(client)
    wf = "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: tj-actions/changed-files@v44\n"
    r = raw_client.post("/api/scan/ci", headers={"X-Palivane-Token": key}, json={
        "repo": "acme/api", "workflows": [{"path": "wf.yml", "content": wf}], "record": False})
    assert r.status_code == 200
    checks = {s["check"] for w in r.json()["workflows"] for s in w["signals"]}
    assert "ci_unpinned_action" not in checks
