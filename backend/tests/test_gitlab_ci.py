"""GitLab CI posture: flavor detection, remote/mutable includes, MR-privilege reach,
runner tags on MR jobs, AI agents + autonomy + secrets-to-agent in scripts, and the
scan endpoint's per-file channel naming."""

from __future__ import annotations

from app.detectors import AnalysisInput, CIGuardDetector, Surface

det = CIGuardDetector()


def _analyze(yaml_text: str):
    return det.analyze(AnalysisInput(content=yaml_text, surface=Surface.CI,
                                     metadata={"kind": "ci_workflow"}))


def _checks(signals) -> set[str]:
    return {s.effective_check for s in signals}


SAFE_GL = """
stages: [test]
test:
  stage: test
  image: python:3.12@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  script:
    - make test
"""


def test_safe_gitlab_pipeline_is_clean():
    assert _analyze(SAFE_GL) == []


def test_github_workflows_still_take_the_github_path():
    # jobs+on present → GitHub rules; a GitLab-only rule must not fire on it.
    wf = """
on: [push]
jobs:
  t:
    runs-on: ubuntu-latest
    steps: [{run: make test}]
"""
    assert _checks(_analyze(wf)) == set()


def test_remote_include_flagged_and_escalates_with_credentials():
    plain = """
include:
  - remote: https://example.com/shared/ci.yml
test:
  script: [make test]
"""
    sigs = _analyze(plain)
    assert _checks(sigs) == {"ci_unpinned_action"}
    base = next(s for s in sigs if s.title == "Remote CI include")

    privileged = plain + """
deploy:
  script:
    - deploy --key $AWS_SECRET_ACCESS_KEY
"""
    sigs2 = _analyze(privileged)
    esc = next(s for s in sigs2 if s.title == "Remote CI include")
    assert esc.weight > base.weight            # credentials in reach → heavier


def test_project_include_floating_ref_flagged_sha_not():
    floating = """
include:
  - project: platform/ci-templates
    ref: main
    file: /base.yml
test: {script: [make test]}
"""
    assert "ci_unpinned_action" in _checks(_analyze(floating))
    pinned = floating.replace("ref: main",
                              "ref: 2f3a4b5c6d7e8f901234567890abcdef12345678")
    assert "ci_unpinned_action" not in _checks(_analyze(pinned))


def test_mr_job_with_privileged_variables_flagged():
    gl = """
deploy:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - ./deploy.sh $AWS_SECRET_ACCESS_KEY $PROD_DB_PASSWORD
"""
    sigs = _analyze(gl)
    s = next(x for x in sigs if x.title == "Privileged variables on MR-triggered job")
    assert "AWS_SECRET_ACCESS_KEY" in s.evidence
    assert s.effective_check == "ci_unsafe_trigger"


def test_mr_job_without_credentials_not_flagged_for_privilege():
    gl = """
lint:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script: [make lint]
"""
    assert not any(s.title == "Privileged variables on MR-triggered job"
                   for s in _analyze(gl))


def test_runner_tags_on_mr_job_flagged():
    gl = """
build:
  tags: [macos-fleet]
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script: [make build]
"""
    sigs = _analyze(gl)
    s = next(x for x in sigs if x.title == "Specific runner tags on MR-triggered job")
    assert "macos-fleet" in s.evidence


def test_ai_agent_and_secrets_and_autonomy_in_scripts():
    gl = """
review:
  script:
    - npx @anthropic-ai/claude-code -p "review this MR" --dangerously-skip-permissions
  variables:
    DEPLOY_TOKEN: $DEPLOY_TOKEN
"""
    checks = _checks(_analyze(gl))
    assert {"ci_ai_agent", "ci_secrets_to_ai", "unsafe_autonomy"} <= checks


def test_model_keys_are_expected_not_flagged():
    gl = """
review:
  script:
    - claude -p "summarize"
  variables:
    ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
"""
    checks = _checks(_analyze(gl))
    assert "ci_ai_agent" in checks and "ci_secrets_to_ai" not in checks


def test_scan_endpoint_names_gitlab_channel(client, raw_client=None):
    r = client.post("/api/apikeys", json={"label": "ci", "actor": "ci@acme.com"})
    key = r.json()["token"]
    gl = """
review:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - claude -p "review" --dangerously-skip-permissions $AWS_SECRET_ACCESS_KEY
"""
    r = client.post("/api/scan/ci", headers={"X-Palivane-Token": key}, json={
        "repo": "acme/api", "workflows": [{"path": ".gitlab-ci.yml", "content": gl}]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["workflows"], body
    rows = client.get("/api/findings?surface=ci").json()["findings"]
    assert rows and rows[0]["channel"] == "gitlab-ci"
