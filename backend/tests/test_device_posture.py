"""Device-posture detector: capture-plane collisions, breaker fail-open, coverage gaps."""

from __future__ import annotations

import json

from app.detectors import AnalysisInput, Surface
from app.detectors.device_posture import DevicePostureDetector

det = DevicePostureDetector()


def _item(report: dict) -> AnalysisInput:
    return AnalysisInput(content=json.dumps(report), channel="device-posture",
                         surface=Surface.DEVICE, metadata={"kind": "device_posture"})


def _healthy() -> dict:
    return {"proxy": {"port": 8081, "listening": True, "listener": "mitmdump",
                      "env_proxy": "http://127.0.0.1:8081", "env_points_local": True},
            "breaker": {"cooldown_active": False, "deauth_active": False},
            "gaps": {"wsl": False, "docker_present": False, "in_container": False}}


def _checks(report: dict) -> set[str]:
    return {s.effective_check for s in det.analyze(_item(report))}


def test_healthy_device_is_clean():
    assert _checks(_healthy()) == set()


def test_proxy_dead_but_routed():
    r = _healthy()
    r["proxy"].update(listening=False, listener="")
    assert "proxy_dead" in _checks(r)


def test_proxy_down_but_not_routed_is_clean():
    r = _healthy()
    r["proxy"].update(listening=False, listener="", env_proxy="", env_points_local=False)
    assert _checks(r) == set()


def test_port_conflict_flags_foreign_listener():
    r = _healthy()
    r["proxy"]["listener"] = "node"
    assert "proxy_port_conflict" in _checks(r)


def test_own_listener_names_pass():
    for name in ("mitmdump", "mitmproxy", "palivane-proxy"):
        r = _healthy()
        r["proxy"]["listener"] = name
        assert _checks(r) == set(), name


def test_breaker_cooldown_reports_fail_open():
    r = _healthy()
    r["breaker"]["cooldown_active"] = True
    assert "scan_fail_open" in _checks(r)


def test_breaker_deauth_outranks_cooldown():
    r = _healthy()
    r["breaker"].update(cooldown_active=True, deauth_active=True)
    checks = _checks(r)
    assert "capture_key_revoked" in checks and "scan_fail_open" not in checks


def test_coverage_gap_wsl_and_docker():
    r = _healthy()
    r["gaps"].update(wsl=True, docker_present=True)
    sigs = det.analyze(_item(r))
    gap = [s for s in sigs if s.effective_check == "coverage_gap"]
    assert len(gap) == 1 and "WSL" in gap[0].title and "Docker" in gap[0].title
    assert gap[0].contribution < 0.2   # informational — never blocks on its own


def test_inside_container_not_flagged_as_gap():
    r = _healthy()
    r["gaps"].update(docker_present=True, in_container=True)
    assert _checks(r) == set()


def test_wrong_kind_and_garbage_are_ignored():
    item = AnalysisInput(content="not json", channel="device-posture",
                         surface=Surface.DEVICE, metadata={"kind": "device_posture"})
    assert det.analyze(item) == []
    item2 = AnalysisInput(content=json.dumps(_healthy()), surface=Surface.DEVICE,
                          metadata={"kind": "something_else"})
    assert det.analyze(item2) == []


def test_local_llm_runtime_surfaces_unsanctioned_ai():
    """Ollama/LM Studio are AI usage with zero network tell — presence is the finding."""
    from app.detectors.base import Category
    r = {"proxy": {"port": 8081, "listening": True, "listener": "mitmdump",
                   "env_proxy": "", "env_points_local": False},
         "breaker": {}, "gaps": {},
         "local_llms": [{"name": "ollama", "listening": True},
                        {"name": "lm studio", "listening": False}]}
    sigs = [s for s in det.analyze(_item(r)) if s.category == Category.UNSANCTIONED_AI]
    assert len(sigs) == 2
    serving = next(s for s in sigs if s.evidence == "ollama")
    idle = next(s for s in sigs if s.evidence == "lm studio")
    assert "currently serving" in serving.detail and serving.weight > idle.weight
    assert all(s.check == "local_llm" for s in sigs)
