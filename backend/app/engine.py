"""The detection engine: runs the relevant detectors over an item and scores them.

A detector declares which input `surfaces` it applies to (llm_io = prompts on the
org's own LLMs, ai_usage = content bound for external AI tools); the engine routes
each submission only to the detectors that match its surface. Scoring and the
findings store are shared — adding detection means writing a detector and registering
it here, not forking the backbone.
"""

from __future__ import annotations

import logging
import traceback

from . import metrics
from .detectors import (
    AgentRulesDetector,
    AgentSafetyDetector,
    AnalysisInput,
    BrowserExtGuardDetector,
    CIGuardDetector,
    DepGuardDetector,
    DevicePostureDetector,
    OversharingDetector,
    ExtGuardDetector,
    LLMJudgeDetector,
    MCPGuardDetector,
    MLClassifierDetector,
    PromptThreatDetector,
    SecretsAtRestDetector,
    ShadowAIDetector,
    Surface,
)
from .detectors.base import Signal
from .scoring import Verdict, score, unscanned_marker

_log = logging.getLogger("palivane.engine")


def _unscanned(name: str) -> Signal:
    """The marker a crashed detector leaves in the verdict: weight 0, so it never moves the
    score, but it rides the signal list everywhere a verdict goes (the API payload, the stored
    finding, alerts, SIEM), so "this check did not run" cannot read as "this check found
    nothing". Names the detector only; nothing from the content."""
    return unscanned_marker(f"detector={name}", "A check did not complete",
                            (f"The {name} check failed on this item, so it was only partly "
                             "scanned. The verdict reflects the checks that did run."),
                            detector="engine")


class Engine:
    def __init__(self) -> None:
        self.prompt_threats = PromptThreatDetector()
        self.shadow_ai = ShadowAIDetector()
        self.mcp_guard = MCPGuardDetector()
        self.ml_classifier = MLClassifierDetector()
        self.dep_guard = DepGuardDetector()
        self.ext_guard = ExtGuardDetector()
        self.browser_ext_guard = BrowserExtGuardDetector()
        self.secrets_at_rest = SecretsAtRestDetector()
        self.agent_safety = AgentSafetyDetector()
        self.agent_rules = AgentRulesDetector()
        self.oversharing = OversharingDetector()
        self.ci_guard = CIGuardDetector()
        self.device_posture = DevicePostureDetector()
        self.judge = LLMJudgeDetector()
        self.detectors = [self.prompt_threats, self.shadow_ai, self.ml_classifier, self.mcp_guard,
                          self.dep_guard, self.ext_guard, self.browser_ext_guard,
                          self.secrets_at_rest,
                          self.agent_safety, self.agent_rules, self.oversharing,
                          self.ci_guard, self.device_posture, self.judge]

    @property
    def judge_enabled(self) -> bool:
        return self.judge.enabled

    def _applies(self, detector, surface: Surface) -> bool:
        surfaces = getattr(detector, "surfaces", set())
        return not surfaces or surface in surfaces

    @staticmethod
    def _without_attachments(item: AnalysisInput) -> AnalysisInput:
        """`item` with base64 attachments replaced by a placeholder, for the detector chain.

        An attachment body is not prose, and every content detector was rediscovering that
        separately: one pasted screenshot produced 21 high-severity "possible secret" findings
        from JPEG quantization tables, plus a confidential-material hit on the letters `NDA`
        between two digits and p(code)=1.00 from the source-code classifier. Stripping once,
        here, fixes the class instead of the symptom.

        The Tier-1 secret pass runs over the ORIGINAL bytes and is handed down through the
        item's cache, so this cannot become an evasion path: a real `ghp_…` wrapped in
        something shaped like a JPEG is still found. Only the generic, shape-based detectors
        lose sight of the blob — which is the entire point, because on a blob they are wrong.
        """
        from dataclasses import replace
        from .detectors.patterns import strip_media_blobs
        meta = item.metadata or {}
        args_text = meta.get("args_text") or ""
        content = strip_media_blobs(item.content)
        stripped_args = strip_media_blobs(args_text) if args_text else args_text
        if content == item.content and stripped_args == args_text:
            return item
        labels = item.secret_labels()      # over the real bytes, BEFORE they are dropped
        scanned = replace(item, content=content,
                          metadata=({**meta, "args_text": stripped_args}
                                    if stripped_args != args_text else meta))
        scanned._secret_labels = labels
        return scanned

    def analyze(self, item: AnalysisInput, include_judge: bool = True,
                judge_backends=None) -> Verdict:
        """`judge_backends` overrides the judge's provider list for this analysis (BYOK:
        the tenant's own key runs even when the global judge is unconfigured)."""
        item = self._without_attachments(item)
        signals = []
        for detector in self.detectors:
            if detector is self.judge and not include_judge:
                continue  # tenant opted out of the LLM judge (data-residency)
            if not self._applies(detector, item.surface):
                continue
            try:
                if detector is self.judge:
                    signals.extend(detector.analyze(item, backends=judge_backends))
                else:
                    signals.extend(detector.analyze(item))
            except Exception as exc:
                # A misbehaving detector must never sink the whole analysis, and must never
                # pass for a clean result either. Logged by type and code location only: the
                # exception's message can quote the content, which may be the secret itself.
                name = getattr(detector, "name", type(detector).__name__)
                frame = traceback.extract_tb(exc.__traceback__)[-1]
                _log.error("detector %s raised %s at %s:%s; item only partly scanned",
                           name, type(exc).__name__, frame.filename, frame.lineno)
                metrics.DETECTOR_ERRORS.labels(name).inc()
                signals.append(_unscanned(name))
        return score(signals)


engine = Engine()
