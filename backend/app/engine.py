"""The detection engine: runs the relevant detectors over an item and scores them.

A detector declares which input `surfaces` it applies to (llm_io = prompts on the
org's own LLMs, ai_usage = content bound for external AI tools); the engine routes
each submission only to the detectors that match its surface. Scoring and the
findings store are shared — adding detection means writing a detector and registering
it here, not forking the backbone.
"""

from __future__ import annotations

from .detectors import (
    AgentRulesDetector,
    AgentSafetyDetector,
    AnalysisInput,
    CIGuardDetector,
    DepGuardDetector,
    DevicePostureDetector,
    OversharingDetector,
    ExtGuardDetector,
    LLMJudgeDetector,
    MCPGuardDetector,
    PromptThreatDetector,
    SecretsAtRestDetector,
    ShadowAIDetector,
    Surface,
)
from .scoring import Verdict, score


class Engine:
    def __init__(self) -> None:
        self.prompt_threats = PromptThreatDetector()
        self.shadow_ai = ShadowAIDetector()
        self.mcp_guard = MCPGuardDetector()
        self.dep_guard = DepGuardDetector()
        self.ext_guard = ExtGuardDetector()
        self.secrets_at_rest = SecretsAtRestDetector()
        self.agent_safety = AgentSafetyDetector()
        self.agent_rules = AgentRulesDetector()
        self.oversharing = OversharingDetector()
        self.ci_guard = CIGuardDetector()
        self.device_posture = DevicePostureDetector()
        self.judge = LLMJudgeDetector()
        self.detectors = [self.prompt_threats, self.shadow_ai, self.mcp_guard,
                          self.dep_guard, self.ext_guard, self.secrets_at_rest,
                          self.agent_safety, self.agent_rules, self.oversharing,
                          self.ci_guard, self.device_posture, self.judge]

    @property
    def judge_enabled(self) -> bool:
        return self.judge.enabled

    def _applies(self, detector, surface: Surface) -> bool:
        surfaces = getattr(detector, "surfaces", set())
        return not surfaces or surface in surfaces

    def analyze(self, item: AnalysisInput, include_judge: bool = True,
                judge_backends=None) -> Verdict:
        """`judge_backends` overrides the judge's provider list for this analysis (BYOK:
        the tenant's own key runs even when the global judge is unconfigured)."""
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
            except Exception:
                # A misbehaving detector must never sink the whole analysis.
                continue
        return score(signals)


engine = Engine()
