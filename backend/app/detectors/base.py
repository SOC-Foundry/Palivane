"""Detection primitives shared across all detectors.

A detector inspects a piece of content and emits zero or more `Signal`s. Each
signal is a single piece of evidence — a phishing indicator, a stylometric tell
of AI generation, a suspicious URL — carrying its own weight and confidence.
The scoring engine combines signals from every detector into one risk verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol


class Surface(str, Enum):
    """Where the content came from — which module's detectors should inspect it.

    The engine routes each submission to the detectors that declare its surface, so
    prompt-attack rules and data-loss rules apply where they belong. A detector with
    no declared surface runs on everything (e.g. the LLM judge)."""

    LLM_IO = "llm_io"     # Protect our AI — prompts/responses on the org's own LLMs
    AI_USAGE = "ai_usage" # Shadow-AI governance — content sent to external AI tools
    MCP = "mcp"           # Agentic tool-use — MCP calls from AI coding assistants
    DEPS = "deps"         # Dependency manifests — supply-chain risk in package files
    IDE = "ide"           # IDE extensions — known-bad / unapproved editor plugins
    SECRETS = "secrets"   # Endpoint credential hygiene — secrets at rest on a device
    OVERSHARING = "oversharing"  # Need-to-know: an LLM response returning restricted data
    CI = "ci"             # CI runners — GitHub Actions workflow posture & AI agents in CI
    AGENT_RULES = "agent_rules"  # Agent instruction files (CLAUDE.md/.cursorrules/skills) — hidden-instruction injection
    SESSION = "session"          # Correlated attack chains across an actor's recent activity


class Category(str, Enum):
    """What kind of threat evidence a signal represents."""

    AI_GENERATED = "ai_generated"      # the judge's AI-authorship assessment
    # --- Protect our AI (llm_io) ---
    PROMPT_INJECTION = "prompt_injection"      # instructions hijacking the model
    JAILBREAK = "jailbreak"                    # attempts to defeat safety/guardrails
    DATA_EXFILTRATION = "data_exfiltration"    # extracting system prompt / secrets / data
    # --- Shadow-AI governance (ai_usage) ---
    SECRET_LEAK = "secret_leak"                # credentials/keys leaving for an AI tool
    PII_EXPOSURE = "pii_exposure"              # personal data leaving for an AI tool
    SOURCE_CODE_LEAK = "source_code_leak"      # proprietary code/IP leaving for an AI tool
    CONFIDENTIAL_DATA = "confidential_data"    # confidential business content (financials,
                                               # contracts, roadmaps, labeled/marked material)
    UNSANCTIONED_AI = "unsanctioned_ai"        # destination is an unapproved AI service
    # --- Agentic tool-use (mcp) ---
    MCP_UNTRUSTED_SERVER = "mcp_untrusted_server"      # MCP server not on the allowlist
    MCP_INTEGRITY = "mcp_integrity"                    # local MCP server binary changed vs its pin
    MCP_REPUTATION = "mcp_reputation"                  # server pkg known-bad / non-registry / freshly (re)published
    SENSITIVE_RESOURCE_ACCESS = "sensitive_resource_access"  # tool/resource touches .env, keys, etc.
    DANGEROUS_COMMAND = "dangerous_command"            # tool call runs a high-risk shell command
    TOOL_POISONING = "tool_poisoning"                  # injected instructions in a tool description
    UNSAFE_AUTONOMY = "unsafe_autonomy"                # coding agent set to act without confirmation (YOLO)
    # --- Supply chain (deps) ---
    DEPENDENCY_RISK = "dependency_risk"                # risky/malicious dependency in a manifest
    # --- CI runners (ci) ---
    CI_WORKFLOW_RISK = "ci_workflow_risk"              # exploitable CI workflow configuration
    # --- Endpoint credential hygiene (secrets) ---
    CREDENTIAL_AT_REST = "credential_at_rest"          # a live secret/key sitting on a device
    # --- Access governance (oversharing) ---
    DATA_OVERSHARING = "data_oversharing"              # LLM surfaced restricted data to an unauthorized user
    AGENT_AUTHZ = "agent_authz"                        # agent took an action outside its least-privilege role
    # --- Session behavioral correlation (session) ---
    SESSION_CORRELATION = "session_correlation"        # a sequence of actions forms an attack chain


@dataclass(frozen=True)
class Signal:
    """One piece of evidence found in the content.

    weight     0..1  how much this indicator matters to overall risk
    confidence 0..1  how sure the detector is that the indicator is present
    """

    category: Category
    title: str
    detail: str
    weight: float
    confidence: float
    detector: str
    evidence: str = ""
    check: str = ""   # optional finer-grained policy key; defaults to the category

    @property
    def contribution(self) -> float:
        """The signal's raw push toward the risk score (0..1)."""
        return max(0.0, min(1.0, self.weight)) * max(0.0, min(1.0, self.confidence))

    @property
    def effective_check(self) -> str:
        """The policy check this signal belongs to — an explicit `check` when a detector
        wants sub-category granularity (e.g. 'hidden_characters'), else its category."""
        return self.check or self.category.value


@dataclass
class AnalysisInput:
    """Normalized content handed to every detector."""

    content: str
    subject: str = ""
    sender: str = ""
    channel: str = "email"  # email | chat | sms | document
    surface: Surface = Surface.LLM_IO
    metadata: dict = field(default_factory=dict)


class Detector(Protocol):
    """Anything that turns content into signals.

    `surfaces` declares which input surfaces this detector applies to; an empty
    set (the default) means "all surfaces". The engine uses it to route work."""

    name: str
    surfaces: set[Surface]

    def analyze(self, item: AnalysisInput) -> list[Signal]:
        ...
