"""Policy catalog — the individual detection checks an admin can enable/disable per tenant.

Each check maps to one or more signal keys (a Signal's `effective_check` — an explicit
`check` string or its category). Disabling a check drops its signals before scoring, so a
tenant can tune exactly what Palivane flags. The catalog is the single source of truth for
the console's Policies page and for validating tenant updates.
"""

from __future__ import annotations

# key -> (label, description, group). `key` is what a Signal.effective_check resolves to.
CATALOG: list[dict] = [
    # --- Prompt / LLM I/O ---
    {"key": "prompt_injection", "label": "Prompt injection",
     "desc": "Instruction-override attempts that try to supersede the model's own instructions.",
     "group": "Prompt & LLM I/O"},
    {"key": "jailbreak", "label": "Jailbreak / guardrail evasion",
     "desc": "Personas and tricks that try to disable safety constraints or coerce policy-violating output.",
     "group": "Prompt & LLM I/O"},
    {"key": "data_exfiltration", "label": "System-prompt / data exfiltration",
     "desc": "Attempts to extract the hidden system prompt, rules, secrets, or context data.",
     "group": "Prompt & LLM I/O"},
    {"key": "hidden_characters", "label": "Hidden characters",
     "desc": "Zero-width / invisible Unicode and encoded (base64) payloads used to smuggle instructions.",
     "group": "Prompt & LLM I/O"},
    # --- Data loss (shadow AI) ---
    {"key": "secret_leak", "label": "Secret & credential leak",
     "desc": "API keys, tokens, private keys, and labeled credentials leaving for an AI tool.",
     "group": "Data loss"},
    {"key": "pii_exposure", "label": "PII exposure",
     "desc": "SSNs, payment cards, national IDs, and single-record personal data.",
     "group": "Data loss"},
    {"key": "phi_exposure", "label": "PHI exposure (HIPAA)",
     "desc": "Protected health information: MRNs, Medicare/insurance IDs, NPI/DEA numbers, "
             "diagnosis codes, and patient records with identity in clinical context.",
     "group": "Data loss"},
    {"key": "source_code_leak", "label": "Source / IP leak",
     "desc": "Proprietary source code sent to an AI tool (auto-suppressed for sanctioned coding tools).",
     "group": "Data loss"},
    {"key": "confidential_data", "label": "Confidential business data",
     "desc": "Financials, contracts, roadmaps, and material carrying a classification label (TLP / Purview).",
     "group": "Data loss"},
    {"key": "unsanctioned_ai", "label": "Unsanctioned AI destination",
     "desc": "Content going to a consumer AI service not on the org's approved allowlist.",
     "group": "Data loss"},
    # --- Agentic (MCP) ---
    {"key": "tool_poisoning", "label": "MCP tool poisoning",
     "desc": "Injected instructions hidden in an MCP server's advertised tool descriptions.",
     "group": "Agentic (MCP)"},
    {"key": "mcp_untrusted_server", "label": "MCP untrusted server",
     "desc": "Calls to MCP servers not on the trusted-servers allowlist.",
     "group": "Agentic (MCP)"},
    {"key": "dangerous_command", "label": "Dangerous command",
     "desc": "Agent tool-calls running high-risk shell commands (curl | sh, rm -rf, etc.).",
     "group": "Agentic (MCP)"},
    {"key": "sensitive_resource_access", "label": "Sensitive resource access",
     "desc": "Tool/resource calls touching .env, private keys, and other sensitive paths.",
     "group": "Agentic (MCP)"},
    # --- Coding assistants & agents ---
    {"key": "yolo_mode", "label": "YOLO / auto-apply modes",
     "desc": "Detects agent autonomy settings — autoRun, autoFix, auto-apply, MCP autoApprove, "
             "--dangerously-skip-permissions — that let it act without user confirmation.",
     "group": "Coding assistants & agents"},
    {"key": "cursor_chat", "label": "Cursor chat analysis",
     "desc": "Scans AI coding chats and generated code blocks for destructive / dangerous "
             "commands before a developer runs them.",
     "group": "Coding assistants & agents"},
    # --- Supply chain & endpoint ---
    {"key": "dependency_risk", "label": "Dependency risk",
     "desc": "Risky dependency manifests: install-script abuse, non-registry sources, known-bad packages + CVEs.",
     "group": "Supply chain & endpoint"},
    {"key": "ide_extension", "label": "IDE extension analysis",
     "desc": "Editor extensions with dangerous permissions, unverified publishers, or suspicious naming.",
     "group": "Supply chain & endpoint"},
    {"key": "credential_at_rest", "label": "Credentials at rest",
     "desc": "Live secrets found sitting on a managed endpoint (cloud keys, .npmrc, .git-credentials, key files).",
     "group": "Supply chain & endpoint"},
    # --- CI runners ---
    {"key": "ci_unsafe_trigger", "label": "CI privileged PR trigger",
     "desc": "pull_request_target / workflow_run workflows, and the pwn-request pattern "
             "(privileged trigger + PR-head checkout) that runs fork code with repo secrets.",
     "group": "CI runners"},
    {"key": "ci_unpinned_action", "label": "CI unpinned actions",
     "desc": "Third-party GitHub Actions floating on a mutable tag/branch instead of a commit SHA.",
     "group": "CI runners"},
    {"key": "ci_excessive_permissions", "label": "CI write-all permissions",
     "desc": "Workflows or jobs granting the GITHUB_TOKEN write-all instead of explicit scopes.",
     "group": "CI runners"},
    {"key": "ci_secrets_inherit", "label": "CI secrets: inherit",
     "desc": "Reusable third-party workflows called with `secrets: inherit` — every org secret handed over.",
     "group": "CI runners"},
    {"key": "ci_self_hosted_runner", "label": "CI self-hosted runner on PRs",
     "desc": "PR-triggered jobs on self-hosted runners — a fork PR is code execution inside your network.",
     "group": "CI runners"},
    {"key": "ci_ai_agent", "label": "AI agents in CI",
     "desc": "Coding agents (Claude Code, Codex, Gemini, aider, …) running on CI runners, as actions or CLIs.",
     "group": "CI runners"},
    {"key": "ci_secrets_to_ai", "label": "CI secrets handed to AI steps",
     "desc": "Non-model secrets (cloud/deploy/DB credentials) passed into a step that runs an AI agent.",
     "group": "CI runners"},
    # --- Access governance ---
    {"key": "data_oversharing", "label": "Data oversharing (need-to-know)",
     "desc": "Flags when an enterprise LLM returns restricted data (confidential, PII, keywords) "
             "to a user outside the allowed group — configured in Settings → Need-to-know rules.",
     "group": "Access governance"},
    {"key": "agent_authz", "label": "Agent least-privilege",
     "desc": "Flags when an AI agent calls a tool or MCP server outside its assigned role — "
             "monitor by default, enforce per role. Configured in Agents → Roles.",
     "group": "Access governance"},
]

# The keys that ext_guard uses — ext_guard emits DEPENDENCY_RISK for IDE ext findings, so
# `ide_extension` currently aliases dependency_risk on the `ide` surface. Kept distinct in
# the catalog for admin clarity; both share the underlying category filter.
_ALIASES = {"ide_extension": "dependency_risk"}

VALID_KEYS = {c["key"] for c in CATALOG}

# --- Compliance-framework mapping ------------------------------------------------------
# Each check maps to the external frameworks enterprise evaluations now ask about. Kept in
# one table (not inline on every check) so the mapping is auditable in one place and the
# catalog stays readable. Granularity is what each framework publishes: OWASP LLM/Agentic
# have per-risk codes; NIST AI RMF and the EU AI Act are mapped at the function / article
# level, which is the standard for control-to-framework mapping.
#
#   owasp_llm     — OWASP Top 10 for LLM Applications 2025 (LLM01–LLM10)
#   owasp_agentic — OWASP Agentic AI: Threats & Mitigations (T1–T15)
#   nist_ai_rmf   — NIST AI RMF 1.0 core functions (GOVERN / MAP / MEASURE / MANAGE)
#   eu_ai_act     — EU AI Act obligations by article (high-risk system requirements)
FRAMEWORK_LABELS: dict[str, dict[str, str]] = {
    "owasp_llm": {
        "LLM01": "Prompt Injection", "LLM02": "Sensitive Information Disclosure",
        "LLM03": "Supply Chain", "LLM04": "Data and Model Poisoning",
        "LLM05": "Improper Output Handling", "LLM06": "Excessive Agency",
        "LLM07": "System Prompt Leakage", "LLM08": "Vector and Embedding Weaknesses",
        "LLM09": "Misinformation", "LLM10": "Unbounded Consumption",
    },
    "owasp_agentic": {
        "T2": "Tool Misuse", "T3": "Privilege Compromise", "T6": "Intent Breaking & Goal Manipulation",
        "T8": "Repudiation & Untraceability", "T10": "Overwhelming Human-in-the-Loop",
        "T12": "Agent Communication Poisoning", "T13": "Rogue Agents in the System",
    },
    "nist_ai_rmf": {
        "GOVERN": "Govern — policies, roles, accountability",
        "MAP": "Map — context and risk identification",
        "MEASURE": "Measure — analyze, assess, track risk",
        "MANAGE": "Manage — respond to and act on risk",
    },
    "eu_ai_act": {
        "Art.10": "Data & data governance", "Art.12": "Record-keeping / logging",
        "Art.14": "Human oversight", "Art.15": "Accuracy, robustness & cybersecurity",
    },
}

# check key -> {framework: [codes]}. A check with no entry maps to nothing (and the report
# says so, rather than silently claiming coverage).
_FW = "owasp_llm"; _AG = "owasp_agentic"; _NI = "nist_ai_rmf"; _EU = "eu_ai_act"
FRAMEWORK_MAP: dict[str, dict[str, list[str]]] = {
    "prompt_injection":  {_FW: ["LLM01"], _NI: ["MEASURE", "MANAGE"], _EU: ["Art.15"]},
    "jailbreak":         {_FW: ["LLM01"], _NI: ["MEASURE", "MANAGE"], _EU: ["Art.15"]},
    "data_exfiltration": {_FW: ["LLM07", "LLM02"], _NI: ["MEASURE", "MANAGE"], _EU: ["Art.15"]},
    "hidden_characters": {_FW: ["LLM01"], _NI: ["MEASURE"], _EU: ["Art.15"]},
    "secret_leak":       {_FW: ["LLM02"], _NI: ["MANAGE"], _EU: ["Art.10", "Art.15"]},
    "pii_exposure":      {_FW: ["LLM02"], _NI: ["MANAGE"], _EU: ["Art.10"]},
    "phi_exposure":      {_FW: ["LLM02"], _NI: ["MANAGE"], _EU: ["Art.10"]},
    "source_code_leak":  {_FW: ["LLM02"], _NI: ["MANAGE"], _EU: ["Art.10"]},
    "confidential_data": {_FW: ["LLM02"], _NI: ["MANAGE"], _EU: ["Art.10"]},
    "unsanctioned_ai":   {_FW: ["LLM02"], _NI: ["GOVERN", "MAP"], _EU: ["Art.10"]},
    "tool_poisoning":    {_FW: ["LLM01"], _AG: ["T2", "T12"], _NI: ["MEASURE"], _EU: ["Art.15"]},
    "mcp_untrusted_server": {_FW: ["LLM03"], _AG: ["T2", "T13"], _NI: ["MAP", "MANAGE"], _EU: ["Art.15"]},
    "dangerous_command": {_FW: ["LLM06"], _AG: ["T2"], _NI: ["MANAGE"], _EU: ["Art.14", "Art.15"]},
    "sensitive_resource_access": {_FW: ["LLM06"], _AG: ["T2"], _NI: ["MANAGE"], _EU: ["Art.15"]},
    "yolo_mode":         {_FW: ["LLM06"], _AG: ["T2", "T10"], _NI: ["GOVERN", "MANAGE"], _EU: ["Art.14"]},
    "cursor_chat":       {_FW: ["LLM05", "LLM06"], _AG: ["T2"], _NI: ["MEASURE", "MANAGE"], _EU: ["Art.14"]},
    "dependency_risk":   {_FW: ["LLM03"], _NI: ["MAP", "MANAGE"], _EU: ["Art.15"]},
    "ide_extension":     {_FW: ["LLM03"], _NI: ["MAP"], _EU: ["Art.15"]},
    "credential_at_rest": {_FW: ["LLM02"], _NI: ["MANAGE"], _EU: ["Art.15"]},
    "ci_unsafe_trigger": {_FW: ["LLM03"], _AG: ["T3"], _NI: ["MAP", "MANAGE"], _EU: ["Art.15"]},
    "ci_unpinned_action": {_FW: ["LLM03"], _NI: ["MAP", "MANAGE"], _EU: ["Art.15"]},
    "ci_excessive_permissions": {_FW: ["LLM06", "LLM03"], _AG: ["T3"], _NI: ["GOVERN", "MANAGE"], _EU: ["Art.15"]},
    "ci_secrets_inherit": {_FW: ["LLM02", "LLM03"], _NI: ["MANAGE"], _EU: ["Art.15"]},
    "ci_self_hosted_runner": {_FW: ["LLM03"], _NI: ["MAP", "MANAGE"], _EU: ["Art.15"]},
    "ci_ai_agent":       {_FW: ["LLM06"], _AG: ["T2"], _NI: ["MAP", "GOVERN"], _EU: ["Art.14"]},
    "ci_secrets_to_ai":  {_FW: ["LLM02", "LLM06"], _AG: ["T2"], _NI: ["MANAGE"], _EU: ["Art.10", "Art.15"]},
    "data_oversharing":  {_FW: ["LLM02", "LLM06"], _NI: ["MANAGE"], _EU: ["Art.10", "Art.14"]},
    "agent_authz":       {_FW: ["LLM06"], _AG: ["T3"], _NI: ["GOVERN", "MANAGE"], _EU: ["Art.14"]},
}
# Fail loudly if a check ever ships without a mapping — an unmapped check would silently
# understate coverage in the compliance report.
assert set(FRAMEWORK_MAP) == VALID_KEYS, (
    "policies FRAMEWORK_MAP out of sync with CATALOG: "
    f"missing {VALID_KEYS - set(FRAMEWORK_MAP)}, extra {set(FRAMEWORK_MAP) - VALID_KEYS}")


def frameworks_for(key: str) -> dict[str, list[str]]:
    """The framework codes a check maps to (empty dict if none)."""
    return FRAMEWORK_MAP.get(key, {})

# Presets: the set of checks each preset DISABLES (everything else on).
PRESETS: dict[str, list[str]] = {
    "strict": [],  # everything on
    "balanced": [],  # everything on — the default; presets differ mostly by enforce/severity elsewhere
    "monitor": [],  # discovery-first: keep all checks recording (blocking handled by mode, not checks)
}


def parse_disabled(raw) -> set[str]:
    """Normalize a stored value (CSV string or list) into a validated set of check keys."""
    if not raw:
        return set()
    items = raw.split(",") if isinstance(raw, str) else list(raw)
    return {i.strip() for i in items if i and i.strip() in VALID_KEYS}


def _best_match(actor: str, overrides, channel: str = ""):
    """The single override that governs this actor (+ optional tool/channel), or None.

    A user override (exact email) beats any group override; among group overrides the most
    specific glob wins (fewest wildcards, then longest pattern). An override may be scoped
    to a tool/channel glob (e.g. "claude-code", "claude-*") — it then only applies to
    captures on that tool, and a tool-scoped override beats a tool-any one for the same
    actor."""
    import fnmatch

    a = (actor or "").strip().lower()
    ch = (channel or "").strip().lower()
    if not a or not overrides:
        return None

    def _chan(o) -> str:
        return (getattr(o, "channel", "") or "").strip().lower()

    def _chan_ok(o) -> bool:
        och = _chan(o)
        return not och or (bool(ch) and fnmatch.fnmatch(ch, och))

    users = [o for o in overrides if o.scope == "user"
             and (o.match or "").strip().lower() == a and _chan_ok(o)]
    if users:
        users.sort(key=lambda o: not _chan(o))   # tool-scoped beats tool-any
        return users[0]

    groups = [o for o in overrides if o.scope == "group"
              and fnmatch.fnmatch(a, (o.match or "").strip().lower()) and _chan_ok(o)]
    if groups:
        groups.sort(key=lambda o: (not _chan(o), (o.match or "").count("*"),
                                   -len(o.match or "")))
        return groups[0]

    return None


def _matched_dict(o) -> dict:
    return {"id": o.id, "scope": o.scope, "match": o.match,
            "channel": (getattr(o, "channel", "") or "").strip().lower()}


def resolve_disabled(base_disabled: set[str], actor: str, overrides,
                     channel: str = "") -> tuple[set[str], dict | None]:
    """Pick the effective disabled-check set for an actor (and optionally the tool/channel
    the content is flowing through). The matched override REPLACES the tenant default.
    Returns (disabled_set, matched_override_dict_or_None)."""
    hit = _best_match(actor, overrides, channel)
    if hit is None:
        return base_disabled, None
    return parse_disabled(hit.disabled_checks), _matched_dict(hit)


def resolve_enforce(default: bool, actor: str, overrides,
                    channel: str = "") -> tuple[bool, dict | None]:
    """Effective monitor/enforce stance for an actor (+ optional tool/channel): the
    best-matching override that carries an explicit enforce wins, else the tenant/global
    default. This is what makes STAGED enforcement possible — enforce a pilot user,
    group glob, or single tool while the rest of the org stays in monitor. Only
    overrides with enforce set participate; check-only overrides are invisible here."""
    hit = _best_match(actor, [o for o in (overrides or [])
                              if getattr(o, "enforce", None) is not None], channel)
    if hit is None:
        return default, None
    return bool(hit.enforce), _matched_dict(hit)


def checks_signal_filter(disabled: set[str]):
    """A signal filter (list[Signal] -> list[Signal]) that drops signals for disabled checks.
    Resolves aliases so a catalog key and its underlying category both match."""
    if not disabled:
        return None
    active = set(disabled) | {_ALIASES[d] for d in disabled if d in _ALIASES}
    return lambda signals: [s for s in signals if s.effective_check not in active]


def catalog_for(disabled: set[str]) -> dict:
    """The catalog annotated with each check's current enabled state, grouped, + presets.
    Each check carries its framework mapping so the console can show OWASP/NIST/EU tags."""
    checks = [{**c, "enabled": c["key"] not in disabled, "frameworks": frameworks_for(c["key"])}
              for c in CATALOG]
    return {"checks": checks, "groups": list(dict.fromkeys(c["group"] for c in CATALOG)),
            "presets": list(PRESETS.keys())}


def compliance_report(disabled: set[str]) -> dict:
    """A framework-coverage report for this tenant's active policy: for every framework
    control, which Palivane checks cover it and whether they are currently enabled.

    This is the artifact an enterprise eval asks for — "show me your OWASP LLM Top 10 /
    NIST AI RMF / EU AI Act coverage." It is generated from the live policy, so it reflects
    what the org actually has switched on, not a static claim."""
    frameworks = []
    for fw_key, labels in FRAMEWORK_LABELS.items():
        controls = []
        for code, name in labels.items():
            covering = [c["key"] for c in CATALOG
                        if code in frameworks_for(c["key"]).get(fw_key, [])]
            enabled = [k for k in covering if k not in disabled]
            controls.append({
                "code": code, "name": name,
                "checks": covering,
                "enabled_checks": enabled,
                # covered = at least one mapped check is on; a control with mapped-but-all-
                # disabled checks is reported as a gap, not silently "covered".
                "status": ("covered" if enabled else "gap" if covering else "not_mapped"),
            })
        covered = sum(1 for c in controls if c["status"] == "covered")
        mapped = sum(1 for c in controls if c["status"] != "not_mapped")
        frameworks.append({
            "framework": fw_key,
            "controls": controls,
            "covered": covered, "mapped": mapped, "total": len(controls),
        })
    return {"frameworks": frameworks,
            "checks_total": len(CATALOG),
            "checks_enabled": len([c for c in CATALOG if c["key"] not in disabled])}
