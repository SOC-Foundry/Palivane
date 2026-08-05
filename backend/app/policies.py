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
    """The catalog annotated with each check's current enabled state, grouped, + presets."""
    checks = [{**c, "enabled": c["key"] not in disabled} for c in CATALOG]
    return {"checks": checks, "groups": list(dict.fromkeys(c["group"] for c in CATALOG)),
            "presets": list(PRESETS.keys())}
