"""GitHub Actions runner/workflow posture (surface=ci).

Given a workflow file's YAML, flag the configurations that get CI runners popped or that
put AI agents in the blast radius:

  * pwn-request: a `pull_request_target`/`workflow_run` trigger that checks out the PR
    head — fork code runs with the base repo's secrets
  * unpinned third-party actions (mutable tag/branch instead of a commit SHA) — the
    tj-actions/changed-files class of supply-chain compromise
  * `permissions: write-all` (workflow- or job-level) — a compromised step can rewrite
    the repo / releases
  * `secrets: inherit` into a third-party reusable workflow — hands it every org secret
  * self-hosted runners on PR-triggered workflows — fork PRs execute on your infra
  * AI agents running in CI (Claude Code, Codex, Gemini, aider, …, as actions or CLIs) —
    inventory for shadow-AI discovery, and a hard flag when a step hands one deploy/cloud
    credentials or runs it with autonomy flags (--dangerously-skip-permissions, --yolo)

Structural, not content-based: the interesting evidence is the workflow shape, so this
parses YAML (best-effort — a broken file falls back to text checks) rather than scanning
prose. Model API keys (ANTHROPIC/OPENAI/GEMINI_*_KEY) passed to an AI step are expected
and NOT flagged — the flag is for non-model secrets (AWS_/DEPLOY_/PROD_/DB creds).
"""

from __future__ import annotations

import re

import yaml

from .base import AnalysisInput, Category, Signal, Surface

# Orgs whose actions we treat as first-party enough to run un-pinned.
_TRUSTED_ACTION_ORGS = {"actions", "github"}

# `uses:` values that put an AI agent on the runner (matched on the owner/repo prefix).
_AI_ACTIONS = {
    "anthropics/claude-code-action": "Claude Code",
    "anthropics/claude-code-base-action": "Claude Code",
    "openai/codex-action": "Codex",
    "google-github-actions/run-gemini-cli": "Gemini CLI",
    "google-gemini/gemini-cli-action": "Gemini CLI",
}
# CLI invocations in `run:` steps that mean an AI agent is executing in CI.
_AI_CLIS = [
    (re.compile(r"(?:^|[\s;&|])claude(?:\s|$)", re.M), "Claude Code"),
    (re.compile(r"@anthropic-ai/claude-code"), "Claude Code"),
    (re.compile(r"(?:^|[\s;&|])codex(?:\s|$)", re.M), "Codex"),
    (re.compile(r"@openai/codex"), "Codex"),
    (re.compile(r"(?:^|[\s;&|])gemini(?:\s|$)", re.M), "Gemini CLI"),
    (re.compile(r"(?:^|[\s;&|])aider(?:\s|$)", re.M), "aider"),
    (re.compile(r"(?:^|[\s;&|])cursor-agent(?:\s|$)", re.M), "Cursor"),
    (re.compile(r"copilot\s+(?:suggest|explain|exec)", re.M), "GitHub Copilot CLI"),
]
_AUTONOMY_FLAGS = re.compile(
    r"--dangerously-skip-permissions|--yolo|--auto-approve|--full-auto|"
    r"--dangerously-bypass-approvals|--trust-all-tools", re.I)
_SHA_REF = re.compile(r"^[0-9a-f]{40}$")
# Secrets that are a model key (expected input for an AI step) vs. everything else.
_MODEL_KEY = re.compile(r"(ANTHROPIC|OPENAI|GEMINI|GOOGLE_AI|CLAUDE|OPENROUTER|MISTRAL|"
                        r"GROQ|XAI|DEEPSEEK)\w*_?(API_)?(KEY|TOKEN)", re.I)
_SECRET_REF = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)")
_ID_TOKEN_WRITE = re.compile(r"id-token\s*:\s*write")
_PR_HEAD_REF = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref")


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _jobs(doc: dict) -> dict:
    jobs = doc.get("jobs")
    return jobs if isinstance(jobs, dict) else {}


def _steps(job) -> list[dict]:
    if not isinstance(job, dict):
        return []
    return [s for s in _as_list(job.get("steps")) if isinstance(s, dict)]


def _step_text(step: dict) -> str:
    """The step's run body plus env/with values — where secrets and flags appear."""
    parts = [str(step.get("run") or "")]
    for key in ("env", "with"):
        block = step.get(key)
        if isinstance(block, dict):
            parts.extend(f"{k}={v}" for k, v in block.items())
    return "\n".join(parts)


def _ai_in_step(step: dict) -> str | None:
    """The AI tool this step runs, if any."""
    uses = str(step.get("uses") or "")
    for prefix, tool in _AI_ACTIONS.items():
        if uses.lower().startswith(prefix):
            return tool
    text = str(step.get("run") or "")
    for pat, tool in _AI_CLIS:
        if pat.search(text):
            return tool
    return None


class CIGuardDetector:
    name = "ci_guard"
    surfaces: set[Surface] = {Surface.CI}

    def analyze(self, item: AnalysisInput) -> list[Signal]:
        if (item.metadata or {}).get("kind") != "ci_workflow":
            return []
        try:
            doc = yaml.safe_load(item.content)
        except yaml.YAMLError:
            doc = None
        if not isinstance(doc, dict):
            return self._text_only(item.content)
        signals: list[Signal] = []
        signals += self._triggers(doc, item.content)
        signals += self._pins(doc, item.content)
        signals += self._permissions(doc)
        signals += self._reusable_secrets(doc)
        signals += self._runners(doc)
        signals += self._ai_steps(doc)
        return signals

    # --- rules -------------------------------------------------------------------

    def _triggers(self, doc: dict, raw: str) -> list[Signal]:
        # YAML 1.1 quirk: an unquoted `on:` loads as the boolean True.
        on = doc.get("on", doc.get(True))
        trig = set()
        if isinstance(on, str):
            trig = {on}
        elif isinstance(on, list):
            trig = {str(t) for t in on}
        elif isinstance(on, dict):
            trig = {str(t) for t in on}
        risky = trig & {"pull_request_target", "workflow_run"}
        if not risky:
            return []
        checks_out_head = bool(_PR_HEAD_REF.search(raw))
        if checks_out_head:
            return [Signal(
                category=Category.CI_WORKFLOW_RISK, title="Pwn-request pattern",
                detail=f"Privileged trigger ({', '.join(sorted(risky))}) checks out the PR "
                       "head — fork code runs with this repo's secrets and token.",
                weight=0.9, confidence=0.9, detector=self.name,
                evidence=", ".join(sorted(risky)), check="ci_unsafe_trigger")]
        return [Signal(
            category=Category.CI_WORKFLOW_RISK, title="Privileged PR trigger",
            detail=f"'{', '.join(sorted(risky))}' runs with secrets on PR events; audit "
                   "every step that touches PR-controlled data.",
            weight=0.45, confidence=0.8, detector=self.name,
            evidence=", ".join(sorted(risky)), check="ci_unsafe_trigger")]

    def _pins(self, doc: dict, raw: str) -> list[Signal]:
        """One signal per workflow, not per occurrence. Unpinned actions are a single
        posture problem ("this workflow doesn't pin third parties"), so N of them must not
        saturate the score into `critical` — that tier is for confirmed exposure
        (pwn-request, secrets handed to an agent). Severity instead turns on whether the
        workflow actually hands credentials to those actions."""
        unpinned: list[str] = []
        for job in _jobs(doc).values():
            for step in _steps(job):
                uses = str(step.get("uses") or "")
                if not uses or uses.startswith("./"):
                    continue
                if uses.startswith("docker://"):
                    if "@sha256:" not in uses and uses not in unpinned:
                        unpinned.append(uses)
                    continue
                ref = uses.partition("@")[2]
                org = uses.split("/", 1)[0].lower()
                if org in _TRUSTED_ACTION_ORGS or _SHA_REF.match(ref):
                    continue
                if uses not in unpinned:
                    unpinned.append(uses)
        if not unpinned:
            return []
        # A hijacked tag only reaches credentials if this workflow has some to reach.
        privileged = bool(_SECRET_REF.search(raw) or _ID_TOKEN_WRITE.search(raw))
        shown = ", ".join(unpinned[:5]) + (f" (+{len(unpinned) - 5} more)"
                                           if len(unpinned) > 5 else "")
        detail = (f"{len(unpinned)} third-party action(s) float on a mutable ref: {shown}. "
                  "Pin each to a full commit SHA.")
        if privileged:
            detail += (" This workflow exposes secrets or an OIDC id-token, so a hijacked "
                       "tag would run with those credentials.")
        return [Signal(
            category=Category.CI_WORKFLOW_RISK, title="Unpinned third-party action",
            detail=detail, weight=0.75 if privileged else 0.5, confidence=0.85,
            detector=self.name, evidence=shown, check="ci_unpinned_action")]

    def _permissions(self, doc: dict) -> list[Signal]:
        found = []
        if doc.get("permissions") == "write-all":
            found.append("workflow")
        for name, job in _jobs(doc).items():
            if isinstance(job, dict) and job.get("permissions") == "write-all":
                found.append(f"job '{name}'")
        return [Signal(
            category=Category.CI_WORKFLOW_RISK, title="write-all token permissions",
            detail=f"{where} grants the GITHUB_TOKEN write-all, a compromised step can "
                   "push code, rewrite releases, and edit workflows. Grant scopes explicitly.",
            weight=0.55, confidence=0.9, detector=self.name,
            evidence=where, check="ci_excessive_permissions") for where in found]

    def _reusable_secrets(self, doc: dict) -> list[Signal]:
        out = []
        for name, job in _jobs(doc).items():
            if not isinstance(job, dict):
                continue
            uses = str(job.get("uses") or "")
            if job.get("secrets") == "inherit" and uses and not uses.startswith("./"):
                org = uses.split("/", 1)[0].lower()
                if org in _TRUSTED_ACTION_ORGS:
                    continue
                out.append(Signal(
                    category=Category.CI_WORKFLOW_RISK, title="secrets: inherit to third party",
                    detail=f"Job '{name}' hands every repo/org secret to reusable workflow "
                           f"'{uses}'. Pass the specific secrets it needs.",
                    weight=0.6, confidence=0.9, detector=self.name,
                    evidence=uses, check="ci_secrets_inherit"))
        return out

    def _runners(self, doc: dict) -> list[Signal]:
        on = doc.get("on", doc.get(True))
        trig = set(on) if isinstance(on, (dict, list)) else {str(on or "")}
        pr_triggered = bool(trig & {"pull_request", "pull_request_target"})
        if not pr_triggered:
            return []
        out = []
        for name, job in _jobs(doc).items():
            if not isinstance(job, dict):
                continue
            runs_on = " ".join(str(r) for r in _as_list(job.get("runs-on")))
            if "self-hosted" in runs_on:
                out.append(Signal(
                    category=Category.CI_WORKFLOW_RISK, title="Self-hosted runner on PR trigger",
                    detail=f"Job '{name}' runs PR-triggered code on a self-hosted runner, "
                           "a fork PR is code execution inside your network.",
                    weight=0.65, confidence=0.85, detector=self.name,
                    evidence=runs_on, check="ci_self_hosted_runner"))
        return out

    def _ai_steps(self, doc: dict) -> list[Signal]:
        out = []
        for jname, job in _jobs(doc).items():
            for step in _steps(job):
                tool = _ai_in_step(step)
                if not tool:
                    continue
                where = f"{jname}/{step.get('name') or step.get('uses') or 'run'}"
                out.append(Signal(
                    category=Category.UNSANCTIONED_AI, title="AI agent in CI",
                    detail=f"{tool} runs on the CI runner (step {where}) with whatever the "
                           "job can reach. Inventory + policy: is this sanctioned here?",
                    weight=0.35, confidence=0.9, detector=self.name,
                    evidence=tool, check="ci_ai_agent"))
                text = _step_text(step)
                risky_secrets = sorted({s for s in _SECRET_REF.findall(text)
                                        if s != "GITHUB_TOKEN" and not _MODEL_KEY.search(s)})
                if risky_secrets:
                    out.append(Signal(
                        category=Category.SECRET_LEAK, title="Non-model secrets handed to AI step",
                        detail=f"Step {where} passes {', '.join(risky_secrets[:5])} to {tool}, "
                               "deploy/cloud credentials inside an AI agent's context.",
                        weight=0.8, confidence=0.85, detector=self.name,
                        evidence=", ".join(risky_secrets[:5]), check="ci_secrets_to_ai"))
                if _AUTONOMY_FLAGS.search(text):
                    out.append(Signal(
                        category=Category.UNSAFE_AUTONOMY, title="Autonomous AI agent in CI",
                        detail=f"Step {where} runs {tool} with approval prompts disabled "
                               f"({_AUTONOMY_FLAGS.search(text).group(0)}) on the runner.",
                        weight=0.7, confidence=0.9, detector=self.name,
                        evidence=_AUTONOMY_FLAGS.search(text).group(0),
                        check="unsafe_autonomy"))
        return out

    # --- degraded path for unparseable YAML ---------------------------------------

    def _text_only(self, raw: str) -> list[Signal]:
        out = []
        if "pull_request_target" in raw and _PR_HEAD_REF.search(raw):
            out.append(Signal(
                category=Category.CI_WORKFLOW_RISK, title="Pwn-request pattern",
                detail="pull_request_target + PR-head checkout (workflow did not parse as "
                       "YAML; matched textually).",
                weight=0.85, confidence=0.7, detector=self.name,
                evidence="pull_request_target", check="ci_unsafe_trigger"))
        if _AUTONOMY_FLAGS.search(raw):
            out.append(Signal(
                category=Category.UNSAFE_AUTONOMY, title="Autonomous AI agent in CI",
                detail="An agent autonomy flag appears in an unparseable workflow file.",
                weight=0.6, confidence=0.7, detector=self.name,
                evidence=_AUTONOMY_FLAGS.search(raw).group(0), check="unsafe_autonomy"))
        return out
