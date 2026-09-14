"""Agent-rules detector: hidden-instruction injection in agent instruction files.

Coding agents load steering files on every turn — `CLAUDE.md`, `.cursorrules`,
`.cursor/rules/*.mdc`, `AGENTS.md`, `.github/copilot-instructions.md`, Skill `SKILL.md`,
and agent memory. Anything in those files is authority the model obeys, but a human
reviewer skims them. That gap is the "rules-file backdoor": an attacker (or a poisoned
template/dependency) plants instructions that steer the agent to exfiltrate secrets, run
commands, or hide its behavior — visible to the model, easy to miss in review.

This detector reads a rules file's raw bytes and flags:

  - **Concealment** (`rules_concealment`) — content hidden from the reviewer but live for
    the model: zero-width / bidi / Unicode-tag characters, or directive text buried inside
    an HTML/markdown comment. Concealment is the strongest tell — legitimate rules have
    nothing to hide.
  - **Exfiltration directives** (`rules_exfil`) — instructions to read credentials
    (~/.aws, .env, .ssh, keychains) and send them out, or to POST/upload/email data to an
    external destination.
  - **Concealed-behavior directives** (`rules_secrecy`) — "do not tell the user", "without
    informing", "silently", "keep this between us" — a rules file telling the agent to
    hide what it does is a backdoor tell, not a style preference.
  - **Tool-poisoning preambles** (`rules_tool_poison`) — "before using any tool, first …",
    "always run … first" — mandatory hidden steps injected ahead of the agent's real work.

General instruction-override phrasing ("ignore all previous instructions", role
reassignment) is caught by the prompt-threat detector, which also runs on this surface;
the LLM judge reads the file semantically for novel cases. Runs only on Surface.AGENT_RULES.
"""

from __future__ import annotations

import re

from .base import AnalysisInput, Category, Signal, Surface
from .normalize import _ZERO_WIDTH, normalize_for_match

# Directive text hidden inside an HTML/markdown comment — invisible in rendered Markdown,
# read verbatim by the model.
_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_COMMENT_DIRECTIVE = re.compile(
    r"\b(ignore|disregard|instead|always|never|do not|don't|must|system|assistant|tool|"
    r"execute|run|fetch|send|curl|exfiltrat|secret|api[_ -]?key|password|credential)\b",
    re.IGNORECASE,
)

# "read a credential store … and (send|post|include|exfiltrate) it" — the s1ngularity shape.
# A NAMED credential store or a case-sensitive secret ENV VAR (FOO_TOKEN / X_API_KEY /
# AWS_SECRET…) — deliberately NOT the bare lowercase word "token": "pass your token to the
# API" is in every vendor SDK doc, and treating it as a credential store made ordinary API
# documentation read as exfiltration. `(?-i:…)` keeps the env-var arm case-sensitive even
# though the surrounding pattern is IGNORECASE.
# Credential FILES / stores — reading one of these and sending it out is the s1ngularity
# shape. Kept separate from the env-var-NAME arm below because doc/skill files MENTION env-var
# names constantly ("set AWS_SECRET_KEY"), so a bare name near a URL is not exfil — only a
# credential FILE reference is strong enough to gate the destination-only rule.
# `.env` must be a FILE, not JS env access: `(?<![\w.])` excludes process.env.X /
# import.meta.env.X (env-var reads), which were matching as a ".env file" in vendor docs.
_CRED_FILE = (r"(?:~/\.aws|\.aws/credentials|~/\.ssh|id_rsa|(?<![\w.])\.env(?:\.\w+)?|"
              r"\.git-credentials|~/\.config|keychain|secrets?\.(?:json|ya?ml))")
_CRED_FILE_RE = re.compile(_CRED_FILE, re.IGNORECASE)
# NB: wrapped as one non-capturing group. Unwrapped, its internal `|` leaked to the top level
# of _EXFIL, so a BARE credential mention (a lone `.env` / `API_KEY`) matched as exfiltration
# with no send verb at all — the root of the skill-doc false positives.
_CRED_PATH = (r"(?:" + _CRED_FILE +
              r"|(?-i:[A-Z][A-Z0-9]*_(?:TOKEN|API_?KEY|KEY|SECRET|PASSWORD|CREDENTIALS?)))")
_CRED_PATH_RE = re.compile(_CRED_PATH, re.IGNORECASE)
# A credential ASSIGNED to a placeholder is documentation, not a real store — vendor skill
# docs are full of `API_KEY=local-dev-key`, `TOKEN=<your-token>`, `SECRET=changeme`.
_EXAMPLE_VALUE = re.compile(
    r"[=:]\s*[\"'`]?(?:local[-_]?dev|example|changeme|your[-_]|<[^>]{1,40}>|dummy|sample|"
    r"placeholder|xxx+|todo|test[-_]|redacted|fake|abc123|key[-_]?here|token[-_]?here|"
    r"\.\.\.|\$\{|\{\{)", re.IGNORECASE)
# The s1ngularity shape: an EXFIL verb and a credential in the same clause, either order.
# Requires an explicit send/exfil verb — a credential merely sitting near a URL or a `curl`
# (a READ) is ordinary API documentation, which is what produced the skill-doc false positives.
_EXFIL_VERB = r"(?:send|post|upload|exfiltrat\w*|transmit|email|forward|leak)"
_EXFIL = re.compile(
    _EXFIL_VERB + r"\b[^\n.]{0,80}?" + _CRED_PATH
    + r"|" + _CRED_PATH + r"[^\n.]{0,80}?\b(?:" + _EXFIL_VERB + r"|to\s+\S+@)",
    re.IGNORECASE,
)
# The destination-only rule (push to a URL/email) needs the credential FILE to actually be
# READ/accessed nearby — not just mentioned ("store secrets in `.env`"). Without this, a long
# doc that separately mentions a `.env` and a "POST to https://…" example trips the rule.
_CRED_READ = re.compile(
    r"(?:read|load|cat|open|access|dump|print|echo|grab|include|exfiltrat\w*|send|post|upload|copy)"
    r"\b[^\n.]{0,40}?" + _CRED_FILE
    + r"|" + _CRED_FILE + r"\b[^\n.]{0,25}?\b(?:contents?|values?|secrets?|keys?)\b",
    re.IGNORECASE,
)
# A directive to push data to an external endpoint (URL, webhook, or email address). Only
# meaningful as exfiltration when a real credential is ALSO referenced (gated at the call
# site) — a bare "post to https://…" or "email support@…" is ordinary automation/docs.
# Read verbs (curl/fetch) are excluded: fetching a URL pulls data IN, it is not exfiltration.
_EXFIL_DEST = re.compile(
    r"\b(?:send|post|upload|report|forward|email)\b[^\n.]{0,60}?"
    r"(?:https?://|hooks?\.|webhook|@[\w.-]+\.\w{2,})",
    re.IGNORECASE,
)

# A rules file instructing the agent to hide its behavior from the user.
_SECRECY = re.compile(
    r"do not (?:tell|inform|mention|reveal|notify|alert)\s+the\s+user"
    r"|without (?:telling|informing|notifying|alerting|the user'?s? knowledge)"
    r"|don'?t (?:tell|mention|reveal|let the user)"
    r"|keep (?:this|it) (?:secret|hidden|between us|to yourself|confidential)"
    r"|(?:silently|secretly|covertly|quietly)\s+(?:run|execute|send|do|perform|fetch|read)"
    r"|do not (?:log|report|surface|show)\s+(?:this|it|these)",
    re.IGNORECASE,
)

# Mandatory hidden preamble injected ahead of the agent's real work (tool poisoning).
_TOOL_POISON = re.compile(
    r"before (?:using|calling|running|invoking) (?:any|each|every|the) "
    r"(?:tool|command|function|action)[^\n.]{0,80}?(?:first|always|must|run|execute|fetch|read)"
    r"|always (?:run|execute|fetch|call|read)\b[^\n.]{0,60}?\bfirst\b"
    r"|(?:for|on) every (?:request|prompt|message|turn)[^\n.]{0,60}?(?:run|execute|send|fetch)",
    re.IGNORECASE,
)


def _find(rx: re.Pattern, *texts: str):
    for t in texts:
        m = rx.search(t)
        if m:
            return m
    return None


class AgentRulesDetector:
    name = "agent_rules"
    surfaces = {Surface.AGENT_RULES}

    def analyze(self, item: AnalysisInput) -> list[Signal]:
        raw = item.content or ""
        if not raw.strip():
            return []
        norm = normalize_for_match(raw)          # NFKC, zero-width stripped, homoglyphs folded
        signals: list[Signal] = []

        # 1. Concealment — the strongest tell. Zero-width/bidi/tag chars, or a directive
        #    buried in an HTML comment. A legitimate rules file has nothing to hide.
        zw = _ZERO_WIDTH.findall(raw)
        if zw:
            signals.append(Signal(
                category=Category.PROMPT_INJECTION,
                title="Hidden characters in an agent rules file",
                detail=f"The file contains {len(zw)} invisible character(s) (zero-width / "
                       "bidi / Unicode-tag) — text the model reads but a reviewer can't see. "
                       "Legitimate instruction files don't need them.",
                weight=0.85, confidence=0.9, detector=self.name,
                evidence=f"{len(zw)} concealed char(s)", check="rules_concealment",
            ))
        for c in _COMMENT.finditer(raw):
            body = c.group(1)
            if _COMMENT_DIRECTIVE.search(body):
                signals.append(Signal(
                    category=Category.PROMPT_INJECTION,
                    title="Directive hidden in an agent rules comment",
                    detail="An HTML/markdown comment (invisible in rendered Markdown) contains "
                           "instruction-like text the agent still reads — a common way to smuggle "
                           "a rules-file backdoor past review.",
                    weight=0.75, confidence=0.8, detector=self.name,
                    evidence=body.strip()[:120], check="rules_concealment",
                ))
                break

        # 2. Exfiltration directives — read a credential store and send it out, or push
        #    data to an external endpoint. The Nx "s1ngularity" shape, in a rules file.
        # _EXFIL already requires a credential near the send verb. The destination-only rule
        # (push to an external URL/email) is exfil ONLY when the file also references a real
        # credential somewhere — otherwise it is ordinary automation or API documentation.
        m = _find(_EXFIL, raw, norm)
        if m and _EXAMPLE_VALUE.search(m.group(0)):
            m = None      # the "credential" is a doc placeholder (API_KEY=local-dev-key)
        # Destination-only (push to a URL/email) needs the credential FILE to be READ/accessed
        # somewhere (not just mentioned as advice), else a long doc that separately mentions a
        # `.env` and a "POST to https://…" example trips the rule — the last skill-doc FP.
        if not m and _find(_CRED_READ, raw, norm):
            m = _find(_EXFIL_DEST, raw, norm)
        if m:
            signals.append(Signal(
                category=Category.DATA_EXFILTRATION,
                title="Exfiltration directive in an agent rules file",
                detail="The file instructs the agent to read credentials/secrets or push data "
                       "to an external destination — a rules file should never tell the agent "
                       "to send data out.",
                weight=0.9, confidence=0.85, detector=self.name,
                evidence=m.group(0).strip()[:120], check="rules_exfil",
            ))

        # 3. Concealed-behavior directives — telling the agent to hide what it does.
        m = _find(_SECRECY, raw, norm)
        if m:
            signals.append(Signal(
                category=Category.PROMPT_INJECTION,
                title="Rules file tells the agent to hide its behavior",
                detail="The file instructs the agent to act without informing the user (e.g. "
                       "'do not tell the user', 'silently run …') — a backdoor tell, not a "
                       "legitimate style rule.",
                weight=0.8, confidence=0.85, detector=self.name,
                evidence=m.group(0).strip()[:120], check="rules_secrecy",
            ))

        # 4. Tool-poisoning preamble — mandatory hidden step ahead of real work.
        m = _find(_TOOL_POISON, norm, raw)
        if m:
            signals.append(Signal(
                category=Category.TOOL_POISONING,
                title="Injected preamble in an agent rules file",
                detail="The file forces a hidden step before the agent's real work ('before "
                       "using any tool, first …' / 'always run … first') — the mechanism of a "
                       "tool-poisoning / rules-file injection.",
                weight=0.7, confidence=0.75, detector=self.name,
                evidence=m.group(0).strip()[:120], check="rules_tool_poison",
            ))

        return signals
