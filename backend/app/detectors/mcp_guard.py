"""MCP guard — inspects agentic tool-use captured over MCP (Model Context Protocol).

AI coding assistants (Claude Code, Cursor, Copilot) act through MCP: they call tools,
read resources, and connect to MCP servers. The egress proxy normalizes each MCP
JSON-RPC message and hands it here as an `AnalysisInput` on the `mcp` surface, with the
structured activity in `metadata`. This detector flags:

- **untrusted server** — an MCP server not on the org allowlist (policy-flag stance),
- **sensitive resource access** — a tool/resource touching `.env`, private keys, cloud
  credentials, etc.,
- **dangerous command** — a tool call running a high-risk shell command,
- **tool poisoning** — injected instructions hidden in a tool's *description* (the MCP
  server telling the model to ignore instructions, exfiltrate, etc.).

Secrets/PII inside tool arguments are caught by the shadow-AI detector (which also runs
on the `mcp` surface), so this detector focuses on the agentic-action risks above.
"""

from __future__ import annotations

import binascii
import re
import shlex
import urllib.parse

from ..config import settings
from .base import AnalysisInput, Category, Signal, Surface
from .normalize import command_leet_fold, normalize_for_match

# Paths whose access by an autonomous agent is high-signal (credentials / keys / secrets).
_SENSITIVE_PATH = re.compile(
    # `:` is a valid delimiter too, so a scheme-prefixed path — file:///etc/shadow, which
    # _norm_path collapses to file:/etc/shadow — is still caught (was a recall miss).
    r"(?:^|[/\\\s\"'=:])("
    r"\.env(?:\.[\w.-]+)?"
    r"|\.aws[/\\]credentials|\.aws[/\\]config"
    r"|\.ssh[/\\]|id_rsa|id_ed25519|id_ecdsa|id_dsa|[\w.-]+\.pem|[\w.-]+\.key"
    r"|\.kube[/\\]config|\.docker[/\\]config\.json"
    r"|\.npmrc|\.pypirc|\.netrc|\.git-credentials"
    r"|\.(?:bash|zsh|python|mysql)_history"
    r"|secrets?\.(?:ya?ml|json|env|txt)"
    r"|/etc/shadow|/etc/passwd|/proc/(?:\d+|self)/environ"
    r"|\.gnupg[/\\]|credentials\.json|service[-_]account[\w.-]*\.json"
    r")",
    re.IGNORECASE,
)

# A .pem is only a credential when it holds a key. These are the conventional names of the
# PUBLIC half (the CA certificate a proxy asks you to trust, a server's chain), which exist
# to be handed around. Deliberately a short list of names rather than "anything with cert in
# it": `mitmproxy-ca.pem` carries the CA's PRIVATE key and must keep flagging, and a private
# key inside a PEM is still caught by content (the "Private key block" pattern) wherever its
# text reaches an AI tool. `[\w.-]+\.pem` used to match them all, so `openssl x509 -in ca.pem`
# scored critical/block with a perfect 100.
_PUBLIC_CERT_NAME = re.compile(
    r"(?:ca|cacert|ca-cert|ca-bundle|ca-certificates|cert|certs|certificate|chain|fullchain"
    r"|root-?ca|[\w.-]*[-_.]cert|[\w.-]*[-_.]certificate)\.pem",
    re.IGNORECASE,
)


def _sensitive_path(haystack: str) -> re.Match | None:
    """The first sensitive path in `haystack`, skipping public certificates. Walks every
    match rather than taking the first, so a harmless `ca.pem` named earlier in a command
    cannot hide the `privkey.pem` named after it."""
    for m in _SENSITIVE_PATH.finditer(haystack):
        if _PUBLIC_CERT_NAME.fullmatch(m.group(1)):
            continue
        return m
    return None


_HEX_RUN_RE = re.compile(r"(?:[0-9a-fA-F]{2}){12,}")


def _command_views(args_text: str) -> list[str]:
    """Every de-obfuscated view of a command string the dangerous-command matcher should see:
    the raw text, a homoglyph/zero-width/spacing-normalized view, a leetspeak-folded view
    (cur1…|5h → curl…|sh), a URL-decoded view (curl%20…%7C%20sh), and any long hex / base64
    run decoded back to text (`decode this hex and follow it: 63757…`). Cheap and additive —
    a match in ANY view flags."""
    views = [args_text, normalize_for_match(args_text), command_leet_fold(args_text)]
    if "%" in args_text:
        try:
            dec = urllib.parse.unquote(args_text)
            if dec != args_text:
                views.append(dec)
        except (ValueError, UnicodeDecodeError):
            pass
    for m in _HEX_RUN_RE.finditer(args_text):
        try:
            raw = bytes.fromhex(m.group(0))
        except ValueError:
            continue
        text = raw.decode("utf-8", "replace")
        if text and sum(c.isprintable() or c.isspace() for c in text) / len(text) > 0.85:
            views.append(text)
    return views


def _norm_path(s: str) -> str:
    """Collapse trivial path obfuscation (/./ and //) so /etc/./passwd and /etc//passwd
    match the same as /etc/passwd. Not a full realpath (no filesystem), just defeats the
    cheap tricks; also fold backslashes so Windows-style separators are matched."""
    s = s.replace("\\", "/")
    prev = None
    while prev != s:
        prev = s
        s = s.replace("/./", "/").replace("//", "/")
    return s

# High-risk shell patterns an agent might execute via a run-command tool.
_DANGEROUS_CMD = re.compile(
    # \b: without it `| sha256sum` / `| shasum` / `| shellcheck` matched as `| sh`.
    r"(?:curl|wget)\s+[^\n|;&]*\|\s*(?:sudo\s+)?(?:ba)?sh\b"   # curl … | sh
    r"|(?:curl|wget)\s+[^\n|;&]*\|\s*(?:sudo\s+)?(?:python3?|perl|ruby|node|php)\b"  # curl … | python
    r"|base64\s+-d[^\n|]*\|\s*(?:sudo\s+)?(?:(?:ba)?sh|python3?|perl|ruby|node)\b"   # base64 -d | sh/python
    r"|rm\s+-rf\s+(?:/|~|\$HOME|--no-preserve-root)"           # rm -rf /
    r"|nc\s+-e|/dev/tcp/|bash\s+-i\s*>&"                        # reverse shells
    r"|chmod\s+(?:-R\s+)?0?777"                                 # world-writable
    r"|:\(\)\s*\{.*\};:"                                        # fork bomb
    r"|(?:disable|stop)\s+(?:firewall|defender|selinux|auditd)" # disable security
    r"|history\s+-c|shred\s+|>\s*/dev/null\s+2>&1\s*;\s*rm",    # cover tracks
    re.IGNORECASE,
)

# `curl … | python3` is dangerous because the interpreter runs the download as its PROGRAM.
# `curl … | python3 -c "…"` or `| python3 -m json.tool` hands it a program of its own and the
# download is only data - how every one of us pretty-prints an API response. The pattern above
# matches the pipe, not the behaviour, so a developer inspecting their own dev server scored
# critical/block. These helpers look at what follows the interpreter and keep flagging the two
# shapes that really execute the download: no program of its own, or inline code that runs
# what it reads.
_PIPED_INTERPRETER = re.compile(r"\|\s*(?:sudo\s+)?(python3?|perl|ruby|node|php)$", re.IGNORECASE)
# Per interpreter: the flags that give it a program of its own, and the options that consume
# the next word as a value (so `python3 -W ignore` is not mistaken for running a script named
# "ignore"). Per interpreter because the same letter means different things: `-r` is PHP's
# inline code but Node's and Ruby's "require", and `perl -p` is a loop with no program at all.
_INTERPRETERS = {
    "python": (re.compile(r"-[cm]"), {"-W", "-X", "-Q"}),
    "node": (re.compile(r"-[ep]|--(?:eval|print)"), {"-r", "--require", "--import", "--loader"}),
    # Only real switch letters may precede the e: `-ne`, `-lane`, `-pe`. A module flag such as
    # `-Mfeature` also ends in e, and is not inline code.
    "perl": (re.compile(r"-[lanpisSwWtTuUxcdf]*[eE]"), {"-I"}),
    "ruby": (re.compile(r"-[nplaw]*e"), {"-r", "-I"}),
    "php": (re.compile(r"-r"), set()),
}
# Inline code that EXECUTES its input (as opposed to parsing it).
_EXEC_PRIMITIVES = re.compile(
    r"\bexec\w*\s*\(|\beval\b|\bos\.system\b|\bsystem\s*\(|\bsystem\s+[\"'$<]|\bpopen\b"
    r"|\bsubprocess\b|\bspawn\w*\b|\bchild_process\b|\b__import__\b|\$\(|`",
    re.IGNORECASE,
)


def _executes_stdin(interpreter: str, tail: str) -> bool:
    """Does the interpreter that follows `curl … |` run its stdin as the program?
    `tail` is the text right after the interpreter's name. Errs toward True (flag): it only
    answers False for a flag or a script path that positively gives the interpreter a program
    of its own."""
    inline, takes_value = _INTERPRETERS["python" if interpreter.startswith("python") else interpreter]
    line = tail.split("\n", 1)[0]
    fallback = None
    try:
        toks = shlex.split(line)
    except ValueError:                 # unbalanced quote: judge the program on the raw text
        toks, fallback = line.split(), tail[:2000]
    i = 0
    while i < min(len(toks), 8):
        tok = toks[i]
        if tok in ("|", ";", "&&", "||", "&"):
            break                       # end of this interpreter's own command line
        if tok == "-":
            return True                 # `python3 -` : stdin is the program, spelt out
        if inline.fullmatch(tok):
            program = fallback if fallback is not None else (toks[i + 1] if i + 1 < len(toks) else "")
            return bool(_EXEC_PRIMITIVES.search(program))
        if tok in takes_value:
            i += 2                      # `-W ignore`: the value is not a script
            continue
        if tok.startswith("-"):
            i += 1                      # -u, -B, ...: an option, not a program
            continue
        return False                    # a script path: stdin is its data
    return True                         # bare interpreter: stdin IS the program


def _first_dangerous_command(view: str) -> re.Match | None:
    """The first dangerous-command match in one de-obfuscated view of a command line, passing
    over `curl … | <interpreter>` that is not executing the download. Walks every match, so a
    benign pipe earlier in the command cannot mask a dangerous one after it."""
    for m in _DANGEROUS_CMD.finditer(view):
        pipe = _PIPED_INTERPRETER.search(m.group(0))
        if pipe and not _executes_stdin(pipe.group(1).lower(), view[m.end():]):
            continue
        return m
    return None

# Injection phrasing hidden in a tool's description (MCP "tool poisoning").
_TOOL_POISON = re.compile(
    r"ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\s+"
    r"(?:instructions|guidance|rules|context)"
    r"|disregard\s+(?:the\s+|any\s+|all\s+|earlier\s+)?(?:system\s+prompt|previous|instructions|guidance)"
    # An adversarial verb before "system prompt" — bare "system prompt" over-matched legitimate
    # tool descriptions that merely MENTION it ("the agent's system prompt gets an instruction
    # appended"), which is not poisoning.
    r"|(?:reveal|expose|leak|exfiltrat\w*|print|dump|output|return|send|repeat)\s+"
    r"(?:the\s+|your\s+|its\s+|my\s+|full\s+|entire\s+)*system\s+prompt"
    r"|<important>|do\s+not\s+(?:tell|inform|mention|reveal)\s+(?:the\s+)?user"
    # Concealment needs an object, the same way the agent-rules secrecy check was bound to an
    # audience in #254. A bare "silently"/"without telling" matched ordinary tool-doc English
    # — "unsupported elements are silently dropped", "give it to a grader without telling it
    # which is which" — and scored Claude's own built-in tool descriptions critical, 201
    # recurrences deep (production, 2026-09-22). Either the adverb governs an exfiltrating
    # verb, or the concealment names a person being kept in the dark.
    r"|(?:silently|secretly|covertly|quietly)\s+(?:\w+\s+){0,3}?"
    r"(?:send|upload|post|forward|transmit|exfiltrat\w*|leak|cop(?:y|ie)|email|include|attach|"
    r"read|fetch|collect|record|log|report)\w{0,4}\b"
    r"|without\s+(?:telling|informing|notifying|alerting|asking)\s+(?:the\s+|your\s+|any\s+)?"
    r"(?:user|human|operator|caller|owner|developer|person|admin)"
    r"|exfiltrat|send\s+(?:the\s+)?(?:contents?|secrets?|keys?|env|file)\s+to"
    # Read/attach a CREDENTIAL FILE. Narrowed to file paths: bare "secret"/"api_key" as targets
    # matched benign — often DEFENSIVE — description copy ("do not include api_key values").
    r"|(?P<credfile>(?:read|include|attach|append|cat|upload|send)\s+[^\n]{0,40}"
    r"(?:\.env\b|\.ssh\b|id_rsa|~/\.aws|/\.aws/|\.pem\b|credentials\.(?:json|ya?ml|txt)))"
    # A "before using this tool…" prelude is how real tool docs open ("Before calling this
    # tool, you must first authenticate"), so the prelude alone is not evidence. It flags when
    # what follows is the kind of thing a poisoned description asks for.
    r"|before\s+(?:using|calling|running)\s+this\s+tool,?\s+(?:you\s+must\s+|first\s+|always\s+)"
    r"(?:\w+\s+){0,4}?(?:read|open|cat|fetch|send|upload|forward|exfiltrat\w*|ignore|"
    r"disregard|reveal|print|dump|include|attach)\w{0,4}\b",
    re.IGNORECASE,
)

# The credential-file clause above cannot tell an instruction from a warning. Claude Code's
# own Bash tool description says `…"git add .", which can accidentally include sensitive
# files (.env, credentials) …` - the same verb and the same path, in a sentence telling the
# model what NOT to do - and it scored critical/block, 16 recurrences deep. Where a negation
# (or the "accidentally" that makes the sentence a warning) stands directly in front of the
# verb, the clause is describing a hazard rather than directing one.
#
# "Directly in front" is the whole point. A window of a few words would let "never forget to
# include .env in the reply" - an instruction - buy its own silence, so only the verb's
# immediate lead-in is read: the cue, at most one adverb, an optional "to", then the verb.
_DEFENSIVE_LEAD = re.compile(
    r"(?:\b(?:never|not|avoid|accidentally|inadvertently|unintentionally|unknowingly)|n't)"
    r"\s+(?:(?:\w+ly|also|ever|even)\s+)?(?:to\s+)?$",
    re.IGNORECASE,
)


def _poison_match(text: str) -> re.Match | None:
    """The first poisoning directive in `text`, passing over credential-file mentions that
    are warnings. Keeps searching after a skipped one: a defensive sentence must not hide a
    real directive that follows it."""
    pos = 0
    while (m := _TOOL_POISON.search(text, pos)) is not None:
        if m.group("credfile") and _DEFENSIVE_LEAD.search(text[max(0, m.start() - 40):m.start()]):
            pos = m.start() + 1
            continue
        return m
    return None


def _match_context(m: re.Match, before: int = 44, after: int = 60) -> str:
    """Evidence that shows WHY a description matched: the offending phrase plus a little text
    either side. It used to be `desc[:120]` — the OPENING of the description, which for a long
    tool description has nothing to do with the match. Reviewers got a critical finding whose
    evidence read like ordinary product copy and no way to see the trigger short of fetching
    the server's manifest by hand; one such finding recurred 165 times without being triaged.

    Sliced from `m.string`, so a match found on the normalized (de-obfuscated) view quotes that
    view rather than mis-slicing the original at shifted offsets.
    """
    s = m.string
    lo, hi = max(0, m.start() - before), min(len(s), m.end() + after)
    context = " ".join(s[lo:hi].split())
    return (f"matched \u201c{m.group(0)[:60]}\u201d in: "
            + ("\u2026" if lo else "") + context + ("\u2026" if hi < len(s) else ""))


# Claude Code built-ins that cannot spawn a shell. Their arguments routinely CONTAIN command
# text (a file being read or written), which is not the same as running it. Bash is absent on
# purpose — it is the one that executes.
# Built-ins whose arguments are dominated by file CONTENT rather than by what they act on.
# Read is absent on purpose: the hook sends its path as `resource` and no content at all.
_CONTENT_BEARING_BUILTINS = frozenset({"Edit", "Write", "NotebookEdit"})

_NON_EXECUTING_BUILTINS = frozenset({
    "Read", "Edit", "Write", "NotebookEdit", "Glob", "Grep", "TodoWrite", "WebFetch",
})


def _parse_allow(value) -> set[str]:
    items = value if isinstance(value, (list, tuple, set)) else str(value or "").split(",")
    return {str(s).strip().lower() for s in items if str(s).strip()}


def _server_allowed(server: str, allow: set[str]) -> bool:
    host = (server or "").lower()
    return any(host == a or host.endswith("." + a) or host.endswith(a) for a in allow)


class MCPGuardDetector:
    name = "mcp_guard"
    surfaces: set[Surface] = {Surface.MCP, Surface.AGENT_TOOLS}

    def analyze(self, item: AnalysisInput) -> list[Signal]:
        m = item.metadata or {}
        method = m.get("method", "")
        server = m.get("server", "")
        tool = m.get("tool", "")
        args_text = m.get("args_text", "") or ""
        resource = m.get("resource", "") or ""
        descriptions = m.get("tool_descriptions") or []
        transport = m.get("transport", "http")
        signals: list[Signal] = []

        # 1) Untrusted MCP server (policy-flag). Only when an allowlist is configured.
        # Prefer the per-tenant allowlist passed in metadata; else the global default.
        # EMA `auth/*` events are exempt: their `server` is the IdP / MCP-AS *token
        # endpoint* host (the ID-JAG issuance leg being audited), not an MCP server —
        # connection authority for that leg belongs to the IdP, not this allowlist.
        allow = _parse_allow(m["allowed_servers"]) if "allowed_servers" in m \
            else _parse_allow(settings.mcp_allowed_servers)
        if server and allow and not method.startswith("auth/") \
                and not _server_allowed(server, allow):
            local = transport in ("stdio", "via-llm-api")
            signals.append(Signal(
                category=Category.MCP_UNTRUSTED_SERVER,
                title="Unapproved MCP server",
                detail=(f"MCP activity involves '{server}', which is not on the approved "
                        f"server allowlist." + (" (local/uninspectable transport — governed "
                        "by policy)" if local else "")),
                weight=0.85, confidence=0.9 if not local else 0.7,
                detector=self.name, evidence=f"server={server} transport={transport}",
            ))

        # 1b) Local-server integrity (palivane-mcp supply-chain pin): the wrapped server's
        # resolved binary no longer matches the hash recorded on first use — an update,
        # or a swapped/trojaned server. High-signal either way: it should be re-vetted.
        if m.get("pin_status") == "mismatch":
            signals.append(Signal(
                category=Category.MCP_INTEGRITY,
                title="MCP server binary changed since it was pinned",
                detail=(f"The local MCP server '{server}' no longer matches the binary hash "
                        "recorded when it was first approved (trust-on-first-use pin). "
                        "Re-vet the server and re-pin it if the change is expected."),
                weight=0.9, confidence=0.9, detector=self.name,
                evidence=f"command={m.get('command', '')[:120]} "
                         f"sha256={m.get('binary_sha256', '')[:16]}…",
            ))

        # 2) Sensitive resource / path access. Normalize first so /etc/./passwd,
        # /etc//passwd, and backslash paths don't slip past the pattern.
        #
        # For an editor built-in, args_text is the CONTENT of the file being written, and
        # scanning it here could not tell "opened ~/.aws/credentials" from "wrote a sentence
        # containing .aws/credentials". Documentation and detector fixtures duly scored
        # critical. Those tools carry their real target in `resource`, so scan only that.
        # Everything else — Bash, unknown built-ins, every MCP server tool — still gets the
        # full text, because for them a path in the arguments IS the target.
        content_bearing = not server and tool in _CONTENT_BEARING_BUILTINS
        haystack = _norm_path(resource if content_bearing else f"{resource}\n{args_text}")
        mres = _sensitive_path(haystack)
        if mres:
            signals.append(Signal(
                category=Category.SENSITIVE_RESOURCE_ACCESS,
                title="Access to a sensitive resource",
                detail=f"An MCP tool/resource call targets a sensitive path ({mres.group(1)}).",
                weight=0.9, confidence=0.9, detector=self.name,
                evidence=f"tool={tool or method} path={mres.group(1)}",
            ))

        # 3) Dangerous command execution. Scan every de-obfuscated view (normalized, leet-
        # folded, URL-decoded, hex-decoded) so homoglyph / fullwidth / zero-width / leetspeak
        # (cur1…|5h) / URL- and hex-encoded wrappers of `curl … | sh` can't slip past.
        #
        # ...but only for a tool that can actually run one. A built-in editor tool carries the
        # text of the file being edited, so writing documentation that mentions `rm -rf /`
        # scored critical with recommended_action=block — in enforcement mode that blocks a
        # file edit because of what the file SAYS. The suppression is deliberately narrow:
        # only built-ins (server == "") on the known non-executing list. An unrecognised tool,
        # and every tool on an MCP server, still gets scanned, because we cannot know what it
        # does and a silent miss there is far worse than a noisy hit.
        can_execute = bool(server) or tool not in _NON_EXECUTING_BUILTINS
        mcmd = next((mm for v in _command_views(args_text)
                     if (mm := _first_dangerous_command(v))), None) if can_execute else None
        if mcmd:
            signals.append(Signal(
                category=Category.DANGEROUS_COMMAND,
                title="High-risk command in a tool call",
                detail=f"An MCP tool call contains a dangerous shell pattern: {mcmd.group(0)[:80]}",
                weight=0.95, confidence=0.9, detector=self.name,
                evidence=f"tool={tool}",
            ))

        # 4) Tool poisoning — injection hidden in a tool description (scan a normalized view
        # so homoglyph / zero-width / fullwidth obfuscation of the directive can't hide it).
        for desc in descriptions:
            if not isinstance(desc, str):
                continue
            m = _poison_match(desc) or _poison_match(normalize_for_match(desc))
            if not m:
                continue
            signals.append(Signal(
                category=Category.TOOL_POISONING,
                title="Poisoned MCP tool description",
                detail="An advertised MCP tool description contains hidden instructions "
                       "aimed at the model (tool-poisoning / prompt injection).",
                weight=0.9, confidence=0.85, detector=self.name,
                evidence=_match_context(m),
            ))

        return signals
