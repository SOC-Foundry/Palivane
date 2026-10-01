"""Dependency-manifest supply-chain risk (surface=deps).

Vets a dependency manifest (package.json, requirements.txt, pyproject) for the
supply-chain risks that don't need an external advisory feed — so it runs agentlessly in
CI / the git plane:

- **install-script abuse** — npm lifecycle scripts (preinstall/install/postinstall) that
  run shell payloads (`curl … | sh`, `node -e`, `base64 -d | sh`) — the classic malicious
  package vector;
- **non-registry sources** — deps pointing at a git URL, http tarball, or local path,
  which bypass registry review;
- **known-bad names** — a small built-in denylist plus `DEP_DENYLIST` additions.

This is a heuristic *risk* scan, not a CVE/advisory (OSV) vulnerability feed — that's a
separate, feed-backed add-on. The manifest kind is taken from the filename in `subject`.
"""

from __future__ import annotations

import json
import re

from ..config import settings
from .base import AnalysisInput, Category, Signal, Surface

# Publicly-documented malicious/typosquat package names (illustrative, extend via DEP_DENYLIST).
_BUILTIN_DENYLIST = {
    "crossenv", "cross-env.js", "event-stream-flatmap", "electron-native-notify",
    "colourama", "python3-dateutil", "jeIlyfish", "reqiests", "urllib3-secure",
}

# Shell payloads inside an install/lifecycle script.
_INSTALL_PAYLOAD = re.compile(
    r"(?:curl|wget)\s+[^\n|;&]*\|\s*(?:ba)?sh"
    r"|base64\s+-d[^\n|]*\|\s*(?:ba)?sh"
    r"|node\s+-e\s+['\"].*(?:require\(|https?://|child_process)"
    r"|python\s+-c\s+['\"].*(?:urllib|requests|socket|exec)"
    r"|/dev/tcp/|eval\s*\(|powershell\s+-e(?:nc)?\b",
    re.IGNORECASE,
)
_NPM_INSTALL_KEYS = ("preinstall", "install", "postinstall", "prepare", "prepublish")
# A non-registry source in a version spec (git/url/tarball/local path).
_NONREGISTRY = re.compile(r"^(?:git\+|git:|https?:|file:|link:|github:|bitbucket:|gitlab:|/|\.\.?/)", re.I)


# pip options whose VALUE is where packages come from: an editable path or VCS URL, an index,
# a find-links location. Every other dash-prefixed line (`--hash=…`, `--require-hashes`,
# `--no-binary`, a markdown `---`) says nothing about a source. This used to be
# `startswith("--")`, which flagged all of them, and missed the short forms `-i` and `-f`.
_PIP_SOURCE_OPTION = re.compile(
    r"^(?:-e|--editable|-i|--index-url|--extra-index-url|-f|--find-links)(?:[\s=]|$)", re.I)
# A bare path whose file name is a requirements file: `/proj/requirements.txt`.
_REQ_PATH_LINE = re.compile(r"(?:\S*[/\\])?requirements[\w.-]*\.txt", re.I)

_EXACT_VERSION = re.compile(r"^\d+\.\d+")
_REQ_PIN = re.compile(r"^([A-Za-z0-9._-]+)==([0-9][\w.\-]*)")

# Launchers that fetch-and-run a package from a public registry (the MCP-server supply chain).
_NPM_RUNNERS = ("npx", "npm", "pnpm", "bunx", "yarn")
_PY_RUNNERS = ("uvx", "uv", "pipx")
_RUNNER_FLAGS = {"-y", "--yes", "-q", "--quiet", "-p", "--package", "run", "exec",
                 "dlx", "-c", "--", "install", "add", "--silent"}


def extract_mcp_packages(command: str, args: list) -> list[tuple[str, str, str]]:
    """From an MCP server's launch command, resolve the package it fetches-and-runs to
    (ecosystem, name, version). version="" means UNPINNED (runs whatever the registry serves
    now — a supply-chain backdoor risk). Returns [] when there's no registry package (a local
    script, a bare `python -m`, etc.)."""
    cmd = (command or "").strip().lower().split("/")[-1]
    toks = [str(a).strip() for a in (args or []) if str(a).strip()]
    if cmd in _NPM_RUNNERS:
        eco = "npm"
    elif cmd in _PY_RUNNERS:
        eco = "PyPI"
    else:
        return []
    for tok in toks:
        low = tok.lower()
        if low in _RUNNER_FLAGS or tok.startswith("-"):
            continue
        # First real token is the package spec; a path/URL isn't a registry package.
        if "/" in tok and not tok.startswith("@"):
            return []
        if eco == "npm":
            # @scope/name@ver | name@ver | @scope/name | name
            at = tok.rfind("@")
            if at > 0:
                return [("npm", tok[:at], tok[at + 1:])]
            return [("npm", tok, "")]
        else:
            m = re.match(r"^([A-Za-z0-9._-]+)(?:==([0-9][\w.\-]*))?$", tok)
            if m:
                return [("PyPI", m.group(1), m.group(2) or "")]
            return []
    return []


def extract_pinned(content: str, subject: str = "") -> list[tuple[str, str, str]]:
    """Extract (ecosystem, name, version) for dependencies pinned to a concrete version —
    the only ones an advisory feed (OSV) can resolve. Ranges (^, ~, >=) are skipped."""
    fname = (subject or "").lower()
    pins: list[tuple[str, str, str]] = []
    if fname.endswith(".json") or content.lstrip().startswith("{"):
        try:
            j = json.loads(content)
        except (ValueError, TypeError):
            return []
        if not isinstance(j, dict):
            return []
        for sect in ("dependencies", "devDependencies"):
            for name, spec in (j.get(sect) or {}).items():
                if isinstance(spec, str):
                    s = spec.strip().lstrip("=v")
                    if _EXACT_VERSION.match(s):
                        pins.append(("npm", name, s))
    else:
        for raw in content.splitlines():
            m = _REQ_PIN.match(raw.strip())
            if m:
                pins.append(("PyPI", m.group(1), m.group(2)))
    return pins


def _requirements_written(content: str, resource: str = "") -> str | None:
    """The body of a requirements file that a tool call is WRITING, or None.

    A mention is not a write. `pip install -r requirements.txt`, `git add requirements.txt`, a
    heredoc that names it: none of those is the file, but the old test - "the word
    requirements.txt appears anywhere in the text" - read every line of such a command as a
    requirement, so `/abs/path`, `./script` and `https://…` lines each became a "non-registry
    dependency". The file's path has to stand alone, as the call's resource or as the first
    line of its arguments (how a Write/Edit and an MCP filesystem write_file both arrive).
    The path lines are dropped from the body: a path is not a requirement either."""
    lines = content.split("\n")
    path_lines = {s for s in ((lines[0] if lines else "").strip(), (resource or "").strip())
                  if s and _REQ_PATH_LINE.fullmatch(s)}
    if not path_lines:
        return None
    return "\n".join(ln for ln in lines if ln.strip() not in path_lines)


_MANIFEST_KEYS = {"dependencies", "devDependencies", "scripts"}
_JSON_DECODER = json.JSONDecoder()


def _extract_manifest_json(content: str) -> str | None:
    """Find an npm-manifest-shaped JSON object in free text (has dependencies / scripts) and
    return just that JSON substring — so a package.json written via a tool call is caught even
    when the content is prefixed by the file path. None if there's no such manifest."""
    # A real manifest's opening brace is within the first line or two (after the file path),
    # so only try the first few `{` — otherwise `raw_decode` per `{` over adversarial text
    # like `'{"a":' * 20000` is O(n²).
    i, attempts = content.find("{"), 0
    while i != -1 and attempts < 32:
        attempts += 1
        try:
            obj, end = _JSON_DECODER.raw_decode(content, i)
        except ValueError:
            i = content.find("{", i + 1)
            continue
        if isinstance(obj, dict) and (obj.keys() & _MANIFEST_KEYS):
            return content[i:end]
        i = content.find("{", i + 1)
    return None


class DepGuardDetector:
    name = "dep_guard"
    # DEPS = the /api/scan/deps manifest scan; MCP = a manifest written via an agent tool call
    # (a package.json Write), which would otherwise only trip the generic dangerous_command check.
    surfaces: set[Surface] = {Surface.DEPS, Surface.MCP, Surface.AGENT_TOOLS}

    def analyze(self, item: AnalysisInput) -> list[Signal]:
        fname = (item.subject or "").lower()
        content = item.content or ""
        m = item.metadata or {}
        # Per-tenant denylist (metadata) over the global default, always plus the built-in.
        extra = m["dep_denylist"] if "dep_denylist" in m else settings.dep_denylist
        deny = _BUILTIN_DENYLIST | {s.strip().lower() for s in str(extra or "").split(",") if s.strip()}

        # DEPS: the caller (scan_deps) guarantees the content IS a manifest, keyed by filename.
        if item.surface == Surface.DEPS:
            if fname.endswith(".json") or content.lstrip().startswith("{"):
                return self._scan_package_json(content, deny)
            return self._scan_requirements(content, deny)

        # Any other surface (e.g. an MCP Write of package.json): only act on content that
        # clearly IS a manifest, so arbitrary tool-call text can't false-positive.
        pkg = _extract_manifest_json(content)
        if pkg is not None:
            return self._scan_package_json(pkg, deny)
        body = _requirements_written(content, m.get("resource") or "")
        if body is not None:
            return self._scan_requirements(body, deny)
        return []

    def _sig(self, title: str, detail: str, evidence: str, weight: float, conf: float) -> Signal:
        return Signal(category=Category.DEPENDENCY_RISK, title=title, detail=detail,
                      weight=weight, confidence=conf, detector=self.name, evidence=evidence)

    def _scan_package_json(self, content: str, deny: set) -> list[Signal]:
        try:
            j = json.loads(content)
        except (ValueError, TypeError):
            return []
        if not isinstance(j, dict):
            return []
        # A malformed manifest can have non-dict "dependencies" (a string/list); guard the
        # spread so it can't raise "argument to ** must be a mapping".
        deps = j.get("dependencies") if isinstance(j.get("dependencies"), dict) else {}
        dev = j.get("devDependencies") if isinstance(j.get("devDependencies"), dict) else {}
        signals: list[Signal] = []
        signals.extend(self._denylist_signals({**deps, **dev}.items(), deny))

        scripts = j.get("scripts") or {}
        if isinstance(scripts, dict):
            for k in _NPM_INSTALL_KEYS:
                v = scripts.get(k)
                if isinstance(v, str) and _INSTALL_PAYLOAD.search(v):
                    signals.append(self._sig(
                        "Malicious install script",
                        f"The '{k}' lifecycle script runs a shell payload on install — the "
                        f"classic malicious-package vector.",
                        f"{k}: {v[:100]}", 0.95, 0.9))

        for name, spec in {**deps, **dev}.items():
            if isinstance(spec, str) and _NONREGISTRY.search(spec.strip()):
                signals.append(self._sig(
                    "Non-registry dependency source",
                    f"Dependency '{name}' resolves from a non-registry source "
                    f"({spec[:60]}), bypassing registry review.",
                    f"{name}={spec[:60]}", 0.55, 0.8))
        return signals

    def _scan_requirements(self, content: str, deny: set) -> list[Signal]:
        signals: list[Signal] = []
        names = []
        seen: set[str] = set()
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if _NONREGISTRY.search(line) or _PIP_SOURCE_OPTION.match(line):
                # One signal per distinct line. Identical signals each add weight, so twelve
                # copies of the same line once scored a harmless command a perfect 100.
                if line[:80] not in seen:
                    seen.add(line[:80])
                    signals.append(self._sig(
                        "Non-registry dependency source",
                        "A requirement resolves from a URL / VCS / local path, bypassing index review.",
                        line[:80], 0.55, 0.8))
                continue
            if line.startswith("-"):
                continue            # an option that names no source (--hash=…, --pre, ---)
            names.append(re.split(r"[<>=!~\[ ]", line, maxsplit=1)[0].strip())
        signals.extend(self._denylist_signals(((n, "") for n in names if n), deny))
        return signals

    def _denylist_signals(self, items, deny: set) -> list[Signal]:
        out = []
        for name, _spec in items:
            if isinstance(name, str) and name.strip().lower() in deny:
                out.append(self._sig(
                    "Known-bad dependency",
                    f"Dependency '{name}' is on the malicious/typosquat denylist.",
                    name, 0.95, 0.9))
        return out
