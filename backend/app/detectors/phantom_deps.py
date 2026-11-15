"""Phantom dependencies: the package a model suggests does not exist, or appeared last week.

Models invent package names, and people register them: a developer pastes the model's
`pip install` line and installs whatever squatted the name (slopsquatting). Nobody checks
this at the moment it matters, which is before the paste. Palivane sees both halves:
the provider's reply on its way back (surface ai_usage/llm_io, direction "response"), and
the install command the coding agent actually runs (agent_tools / mcp). Every install
line in either is parsed for its ecosystem and package names, each name is looked up
(registry_lookup: cached, SSRF-pinned, fail-open), and one of two signals is raised:

    the package does not exist          weight 0.8   the squat is open, or the name is fiction
    the package is younger than N days  weight 0.45  real, but too new to have earned trust

Well-known names skip the network. Nothing is raised when a registry cannot be asked.
"""
from __future__ import annotations

import re

from ..config import settings
from .base import AnalysisInput, Category, Signal, Surface

CHECK = "phantom_dependency"
_SHELL_TOOLS = {"bash", "shell", "run_command", "execute_command", "run_shell_command", "terminal",
                "execute", "run_terminal_cmd", "exec"}
FRESH_DAYS = 14
MAX_NAMES = 12

# Names that never need a lookup: the request budget is for the names nobody has heard of.
_WELL_KNOWN = {
    "pypi": {"requests", "numpy", "pandas", "flask", "django", "fastapi", "pytest", "boto3",
             "scipy", "sqlalchemy", "pydantic", "httpx", "uvicorn", "pillow", "matplotlib",
             "pyyaml", "click", "rich", "typer", "openai", "anthropic", "torch", "transformers",
             "black", "ruff", "mypy", "setuptools", "wheel", "pip", "poetry", "jinja2", "redis",
             "celery", "psycopg2", "psycopg2-binary", "cryptography", "paramiko", "aiohttp"},
    "npm": {"react", "react-dom", "next", "express", "lodash", "axios", "typescript", "vite",
            "eslint", "prettier", "jest", "vitest", "zod", "tailwindcss", "vue", "svelte",
            "webpack", "esbuild", "dotenv", "uuid", "moment", "dayjs", "chalk", "commander",
            "yargs", "playwright", "puppeteer", "openai", "@anthropic-ai/sdk", "ws", "cors",
            "body-parser", "mongoose", "pg", "prisma", "@prisma/client", "node-fetch"},
    "crates": {"serde", "tokio", "clap", "anyhow", "thiserror", "reqwest", "rand", "regex",
               "serde_json", "axum", "hyper", "tracing", "log", "chrono", "uuid"},
    "gem": {"rails", "rake", "rspec", "puma", "sinatra", "nokogiri", "devise", "sidekiq"},
    "go": set(),
}

# One install line -> (ecosystem, the text after the verb). Flags and versions are stripped
# from the tail by _names().
_INSTALL_RE = re.compile(
    r"(?im)^\s*(?:[$>]\s*)?(?:sudo\s+)?"
    r"(?:(?P<pip>(?:python3?\s+-m\s+)?(?:pip3?|pipx|uv\s+pip)\s+install|uv\s+add|poetry\s+add)"
    r"|(?P<npm>(?:npm\s+(?:i|install|add)|yarn\s+add|pnpm\s+(?:add|i|install)|npx|bunx|bun\s+add))"
    r"|(?P<crates>cargo\s+(?:add|install))"
    r"|(?P<gem>gem\s+install)"
    r"|(?P<go>go\s+(?:get|install)))"
    r"[ \t]+(?P<tail>[^\n]+)"
)
_PY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")
_NPM_NAME = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*")
_GENERIC = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")
_GO_NAME = re.compile(r"^[a-z0-9.-]+\.[a-z]+/[A-Za-z0-9._/-]+")


def _names(eco: str, tail: str) -> list[str]:
    out: list[str] = []
    for tok in tail.split():
        if tok.startswith("-") or tok in (".", "..") or tok.startswith(("./", "/", "~", "http:", "https:", "git+", "file:")):
            if tok in ("-r", "--requirement", "-e", "--editable"):
                break            # the rest names a file or a path, not a package
            continue
        if tok in ("&&", "||", ";", "|"):
            break
        tok = tok.strip("'\"`,")
        if eco == "pypi":
            m = _PY_NAME.match(tok)
            name = m.group(0).lower() if m else ""
            name = name.split("[")[0]
        elif eco == "npm":
            m = _NPM_NAME.match(tok)
            name = m.group(0) if m else ""
        elif eco == "go":
            m = _GO_NAME.match(tok)
            name = m.group(0).split("@")[0] if m else ""
        else:
            m = _GENERIC.match(tok)
            name = m.group(0).lower() if m else ""
        if name and name not in out:
            out.append(name)
    return out


def extract_installs(text: str) -> list[tuple[str, str, str]]:
    """[(ecosystem, package, the install line)] for every install command in `text`."""
    found: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for m in _INSTALL_RE.finditer(text or ""):
        eco = next(k for k in ("pip", "npm", "crates", "gem", "go") if m.group(k))
        eco = "pypi" if eco == "pip" else eco
        line = m.group(0).strip()
        for name in _names(eco, m.group("tail")):
            if (eco, name) in seen:
                continue
            seen.add((eco, name))
            found.append((eco, name, line[:160]))
            if len(found) >= MAX_NAMES:
                return found
    return found


class PhantomDepsDetector:
    """Registry-checks the packages a model suggests, or an agent is about to install."""

    name = "phantom_deps"
    surfaces: set[Surface] = {Surface.AI_USAGE, Surface.LLM_IO, Surface.AGENT_TOOLS, Surface.MCP}

    def _applies(self, item: AnalysisInput) -> bool:
        if not settings.phantom_deps_enabled:
            return False
        m = item.metadata or {}
        if item.surface in (Surface.AI_USAGE, Surface.LLM_IO):
            return m.get("direction") == "response"
        # A tool call: only a shell tool installs anything. Config scans and file edits that
        # happen to mention a package manager are other detectors' business.
        tool = str(m.get("tool") or "").lower()
        return bool(m.get("shell_command")) or tool in _SHELL_TOOLS

    def analyze(self, item: AnalysisInput) -> list[Signal]:
        if not self._applies(item):
            return []
        installs = extract_installs(item.content or "")
        if not installs:
            return []
        from .. import registry_lookup
        response = item.surface in (Surface.AI_USAGE, Surface.LLM_IO)
        out: list[Signal] = []
        for eco, pkg, line in installs:
            if pkg in _WELL_KNOWN.get(eco, ()):
                continue
            info = registry_lookup.lookup(eco, pkg)
            if info is None:
                continue
            missing = not info.get("exists")
            fresh = (not missing and info.get("age_days") is not None and info["age_days"] <= FRESH_DAYS)
            if not missing and not fresh:
                continue
            days = info.get("age_days")
            if missing:
                detail = (f"'{pkg}' is not on {eco}. A model-invented name is the slopsquatting "
                          f"target: whoever registers it first owns the install. Do not run this "
                          f"line as written.")
            else:
                detail = (f"'{pkg}' first appeared on {eco} {days} day{'s' if days != 1 else ''} ago. "
                          f"New names that models keep suggesting are where squatted packages "
                          f"live; verify the publisher before installing.")
            common = dict(category=Category.DEPENDENCY_RISK, detail=detail, detector=self.name,
                          evidence=line, check=CHECK,
                          weight=0.8 if missing else 0.45, confidence=0.9 if missing else 0.8)
            # Literal titles on purpose: frontend/scripts/gen-stats.mjs counts `title="..."`.
            if missing and response:
                out.append(Signal(title="Suggested package does not exist", **common))
            elif missing:
                out.append(Signal(title="Installing a package that does not exist", **common))
            elif response:
                out.append(Signal(title="Suggested package is brand new", **common))
            else:
                out.append(Signal(title="Installing a package published this week", **common))
        return out
