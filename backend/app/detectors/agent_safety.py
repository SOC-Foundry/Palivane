"""Agent-safety detector: coding-assistant autonomy risk.

Two checks, both aimed at AI coding tools (Cursor, Claude Code, aider, Copilot agents):

  - YOLO / auto-apply modes ('yolo_mode') — settings or CLI flags that let the agent run
    commands or apply edits WITHOUT user confirmation (Cursor's autoRun / autoFix /
    shouldAutoApplyIfNoEditTool / "YOLO mode", MCP autoApprove, --dangerously-skip-
    permissions, --yolo, aider --yes). Scanned from an IDE/agent config blob.

  - Cursor chat analysis ('cursor_chat') — destructive or dangerous commands appearing in
    an AI chat transcript / generated code block (rm -rf /, curl | sh, reverse shells,
    disabling security), so a risky suggestion is caught before a developer runs it.

Both are independently togglable in the Policies console via the Signal `check` key. Runs on
the IDE surface (config scans) and the AI_USAGE / MCP surfaces (chat capture), self-gating
the chat analysis to coding tools so it doesn't fire on ordinary chat.
"""

from __future__ import annotations

import re

from .base import AnalysisInput, Category, Signal, Surface

# Dangerous autonomy settings/flags — Cursor, MCP clients, and agent CLIs. `yolo` matches
# inside camelCase keys too (e.g. enableYoloMode), so no word boundary on it.
_YOLO = re.compile(
    r"yolo"                                                  # "YOLO mode" / enableYoloMode
    r"|shouldAutoApplyIfNoEditTool"                          # Cursor composer auto-apply
    r"|auto[_-]?run|auto[_-]?fix|auto[_-]?apply|auto[_-]?accept"
    r"|autoApprove|auto[_-]?execute|autoConfirm"            # MCP / agent auto-approve
    r"|dangerously[_-]?skip[_-]?permissions"                 # claude-code --dangerously-skip-permissions
    r"|--yes-always|acceptAllEdits",
    re.IGNORECASE,
)
# In a settings blob, skip a match whose value is explicitly OFF (…: false / = disabled).
_YOLO_OFF = re.compile(r"\b(false|off|disabled|no|0)\b", re.IGNORECASE)

# Destructive / dangerous commands in generated code or chat (shared spirit with mcp_guard).
_DANGEROUS_CMD = re.compile(
    r"(?:curl|wget)\s+[^\n|;&]*\|\s*(?:sudo\s+)?(?:ba)?sh"     # curl … | sh
    r"|base64\s+-d[^\n|]*\|\s*(?:ba)?sh"                        # base64 -d | sh
    r"|rm\s+-rf\s+(?:/|~|\$HOME|\*|--no-preserve-root)"        # rm -rf /
    r"|nc\s+-e|/dev/tcp/|bash\s+-i\s*>&"                        # reverse shells
    r"|mkfs\.|dd\s+if=/dev/(?:zero|random)\s+of=/dev/"         # wipe a disk
    r"|chmod\s+(?:-R\s+)?0?777"                                 # world-writable
    r"|:\(\)\s*\{.*\};:"                                        # fork bomb
    r"|(?:disable|stop)\s+(?:firewall|defender|selinux|auditd)" # disable security
    r"|git\s+push\s+(?:-f|--force)\s+.*(?:main|master)",       # force-push protected branch
    re.IGNORECASE,
)

_CODING_TOOLS = ("cursor", "claude-code", "claude code", "copilot", "codeium",
                 "windsurf", "aider", "cline", "continue", "gemini-cli")


def _is_config(item: AnalysisInput) -> bool:
    ch = (item.channel or "").lower()
    return "config" in ch or (item.metadata or {}).get("kind") == "agent_config"


def _is_coding_tool(item: AnalysisInput) -> bool:
    ch = (item.channel or "").lower()
    tool = str((item.metadata or {}).get("tool") or "").lower()
    return any(t in ch or t in tool for t in _CODING_TOOLS)


class AgentSafetyDetector:
    name = "agent_safety"
    surfaces = {Surface.IDE, Surface.AI_USAGE, Surface.MCP}

    def analyze(self, item: AnalysisInput) -> list[Signal]:
        text = f"{item.subject}\n{item.content}"
        signals: list[Signal] = []

        # --- YOLO / auto-apply: config scans, or explicit enable in any coding context ---
        if _is_config(item) or _is_coding_tool(item):
            for m in _YOLO.finditer(text):
                # In a settings blob, skip a setting explicitly turned OFF; a bare CLI flag
                # (no value following) still counts as enabled.
                if _is_config(item) and _YOLO_OFF.search(text[m.end():m.end() + 30]):
                    continue
                signals.append(Signal(
                    category=Category.UNSAFE_AUTONOMY,
                    title="Unsafe agent autonomy (YOLO / auto-apply)",
                    detail="A coding agent is configured to run commands or apply edits without "
                           "user confirmation — a single bad suggestion can execute unchecked.",
                    weight=0.7, confidence=0.8, detector=self.name,
                    evidence=m.group(0), check="yolo_mode",
                ))
                break  # one is enough

        # --- Cursor chat analysis: dangerous commands in a chat / generated code block ---
        if _is_coding_tool(item) and not _is_config(item):
            dm = _DANGEROUS_CMD.search(text)
            if dm:
                signals.append(Signal(
                    category=Category.DANGEROUS_COMMAND,
                    title="Dangerous command in AI coding chat",
                    detail="The AI chat or its generated code contains a destructive/high-risk "
                           "command — review before running.",
                    weight=0.75, confidence=0.75, detector=self.name,
                    evidence=dm.group(0)[:80], check="cursor_chat",
                ))

        return signals
