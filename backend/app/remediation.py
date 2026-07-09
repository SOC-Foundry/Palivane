"""Actionable 'how to fix' steps derived from a verdict's signals.

Single source of truth for remediation guidance, surfaced wherever a developer meets a
finding: the Cursor hook's in-IDE message, the browser-extension block modal, and the
capture-plane API responses. `signals` is the list of signal dicts from a verdict
(category / title / detail / evidence), so this works on the API payload directly.
"""

from __future__ import annotations


def remediation_for(signals: list[dict]) -> list[str]:
    cats = {s.get("category", "") for s in (signals or [])}
    ev = " ".join(str(s.get(k, "")) for s in (signals or [])
                  for k in ("evidence", "title", "detail")).lower()
    steps: list[str] = []

    if "secret_leak" in cats or "credential_at_rest" in cats:
        if "verified live" in ev:
            steps.append("This credential is CONFIRMED LIVE — rotate it now and assume it is compromised.")
        if "github" in ev:
            steps.append("Revoke the token at github.com/settings/tokens and issue a fine-grained, expiring PAT.")
        if "aws" in ev:
            steps.append("Deactivate the AWS access key in IAM and switch to short-lived creds (SSO/STS).")
        if "private key block" in ev or "-----begin" in ev or "id_rsa" in ev or "pem" in ev:
            steps.append("Rotate the key pair and remove the private key from the message/file; use an agent or keychain.")
        if not any("rotate" in s.lower() or "revoke" in s.lower() for s in steps):
            steps.append("Remove the secret, rotate it, and store it in a secret manager — never paste it into an AI tool.")
    if "pii_exposure" in cats:
        steps.append("Redact the personal data before sending; for regulated data use only an approved, contracted tool.")
    if "source_code_leak" in cats or "confidential_data" in cats:
        steps.append("Share only what's needed; for confidential/classified material use an approved AI tool, not a consumer one.")
    if "unsanctioned_ai" in cats:
        steps.append("Switch to one of your org's sanctioned AI tools (see the block screen) for this content.")
    if "prompt_injection" in cats or "jailbreak" in cats or "data_exfiltration" in cats:
        steps.append("Treat this input as untrusted — don't let it override instructions; strip or quote the injected text.")
    if "hidden_characters" in cats:
        steps.append("Remove hidden/zero-width characters (paste as plain text) — they're a known prompt-smuggling vector.")
    if "unsafe_autonomy" in cats:
        steps.append("Turn off the agent's auto-run / auto-apply (YOLO) setting and require confirmation before it acts.")
    if "dangerous_command" in cats:
        steps.append("Do NOT run the suggested command — review it; a destructive/high-risk shell action was detected.")
    if "tool_poisoning" in cats or "mcp_untrusted_server" in cats or "sensitive_resource_access" in cats:
        steps.append("Restrict or remove this MCP server; add only trusted servers to the allowlist and confirm nothing ran.")
    if "dependency_risk" in cats:
        if "osv" in ev or "advisory" in ev:
            steps.append("Upgrade the flagged dependency to a patched version (see the advisory IDs).")
        if "unpinned" in ev:
            steps.append("Pin the MCP server package to an exact version so you don't run whatever the registry serves.")
        if not steps or steps[-1].startswith("Pin") is False and "osv" not in ev and "unpinned" not in ev:
            steps.append("Remove or replace the risky dependency; prefer registry sources and pinned versions.")
    if "data_oversharing" in cats:
        steps.append("Restrict the source data's permissions at the origin so the LLM can't return it to unauthorized users; verify the need-to-know rule.")

    # De-dupe preserving order.
    seen: set[str] = set()
    return [s for s in steps if not (s in seen or seen.add(s))]
