# Warden — Shadow-AI Guard · Privacy Policy

_Last updated: 2026-06-30_

Warden — Shadow-AI Guard ("the extension") is an organizational data-loss-prevention
tool. It is deployed by an administrator and connected to a **Warden backend that your
organization operates**. Host this policy at a public URL and reference it in the store
listing. Replace the contact line with your details.

## What the extension does

On the supported AI tools (claude.ai, chatgpt.com, chat.openai.com, gemini.google.com,
copilot.microsoft.com), the extension reads the text of a prompt **before it is sent** so
that it can be scanned for secrets, credentials, personal data, and proprietary content,
and then **warns or blocks** risky submissions.

## What data is processed

- **Prompt content** you submit to the supported AI tools — sent to your organization's
  Warden backend for scanning.
- **An optional user identifier** (e.g. your work email), if your administrator
  configures one, so findings can be attributed.
- **Configuration** (backend URL, access token, enforce flag) stored locally via the
  browser's extension storage / enterprise managed policy.

## Where data goes

Scanned content is transmitted **only** to the Warden backend endpoint your organization
configures (`POST /api/ingest/ai-usage`). It is **not** transmitted to the extension's
developer, and it is **not** sold, shared, or used for advertising or any purpose
unrelated to the security scan.

## Retention

The extension itself stores no prompt history; it relays content for a real-time verdict
and discards it. Any retention of findings happens in your organization's Warden backend,
governed by your organization's own data policy.

## Failure behavior

The extension **fails open**: if the backend is unreachable or misconfigured, prompts are
sent to the AI tool untouched and no data is captured.

## Contact

Questions about this policy: **<your-security-team@example.com>**.
</content>
