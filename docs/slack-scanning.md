# Slack scanning

Palivane scans Slack **message content** for secrets, PII, and PHI using the same detection
engine as every other plane. Findings land on the `collab` surface with the usual alerting
and SIEM export.

The reason to care isn't Slack itself: Slack AI, workspace bots, and MCP servers can read
whatever sits in your channels. A regulated record pasted into `#support` two years ago
becomes training-adjacent context the moment an AI rollout indexes the workspace. This
finds it first.

## Two ways to connect

**One-click ("Add to Slack").** Available only when the operator of your Palivane
deployment has registered a published Slack app. If Settings shows the button, use it: you
approve the read scopes in your own workspace and the bot token is stored for you.

**Your own workspace app.** Always available, and the only route on a deployment with no
published app. Ten minutes, once.

## Creating your own Slack app

1. Go to `api.slack.com/apps` → **Create New App** → **From scratch**. Name it whatever
   your workspace will recognise; pick the workspace to install into.
2. **OAuth & Permissions** → **Bot Token Scopes**, add exactly these six:

   | Scope | Why |
   | --- | --- |
   | `channels:read` | list public channels |
   | `groups:read` | list private channels the bot is in |
   | `channels:history` | read public channel messages |
   | `groups:history` | read private channel messages |
   | `users:read` | attribute a message to a person |
   | `users:read.email` | match that person to a Palivane user |
   | `files:read` | read text attachments (CSV, JSON, logs, source) |
   | `channels:join` | optional; lets the bot cover public channels nobody invited it to |

   No write scopes. The bot never posts, edits, or deletes anything.
3. **Install to Workspace**, approve, and copy the **Bot User OAuth Token** (`xoxb-…`).
4. In Palivane: **Settings → Slack scanning**, add the token as a `slack_messages`
   connector.
5. **Invite the bot to the channels you want scanned** (`/invite @yourapp`), or turn on
   "Scan every public channel" below and skip this for public ones. A bot token can only
   read history for conversations the bot is a member of. A channel nobody invited it to is
   invisible, and that is the most common reason a scan comes back emptier than expected.

## Covering every public channel

**Settings → Slack scanning → "Scan every public channel"** enumerates the workspace's
public channels and joins the ones the bot is missing, so coverage stops depending on
somebody remembering to invite a bot.

Two things to know before you turn it on:

- **Joining is visible.** Each join posts the usual "joined the channel" line. That is why
  it is off by default; on a large workspace, turning it on is a noticeable event.
- **It cannot reach private channels or DMs.** No bot scope opens a private conversation.
  Private coverage is exactly what somebody invited the bot to, whatever this setting says.

## Attachments

Files shared in a scanned channel are scanned too, and get their own finding named after
the file, so triage points at the thing to delete rather than at the message beside it.

Three tiers, depending on what the file needs:

| Tier | Formats | Notes |
| --- | --- | --- |
| text | CSV, TSV, JSON, YAML, logs, source, Markdown, plain text | read directly |
| document | **PDF, Word, Excel, PowerPoint** (`.docx/.xlsx/.pptx`) | text pulled out of the container; no layout, which is all a scanner needs |
| ocr | **PNG, JPEG, GIF, WebP, TIFF** | only when OCR is enabled on the deployment (`PALIVANE_OCR=true`, needs Pillow + tesseract). Runs locally; no image is ever sent to a vision API |

What still cannot be opened: pre-2007 Office (`.doc/.xls/.ppt`, a binary OLE container),
encrypted PDFs, and images when OCR is off. Those are counted in the sync summary as
`files_skipped` rather than passed over silently, so "clean" never quietly means "did not
look".

## What a scan does

Each scan pulls messages since the last cursor; the first reaches back seven days. Runs are
bounded (2,000 messages and 25 MB of attachments per sync) and resume where they stopped, so
a large backlog drains over several runs rather than in one long request.

## What it does not do

**Nothing is blocked before delivery, and nothing is edited.** One remediation is
available, and only on Enterprise: deletion.

Some of the rest is Slack's design, not ours, and it is worth being precise about which:

| | Below Enterprise Grid | Enterprise Grid |
| --- | --- | --- |
| Read public channels | yes | yes |
| Read private channels / DMs uninvited | **no** | yes (Discovery API) |
| Block before delivery | **no** | yes |
| Edit someone else's message in place | **no** | yes (`discovery:write`) |
| Delete someone else's message | **yes**, with an admin user token (below) | yes |

`chat.update` refuses to touch a message the caller did not author, on every plan, so
"redact the SSN and leave the sentence" is genuinely Grid-only. Deletion is the one
remediation reachable below Grid, and only with a workspace-admin **user** token, which is
a much stronger credential than the bot token and is treated separately.

## Deleting a confirmed leak (Enterprise)

**Settings → Slack scanning → "Delete confirmed leaks"** removes a message the scan has
just flagged at high or critical from the workspace.

What it needs, and why:

- **A workspace-admin user token** (`xoxp-…`) on the connector, alongside the bot token.
  `chat.delete` with a bot token can remove nothing but the bot's own posts, so there is no
  version of this that runs on the bot token alone. This is a much stronger credential than
  the bot token: it can do anything its owner can. It is stored encrypted, write-only, and
  never returned by the API.
- **The Enterprise plan.** This destroys customer content, so it sits behind a deliberate
  conversation rather than a checkbox a trial finds by accident.
- **The switch, off by default.**

What it will and will not touch:

- Only a message **this scan flagged**, at **high or critical**: the confirmed-leak tier.
  A suspicious-but-unconfirmed hit is recorded, never deleted.
- **Every deletion is written to the audit log first** (`slack.message_deleted`), with the
  finding id, severity, channel, and who posted it. A message removed with no record of
  what it was is worse than the leak it removed.
- A deletion that fails is recorded too (`slack.message_delete_failed`) and counted in the
  sync summary, because remediation that quietly stopped working looks exactly like a
  workspace with nothing left to remediate.

It is deletion, not redaction. Slack will not let any caller edit a message it did not
author, on any plan, so "mask the SSN and leave the sentence" is genuinely Grid-only. If you
are on Enterprise Grid and want in-place redaction or tombstoning, that is a different
integration (Discovery API with discovery:write, org-owner install) and we will scope it with you.

## Private channels & DMs on Enterprise Grid (Discovery API)

A bot token only sees channels the bot is in: private channels must invite it, and DMs
are invisible. On **Enterprise Grid** you can cover everything with the **Slack Discovery
connector**, and it's your own key, so **no Palivane Slack app is involved**:

1. Your **Org Owner** enables the Discovery API for the org (email `exports@slack.com`;
   Slack turns it on after confirming the requester is an Org Owner).
2. The Org Owner creates an **internal** Slack app in your org (or reuses one) with the
   `discovery:read` scope and installs it **org-wide**. On Grid, admin/Discovery-scoped
   apps installed at the org level reach every workspace without being added to each.
3. Paste that token into Palivane as a **`slack_discovery`** connector.

Palivane then reads every conversation org-wide (public, private, DMs, group DMs),
watermark-incremental per conversation, on the `collab` surface. Read-only (no deletion;
that needs `discovery:write`). Use it **instead of** the bot-token connector on Grid.

This is built and unit-tested against the Discovery API's documented shape but not yet
verified against a live Grid org, so pilot it before you rely on it, and tell us what the
real API returns so we can lock it in.
