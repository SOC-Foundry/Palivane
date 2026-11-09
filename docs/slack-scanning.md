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
approve the scopes in your own workspace and the bot token is stored for you. The app asks
for the same scopes as the table below, `channels:join`, `chat:write` and `im:write` included;
it only joins channels if you turn on "Scan every public channel", and only posts if you turn on
"Notify the sender".

**Your own workspace app.** Always available, and the only route on a deployment with no
published app. Ten minutes, once.

## Creating your own Slack app

1. Go to `api.slack.com/apps` → **Create New App** → **From scratch**. Name it whatever
   your workspace will recognise; pick the workspace to install into.
2. **OAuth & Permissions** → **Bot Token Scopes**, add these:

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
   | `chat:write`, `im:write` | optional; "Notify the sender" (a private message to the person who posted a leak) |

   The bot never edits or deletes anything. With the notify scopes it posts one kind of
   message: a private notice to the person whose message was flagged.
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

**Nothing is blocked before delivery.** Slack offers no pre-delivery inspection point below
Enterprise Grid, so this plane finds a leak after it lands and then acts on it (below).

Some of the rest is Slack's design, not ours, and it is worth being precise about which:

| | Below Enterprise Grid | Enterprise Grid |
| --- | --- | --- |
| Read public channels | yes | yes |
| Read private channels / DMs uninvited | **no** | yes (Discovery API) |
| Block before delivery | **no** | yes |
| Edit someone else's message in place (redact) | **no** | yes, through the Discovery API |
| Delete someone else's message | **yes**, with a workspace-admin user token | yes |
| Message the person who posted it | yes (the bot) | yes |

## Acting on a confirmed leak

**Settings → Slack scanning**, per workspace. Each action is off by default and runs only on
a message the scan has just flagged at **high or critical** (the confirmed-leak tier); a
suspicious-but-unconfirmed hit is recorded and nothing else.

| Action | What happens | Needs |
| --- | --- | --- |
| **Notify the sender** | The Palivane bot sends the person who posted it a private message naming what was found (never the value) and what happened to their message, with a reminder to rotate a credential | the bot's `chat:write` and `im:write` scopes; any plan |
| **Redact the values** | The flagged values are replaced with `«redacted:<label>»`; the rest of the message stays | **Enterprise Grid** with Slack's Discovery API enabled and a Slack Discovery connector; Enterprise plan. Provisional: verified with the first Grid org |
| **Delete the message** | The message is removed | a workspace-admin user token; any Slack plan; Enterprise plan |
| **Alert the security team** | The bot posts the leak to your alert channel, with buttons for the actions above | an alert channel; the Slack app's Interactivity URL (below) |

How they combine: with redaction and deletion both on, a message is redacted, and deleted
only when redaction could not be done (no Discovery API, Slack refused the edit, or the
value is visible only after decoding, so there is no exact stretch of text to replace).

**Why redaction needs the Discovery API.** Slack's normal API lets nobody, admins included,
edit a message they did not post, on any plan. The one route is the Discovery API: Enterprise
Grid only, enabled by the org owner, and limited by Slack to security and compliance apps.
Palivane uses the token of the org's Slack Discovery connector (the one that already reads
private channels and DMs org-wide) for the edit. The sender's notice says which happened, or asks them to delete it when neither
ran.

**Alerts with buttons.** Set an **alert channel** and the bot posts every confirmed leak there:
what was found, where, who posted it, what has already been done, a link to the finding, and a
button for each action not yet taken (**Redact**, **Delete**, **Notify sender**, **Dismiss as
false positive**). A click is checked three ways before anything happens: Slack's request
signature, the button's own signature (it names the exact message, so it cannot be pointed at
another one), and that the person who clicked is a **Palivane admin** of the organization,
matched by their Slack email. Anyone else gets a private "only a Palivane admin can do this".
The alert is then updated to say who did what, and the action is audit-logged under that
admin's own address. The message text is read back from Slack at click time; Palivane does
not store it.

To enable the buttons, the Slack app needs one setting: **Interactivity & Shortcuts →
Interactivity on, Request URL `https://<your Palivane host>/api/slack/interactions`**. The bot
joins a public alert channel by itself; invite it to a private one.

**The admin token.** `chat.delete` with a bot token removes nothing but the bot's own posts,
so deletion uses a workspace admin's **user** token (`xoxp-…`),
added under the workspace's remediation switches. It is a much stronger credential than
the bot token (it can do anything its owner can): stored encrypted, write-only, never
returned by the API, and setting or removing it is written to the audit log.

**The record.** Every action is written to the audit log **before** it is reported, whether
it worked or not (`slack.message_redacted`, `slack.message_deleted`, `slack.sender_notified`
and their `…_failed` twins), with the finding id, severity, channel, and who posted it.
Failures are also counted in the scan summary, because remediation that quietly stopped
working looks exactly like a workspace with nothing left to fix.

Files are not redacted (a message's attachment is deleted with its message, or the sender is
notified). Shared channels owned by another organization's workspace cannot be changed from
yours.

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
