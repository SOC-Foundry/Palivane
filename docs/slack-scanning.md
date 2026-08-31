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

Only formats whose bytes are their text are read: CSV, TSV, JSON, YAML, logs, source,
Markdown, plain text. **PDFs, Office documents, and images are not scanned** — those need a
parser and an OCR engine respectively. They are counted in the sync summary as
`files_skipped` rather than passed over silently, so "clean" never quietly means "did not
look".

## What a scan does

Each scan pulls messages since the last cursor; the first reaches back seven days. Runs are
bounded (2,000 messages and 25 MB of attachments per sync) and resume where they stopped, so
a large backlog drains over several runs rather than in one long request.

## What it does not do

**Detection only, for now.** Nothing is blocked, redacted, or deleted by the bot.

Some of that is Slack's design, not ours, and it is worth being precise about which parts:

| | Below Enterprise Grid | Enterprise Grid |
| --- | --- | --- |
| Read public channels | yes | yes |
| Read private channels / DMs uninvited | **no** | yes (Discovery API) |
| Block before delivery | **no** | yes |
| Edit someone else's message in place | **no** | yes (`discovery:write`) |
| Delete someone else's message | possible, with an admin user token | yes |

`chat.update` refuses to touch a message the caller did not author, on every plan — so
"redact the SSN and leave the sentence" is genuinely Grid-only. Deletion is the one
remediation reachable below Grid, and only with a workspace-admin **user** token, which is
a much stronger credential than the bot token and is treated separately.

If you are on Enterprise Grid and want in-place redaction or tombstoning, that is a
different integration (Discovery API, org-owner install, Slack DLP-partner approval) and we
will scope it with you.
