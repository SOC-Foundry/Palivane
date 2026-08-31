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

   No write scopes. The bot never posts, edits, or deletes anything.
3. **Install to Workspace**, approve, and copy the **Bot User OAuth Token** (`xoxb-…`).
4. In Palivane: **Settings → Slack scanning**, add the token as a `slack_messages`
   connector.
5. **Invite the bot to every channel you want scanned** (`/invite @yourapp`). This is a
   Slack rule, not a Palivane one: a bot token can only read history for conversations the
   bot is a member of. A channel nobody invited it to is invisible, and that is the most
   common reason a scan comes back emptier than expected.

## What a scan does

Each scan pulls messages since the last cursor; the first reaches back seven days. Runs are
bounded (2,000 messages per sync) and resume where they stopped, so a large backlog drains
over several runs rather than in one long request.

## What it does not do

**Detection only.** Nothing is blocked, redacted, or deleted. That isn't a roadmap gap so
much as a Slack one: pre-delivery inspection and message tombstoning live behind the
Discovery API, which Slack restricts to Enterprise Grid. On Free, Pro, and Business+, a bot
token can read history and nothing more — every DLP vendor on those plans is detecting
after the fact, whatever the marketing says.

If you are on Enterprise Grid and want tombstoning, say so; that is a different integration
(Discovery API, org-owner install, different scopes) and we will scope it.
