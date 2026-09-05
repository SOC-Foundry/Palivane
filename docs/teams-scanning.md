# Microsoft Teams message scanning

Palivane scans Teams channel messages (and, opt-in, named users' chats) for secrets, PII/
PHI, and confidential content — agentless, via Microsoft Graph. Findings land on the
`collab` surface with the team/channel as the subject.

## One-time Microsoft setup

1. **App registration** (or reuse the one your other Microsoft connectors use):
   Entra ID → App registrations → New. Create a **client secret**.
2. **Application permissions** (Graph → Application, then **Grant admin consent**):
   `ChannelMessage.Read.All`, `Group.Read.All`, `Channel.ReadBasic.All`, `User.Read.All`
   (+ `Chat.Read.All` only if you'll scan 1:1/group chats).
3. **Protected-API approval** — the one step people miss. `ChannelMessage.Read.All`
   (and `Chat.Read.All`) are Microsoft *protected APIs*: submit the
   [request form](https://aka.ms/teamsgraph/requestaccess) once for your app id.
   Until it's approved, syncs fail with 403 and the connector shows the error —
   that's Microsoft gating, not a Palivane misconfiguration.

## In Palivane

Settings → Discovery connectors → **Microsoft Teams message scanning** → tenant id,
client id, client secret → Save, then Sync. First sync looks back 7 days; after that each
sync is delta-incremental per channel and pulls thread replies for roots in the window.

- **Chats (optional, metered):** add a `chat_users` credential entry (comma-separated
  UPNs) and a `chat_model` of `A` or `B` per your Microsoft licensing. Without a model,
  Graph runs in evaluation mode with a low monthly message cap.
- **Files shared in Teams** live in SharePoint/OneDrive — pair with the *SharePoint /
  OneDrive scanning* connector to cover them (it also scans on write).
- A reply to a thread whose root left the sync window is only seen when that root
  changes again — stated here because we'd rather you know the boundary than assume
  coverage that isn't there.
