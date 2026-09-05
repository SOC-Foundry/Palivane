# Email scanning (Gmail & Outlook sent mail)

Outbound email is where data actually leaves the org, so Palivane scans each user's
**sent** mail — body plus text attachments — on the `collab` surface. Detection only:
nothing is quarantined or recalled.

## Gmail (Google Workspace)

Reuses the same service account + domain-wide delegation as the Drive/Workspace
connectors:

1. Service account (Cloud Console) with a JSON key; enable the Gmail API in its project.
2. Admin Console → Security → API controls → **Domain-wide delegation** → add the
   service account's client id with scopes:
   `https://www.googleapis.com/auth/admin.directory.user.readonly`,
   `https://www.googleapis.com/auth/gmail.readonly`
3. Palivane: Settings → connectors → **Gmail sent-mail scanning** → paste the JSON key +
   an admin email (used only for the directory read). Sync.

Watermarks are per mailbox (first sync looks back 7 days). A mailbox the delegation can't
open (suspended user, missing scope) is counted in `mail_errors` — visible in the sync
summary rather than silently skipped.

## Outlook / Exchange Online

Reuses the Entra app registration your other Microsoft connectors use:

1. Application permissions `Mail.Read` + `User.Read.All`, admin-consented. (Not protected
   APIs — no Microsoft form needed, unlike Teams.)
2. Palivane: Settings → connectors → **Outlook sent-mail scanning** → tenant id, client
   id, client secret. Sync.

Same semantics as Gmail: per-mailbox watermarks on `sentDateTime`, text attachments under
a per-sync byte budget, binary/oversize attachments counted as skipped (never assumed
clean), unlicensed mailboxes in `mail_errors`.

**Scoping tip:** application `Mail.Read` grants tenant-wide mailbox read. If your security
review wants it narrower, use an Exchange **application access policy**
(`New-ApplicationAccessPolicy`) to restrict the app to a mail-enabled security group —
Palivane then scans only those mailboxes and counts the rest in `mail_errors`.
