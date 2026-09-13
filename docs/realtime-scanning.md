# Real-time & on-write scanning

The cron pull is the safety net; these paths shrink detection from minutes-to-hours to
seconds. Each degrades honestly back to pull-only when its prerequisite is missing.

| Surface | Mechanism | Prerequisite |
|---|---|---|
| Slack messages | Events API push to `/api/slack/events` | App **signing secret** set on the deployment (`PALIVANE_SLACK_SIGNING_SECRET`) + event subscriptions `message.channels`, `message.groups` on your Slack app |
| SharePoint/OneDrive | Graph change subscriptions → `/api/webhooks/graph` | Deployment has a public URL; subscriptions are created/renewed automatically by each sync (28-day lifetime) |
| Google Drive | `changes.watch` channel → `/api/webhooks/gdrive` | Public URL; channel renewed by each sync. Drive caps channels at ~a day, so infrequent syncs mean realtime can lapse to pull-only between them (the sync summary says so: `watch_errors`) |

All three receivers authenticate the push (Slack request signatures; signed
clientState/channel tokens for Graph/Drive), debounce bursts, and run the same detection
the pull path runs, so findings, alerting, and SIEM export are identical. Sync summaries
surface subscription/channel failures (`subs_errors`, `watch_errors`) because a realtime
path that silently stopped is worse than not having one.
