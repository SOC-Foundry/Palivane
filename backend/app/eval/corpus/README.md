# Evaluation corpus

One `*.jsonl` file per surface; one labeled example per line. The bundled files are a
small, synthetic seed set — **design partners add their own `.jsonl` files here** to
evaluate and tune detection against their real traffic (no code changes needed).

## Schema

```json
{"id": "p01", "surface": "llm_io", "label": "malicious",
 "sender": "...", "subject": "...", "content": "...",
 "destination": "https://chat.openai.com/",
 "expect_categories": ["phishing"], "note": "why it's labeled this way"}
```

- `surface` — `llm_io` | `ai_usage`
- `label` — `malicious` (a finding that *should* be flagged) or `benign`
- `destination` — `ai_usage` only; maps to the egress target
- `expect_categories` — optional; the signal categories you'd expect to fire
- `id` — unique across all files

## Labeling convention

Label by **"is this a finding worth flagging?"**, not "is anything notable here":

- A benign request that happens to go to an *unsanctioned* AI tool with **no sensitive
  data** is low-risk policy noise → `benign`. (Tune the operating cutoff lower if your
  policy treats any unsanctioned use as reportable.)
- An AI-written but harmless newsletter is `benign` — AI-generation alone is not a threat.
