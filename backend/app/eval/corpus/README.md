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

- `surface` — any detection surface: `llm_io` | `ai_usage` | `agent_rules` (rules-file
  backdoors — CLAUDE.md/.cursorrules/skills) | `mcp` | `ide` | … (`--surface` accepts all)
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
- An ordinary rules file that *mentions* secrets, tools, or "do not X" is `benign`; only a
  concealed/exfil/hide-from-user/tool-poisoning directive is a rules-file backdoor.

## Stateful detectors

Single-event scoring runs via `python -m app.eval`. **Session behavioral correlation** is
cross-event (an attack *chain*), so it has its own labeled sequence set and runner:

```
python -m app.eval.sequences            # per-scenario chain-detection precision/recall
```
