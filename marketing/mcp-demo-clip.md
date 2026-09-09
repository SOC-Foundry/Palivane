# MCP demo clip — Product Hunt gallery

A ~45s screen recording of **Claude Desktop** with the Palivane MCP server connected,
asking plain-English questions and getting real answers + actions. Shows the "govern AI
security from your assistant" story. 1920×1080, **captioned** (PH autoplays muted), loopable.

Title + closing cards: `marketing/mcp-demo-cards.html` (open in a browser, screenshot each
frame, or drop into your editor as the first/last frames).

## Shot list

| # | Time | On screen | Prompt to type | What viewers see | Caption overlay |
|---|------|-----------|----------------|------------------|-----------------|
| 0 | 0:00–0:03 | Title card | — | Fade in | **"What if you never had to open the security dashboard?"** |
| 1 | 0:03–0:07 | Claude Desktop, Palivane MCP connected | — | The 🔌 "palivane" server + its tools | *"Palivane, connected to Claude over MCP"* |
| 2 | 0:07–0:16 | Chat | `What high-severity Palivane findings landed today, and who triggered them?` | `list_findings` → tidy list (actor · surface · severity) | *"Ask. No login."* |
| 3 | 0:16–0:26 | Chat | `Which unsanctioned AI tools are people using, and what data leaked to them?` | `ai_tool_inventory` → tools + exposure by team | *"Shadow-AI inventory, in chat"* |
| 4 | 0:26–0:35 | Chat | `Mark finding 4821 as triaged.` | `set_finding_status` → confirms (dismiss stays admin-only) | *"Work the queue from the assistant"* |
| 5 | 0:35–0:42 | Chat | `Are we covered for the OWASP LLM Top 10? Show the gaps.` | `compliance_report` → covered / partial / gap | *"Even the compliance answer"* |
| 6 | 0:42–0:45 | Closing card | — | Logo | **"Palivane — AI security you run from your assistant." palivane.io · PHLAUNCH30** |

## Rehearsal prompt sequence

```
What high-severity Palivane findings landed today, and who triggered them?
Which unsanctioned AI tools are people using, and what data leaked to them?
Mark finding 4821 as triaged.
Are we covered for the OWASP LLM Top 10? Show the gaps.
```

## Production notes

- **Use a dedicated demo/test tenant with seeded findings — NOT the public read-only demo
  org** (that one blocks writes, so "mark triaged" in shot 4 won't execute on camera). Any
  trial org with the demo seed works; grab its admin token for `PALIVANE_API_TOKEN`.
- Pre-seed so the finding id you say out loud (e.g. `4821`) actually exists — rehearse once,
  note the real id, then record.
- Prime Claude to answer tersely ("one short line per finding") so panels don't sprawl.
- Silent-first: burn in the captions; music optional. Trim the tool-call "thinking" pauses
  in the edit so it stays snappy.
- Optional 3s B-roll: the `claude mcp add palivane …` one-liner from the mcp-server README —
  reinforces "two minutes to wire in."
- Setup: `github.com/SOC-Foundry/palivane-clients/tree/main/mcp-server`.
