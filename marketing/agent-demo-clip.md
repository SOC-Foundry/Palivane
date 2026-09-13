# Agent-suite demo clip — gallery

A ~27s rendered clip for **Palivane's agent features**: the read-only **analyst** that
investigates a finding and recommends an action, **agent attestation** (only workload-identity
agents act — the rest are flagged or blocked), and the **A2A flow graph** (which agent fed
which, and where risk crossed the hop). 1920×1080, **captioned** (galleries autoplay muted),
loopable, lofi soundtrack baked in.

Rendered by `scripts/agent_video.py` (picture) + `scripts/agent_score.py` (sound) — same
technique and sonic family as the hero / setup / MCP clips. The field names, action verbs,
and result shapes are the real ones (`app/analyst.py` `InvestigationReport`, the
`agent_attestation` signal in `app/main.py`, `app/agent_graph.py`); the frame around them is
drawn, not a live screen capture.

Title + closing stills: `marketing/agent-title-card.png`, `marketing/agent-end-card.png`.

## Shot list

| # | Time | Scene | What viewers see | Caption overlay |
|---|------|-------|------------------|-----------------|
| 0 | 0:00–0:03 | Title card | Fade in | **"Your agents are taking actions. Which ones should you worry about?"** |
| 1 | 0:03–0:08 | The analyst · read-only | A CRIT finding (agent leaked an AWS key to an external MCP tool) → the analyst report builds: summary, assessment, related activity, **recommended action** (`keep_open`) + confidence 0.86 | *"The analyst reads the context and recommends."* |
| 2 | 0:08–0:14 | Agent identity · attestation | `deploy-bot` (OIDC-attested) → **ALLOW**; `billing-reconciler` (ag_ bearer, not attested) → **BLOCK**; enforcement note | *"Attested agents act. The rest are blocked."* |
| 3 | 0:14–0:19 | Agent-to-agent · flow graph | Directed flows: research-agent→summarizer (HIGH pii_exposure), billing-reconciler→external MCP (CRIT secret_leak), planner→deploy-bot (benign), each with message counts | *"See every hop — and where risk crossed."* |
| 4 | 0:19–0:27 | Closing card | Logo | **"Palivane — AI security for the agent era." palivane.io · PHLAUNCH30** |

## Regenerate

```bash
# picture (needs playwright + chromium)
backend/.venv/bin/python scripts/agent_video.py            # -> marketing/agent-demo.mp4 (silent)

# sound (needs numpy + scipy)
backend/.venv/bin/python scripts/agent_score.py            # -> marketing/agent-demo-score.wav

# mux (write to a temp path — ffmpeg can't read+write the same file in place)
ffmpeg -y -i marketing/agent-demo.mp4 -i marketing/agent-demo-score.wav \
  -map 0:v -map 1:a -c:v copy -c:a aac -movflags +faststart -shortest /tmp/agent-scored.mp4
mv /tmp/agent-scored.mp4 marketing/agent-demo.mp4
```

The `.wav` is a regenerable intermediate — not committed (only the muxed `.mp4` is).

## Gallery card copy

- **Headline:** AI security for the agent era
- **Sub:** Investigate findings, attest agent identity, and map every A2A hop.
- **Three cards** (match the three scenes):
  - **The analyst** — a read-only investigator that gathers the finding's context and the
    actor's recent activity, then recommends dismiss / triage / keep-open with a rationale
    and a calibrated confidence. It never acts on its own.
  - **Agent attestation** — bind tool calls to workload-identity (OIDC). Unattested calls are
    flagged; with enforcement on, they're hard-blocked.
  - **A2A flow graph** — a directed graph of which agent fed which, carrying the message
    count and the worst risk that crossed each hop.

## Production notes

- Galleries autoplay muted — the captions carry the message; keep them if you re-cut.
- The clip is a faithful mockup, not a screen capture; if you'd rather record the live
  console, the surfaces are: a finding's **Investigate** button (FindingDetail), the
  **Agents** tab's A2A flow panel + the "block tool calls that aren't OIDC-attested" toggle.
- Use a demo/test tenant with seeded agent findings if recording live (the public read-only
  demo org blocks writes, so "apply recommended action" won't execute on camera).
