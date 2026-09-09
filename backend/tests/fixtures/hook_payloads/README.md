# Recorded hook payloads

One JSON file per shape a host agent sends us. `test_hook_fixture_replay.py` replays each
through the real extractor in `cli/`, so a vendor renaming a field fails a test here instead
of going unnoticed in the field.

**These only do their job if they are real captures.** A hand-written fixture is written
from the same assumption as the code it tests, so the two drift together and agree with each
other forever. Every fixture below carries `captured_from`; anything marked
`hand-written` is a placeholder that has not yet earned its keep — replace it with a real
capture when you next have the agent in front of you.

## Capturing one

Point the agent's hook at a recorder instead of the real client and keep what arrives:

```bash
cat > /tmp/rec <<'SH'
#!/usr/bin/env bash
cat > "/tmp/hook-$(date +%s%N).json"
SH
chmod +x /tmp/rec        # then set this as the hook command, drive the agent once
```

Then wrap the captured event and record the agent's own build:

```json
{
  "agent": "claude-code",
  "captured_from": "claude-code 2.1.4",
  "event": { ...exactly what arrived on stdin... },
  "expect": {"kind": "prompt", "contains": "some text from the prompt"}
}
```

`expect.kind` is `prompt` (extractor returns an ai-usage payload), `tool` (an MCP activity),
or `parse_miss` (the extractor must recognise the event and get nothing — the drift case).
