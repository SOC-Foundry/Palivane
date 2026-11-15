# Voice-over for the marketing clips

Each clip has a script here (`hero.json`, `setup.json`, `agent.json`, `mcp.json`): one line per
scene change, `t` in seconds from the clip start. The pipeline, from a repo checkout with the
backend venv (numpy/scipy) and ffmpeg:

```sh
# 1. music beds (scripts/demo_score.py and friends)
DEMO_WORK=/tmp/pv backend/.venv/bin/python scripts/demo_score.py            # score.wav, setup-score.wav
AGENT_SCORE_OUT=/tmp/pv/agent.wav backend/.venv/bin/python scripts/agent_score.py
MCP_SCORE_OUT=/tmp/pv/mcp.wav     backend/.venv/bin/python scripts/mcp_score.py

# 2. narration: Google Cloud Text-to-Speech, Chirp 3 HD "Fenrir", API enabled on the palivane project
export GOOGLE_TTS_TOKEN=$(gcloud auth print-access-token) GOOGLE_PROJECT=palivane GOOGLE_TTS_VOICE=en-US-Chirp3-HD-Fenrir
backend/.venv/bin/python scripts/voiceover/synth.py scripts/voiceover/hero.json /tmp/pv/vo-hero      # rate 1.0
GOOGLE_TTS_RATE=1.08 backend/.venv/bin/python scripts/voiceover/synth.py scripts/voiceover/agent.json /tmp/pv/vo-agent   # the two short clips run a touch faster
#    (setup like hero; mcp like agent)

# 3. mix onto the silent-video clip: bed 14 dB down, ducked 10 dB under each line; video copied
backend/.venv/bin/python scripts/voiceover/mix.py frontend/public/shots/demo18.mp4 /tmp/pv/score.wav /tmp/pv/vo-hero/lines.json /tmp/pv/demo18.mp4
```

`mix.py` prints every line's length and the gap before it; a negative gap means two lines
overlap and the script's `t` (or the wording) needs to move. `synth.py` also speaks OpenAI or
ElevenLabs if those keys are set instead; Google is what the shipped clips use.
