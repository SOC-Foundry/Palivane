"""Synthesize voice-over lines. Reads SCRIPT.json ([{"t":..,"text":..}]) and writes one wav per
line plus LINES.json for mix.py. Provider picked by what credentials exist:

  ELEVENLABS_API_KEY  -> ElevenLabs (voice id in ELEVENLABS_VOICE, default "Rachel"-class id)
  OPENAI_API_KEY      -> OpenAI gpt-4o-mini-tts (voice in OPENAI_TTS_VOICE, default "ash")
  GOOGLE_TTS_TOKEN + GOOGLE_PROJECT -> Google Cloud TTS (voice in GOOGLE_TTS_VOICE,
                         default "en-US-Chirp3-HD-Charon"); token = `gcloud auth print-access-token`

    synth.py SCRIPT.json OUTDIR
"""
import base64, json, os, sys, urllib.request

def post(url, headers, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"content-type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()

def google(text, out):
    tok, proj = os.environ["GOOGLE_TTS_TOKEN"], os.environ["GOOGLE_PROJECT"]
    voice = os.environ.get("GOOGLE_TTS_VOICE", "en-US-Chirp3-HD-Charon")
    raw = post("https://texttospeech.googleapis.com/v1/text:synthesize",
               {"Authorization": f"Bearer {tok}", "x-goog-user-project": proj},
               {"input": {"text": text}, "voice": {"languageCode": "en-US", "name": voice},
                "audioConfig": {"audioEncoding": "LINEAR16", "sampleRateHertz": 44100, "speakingRate": float(os.environ.get("GOOGLE_TTS_RATE", "1.0"))}})
    open(out, "wb").write(base64.b64decode(json.loads(raw)["audioContent"]))

def openai_tts(text, out):
    key = os.environ["OPENAI_API_KEY"]; voice = os.environ.get("OPENAI_TTS_VOICE", "ash")
    raw = post("https://api.openai.com/v1/audio/speech", {"Authorization": f"Bearer {key}"},
               {"model": "gpt-4o-mini-tts", "voice": voice, "input": text, "response_format": "wav",
                "instructions": "Calm, confident product narrator. Measured pace, no hype, slight warmth."})
    open(out, "wb").write(raw)

def elevenlabs(text, out):
    key = os.environ["ELEVENLABS_API_KEY"]; voice = os.environ.get("ELEVENLABS_VOICE", "21m00Tcm4TlvDq8ikWAM")
    req = urllib.request.Request(f"https://api.elevenlabs.io/v1/text-to-speech/{voice}?output_format=pcm_44100",
                                 data=json.dumps({"text": text, "model_id": "eleven_multilingual_v2",
                                                  "voice_settings": {"stability": 0.5, "similarity_boost": 0.8}}).encode(),
                                 headers={"content-type": "application/json", "xi-api-key": key})
    with urllib.request.urlopen(req, timeout=120) as r:
        pcm = r.read()
    import numpy as np
    from scipy.io import wavfile
    wavfile.write(out, 44100, np.frombuffer(pcm, dtype=np.int16))

def main(script, outdir):
    os.makedirs(outdir, exist_ok=True)
    fn = elevenlabs if os.environ.get("ELEVENLABS_API_KEY") else openai_tts if os.environ.get("OPENAI_API_KEY") \
        else google if os.environ.get("GOOGLE_TTS_TOKEN") else None
    if fn is None:
        sys.exit("no TTS credential in the environment (ELEVENLABS_API_KEY, OPENAI_API_KEY, or GOOGLE_TTS_TOKEN+GOOGLE_PROJECT)")
    lines = json.load(open(script)); out = []
    for i, ln in enumerate(lines):
        wav = os.path.join(outdir, f"line{i + 1:02d}.wav"); fn(ln["text"], wav); out.append({"t": ln["t"], "wav": wav})
        print(f"{i + 1:2d} {ln['t']:6.2f}s  {ln['text'][:70]}")
    json.dump(out, open(os.path.join(outdir, "lines.json"), "w"), indent=1)
    print("provider:", fn.__name__, "->", os.path.join(outdir, "lines.json"))

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
