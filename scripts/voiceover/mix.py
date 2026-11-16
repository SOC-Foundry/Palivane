"""Lay voice-over lines onto a music bed and mux onto a clip.

    mix.py CLIP.mp4 MUSIC.wav LINES.json OUT.mp4 [--music-db -14] [--duck-db -10]

LINES.json: [{"t": 3.0, "wav": "line1.wav"}, ...]  (t = seconds from clip start).
The music is ducked by duck-db around each line with 250 ms ramps, lines are peak-normalised
to -3 dBFS and the bed sits music-db below full scale when nobody is speaking. A line that
would overlap the next is left as is; the report prints every gap so timing can be tuned.
"""
import json, subprocess, sys, tempfile, os
import numpy as np
from scipy.io import wavfile

SR = 44100

def load(path):
    tmp = tempfile.mktemp(suffix=".wav")
    subprocess.run(["ffmpeg", "-y", "-v", "error", "-i", path, "-ac", "2", "-ar", str(SR), tmp], check=True)
    sr, x = wavfile.read(tmp); os.unlink(tmp)
    x = x.astype(float) / 32768
    return x if x.ndim == 2 else np.stack([x, x], 1)

def trim(v, db=-40.0, keep=0.05):
    """Drop the silence a synthesizer puts before (and after) the words, keeping `keep`
    seconds of air on each side, so a line starts where the script says it does."""
    env = np.abs(v).max(axis=1); thr = 10 ** (db / 20)
    idx = np.where(env > thr)[0]
    if not len(idx):
        return v
    a = max(0, idx[0] - int(keep * SR)); b = min(len(v), idx[-1] + int(keep * SR))
    return v[a:b]


def main(a):
    clip, music, lines, out = a[:4]
    music_db = float(a[a.index("--music-db") + 1]) if "--music-db" in a else -14.0
    duck_db = float(a[a.index("--duck-db") + 1]) if "--duck-db" in a else -10.0
    dur = float(subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", clip],
                               capture_output=True, text=True).stdout.strip())
    n = int(dur * SR)
    bed = load(music)[:n]
    if len(bed) < n: bed = np.vstack([bed, np.zeros((n - len(bed), 2))])
    bed *= 10 ** (music_db / 20) / (np.abs(bed).max() + 1e-9)
    vo = np.zeros((n, 2)); gain = np.ones(n)
    ramp = int(0.25 * SR)
    spec = json.load(open(lines))
    prev_end = 0.0
    for i, ln in enumerate(spec):
        v = load(ln["wav"]); v *= 10 ** (-3 / 20) / (np.abs(v).max() + 1e-9)
        v = trim(v)                       # the synthesizer pads up to ~0.7 s of silence before speech
        s = int(ln["t"] * SR); e = min(n, s + len(v))
        vo[s:e] += v[: e - s]
        gap = ln["t"] - prev_end
        print(f"line {i + 1:2d} at {ln['t']:6.2f}s  len {len(v) / SR:5.2f}s  gap before {gap:5.2f}s" + ("   <-- OVERLAP" if gap < 0 else ""))
        prev_end = ln["t"] + len(v) / SR
        d0, d1 = max(0, s - ramp), min(n, e + ramp)
        gain[d0:d1] = np.minimum(gain[d0:d1], 10 ** (duck_db / 20))
    # smooth the duck envelope so it never clicks
    k = np.ones(ramp) / ramp; gain = np.convolve(gain, k, "same")
    mix = bed * gain[:, None] + vo
    pk = np.abs(mix).max()
    if pk > 0.95: mix *= 0.95 / pk
    wav = tempfile.mktemp(suffix=".wav"); wavfile.write(wav, SR, (mix * 32767).astype(np.int16))
    subprocess.run(["ffmpeg", "-y", "-v", "error", "-i", clip, "-i", wav, "-map", "0:v", "-map", "1:a", "-c:v", "copy",
                    "-c:a", "aac", "-b:a", "160k", "-shortest", "-movflags", "+faststart", out], check=True)
    os.unlink(wav); print("wrote", out, f"({dur:.1f}s, last line ends {prev_end:.1f}s)")

if __name__ == "__main__":
    main(sys.argv[1:])
