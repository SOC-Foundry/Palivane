"""Score for the Palivane marketing videos (the picture comes from scripts/demo_video.py and
friends; scripts/voiceover/ puts the narration on top).

v6: the register the competitor product videos sit in, measured on eight of them (Zenity,
Cyera, Noma, Lasso): 88 bpm, A minor, a sine sub under a plucked synth playing eighth-note
arpeggios, a four-on-the-floor kick with a soft clap on two and four, closed and open hats and
a shaker in the top octave, an airy pad, and a short lead motif. Mastered to about -17 LUFS;
scripts/voiceover/mix.py sits it 14 dB under the narration and ducks it a further 10 dB under
each line. The render API (duration, sections of (t0, t1, chord names, intensity), out_path)
and the chord names are unchanged, so agent_score.py and mcp_score.py keep their storyboards.
"""
import numpy as np
from scipy.io import wavfile
from scipy.signal import butter, sosfilt, fftconvolve
SR = 44100; rng = np.random.default_rng(6)
hz = lambda m: 440.0 * 2 ** ((m - 69) / 12)
BPM = 88; BEAT = 60 / BPM; E8 = BEAT / 2
CH = {"Am": (45, [57, 60, 64, 67, 71]), "F": (41, [57, 60, 64, 69]), "C": (48, [55, 60, 64, 67]),
      "G": (43, [55, 59, 62, 67]), "Dm": (50, [57, 62, 65, 69]), "Em": (40, [55, 59, 64, 67])}
LEAD = [76, 74, 72, 71, 69, 71, 72, 74]   # E D C B A B C D over A minor

def env(n, a, r):
    e = np.ones(n); na = int(a * SR)
    if na: e[:na] = np.linspace(0, 1, min(na, n)) ** 2
    t = np.arange(n) / SR; e *= np.exp(-np.maximum(0, t - max(0, n / SR - r)) / (r / 4 + 1e-9)); return e
def place(buf, sig, t):
    i = int(t * SR); j = min(len(buf[0]), i + len(sig[0]))
    if j > i: buf[0][i:j] += sig[0][: j - i]; buf[1][i:j] += sig[1][: j - i]
def pluck(f, dur, g, pan=0.0):
    n = int(dur * SR); t = np.arange(n) / SR; ph = 2 * np.pi * f * t
    v = np.sin(ph) + 0.5 * np.sin(2 * ph) * np.exp(-t * 6) + 0.25 * np.sin(3 * ph) * np.exp(-t * 9) + 0.12 * np.sin(4 * ph) * np.exp(-t * 12)
    v *= np.exp(-t * 5.5) * env(n, 0.002, 0.08) * g
    return v * (1 - pan), v * (1 + pan)
def lead(f, dur, g):
    n = int(dur * SR); t = np.arange(n) / SR; ph = 2 * np.pi * f * (1 + 0.004 * np.sin(2 * np.pi * 5 * t)) * t
    v = (np.sin(ph) + 0.3 * np.sin(2 * ph) + 0.15 * np.sin(3 * ph)) * env(n, 0.03, dur * 0.5) * np.exp(-t / (dur * 0.8)) * g
    return v, v
def pad(notes, dur, g):
    n = int(dur * SR); t = np.arange(n) / SR; l = np.zeros(n); r = np.zeros(n)
    for k, m in enumerate(notes):
        for det, side in ((-6, -1), (6, 1)):
            ph = 2 * np.pi * hz(m + 12) * 2 ** (det / 1200) * t + rng.uniform(0, 6)
            saw = sum(np.sin(h * ph) / h for h in range(1, 7))
            l += saw * (1 - 0.4 * side); r += saw * (1 + 0.4 * side)
    sos = butter(2, 5200, btype="low", fs=SR, output="sos"); l = sosfilt(sos, l); r = sosfilt(sos, r)
    e = env(n, 0.9, 1.2) * g / (len(notes) * 4); return l * e, r * e
def sub(f, dur, g):
    n = int(dur * SR); t = np.arange(n) / SR; v = (np.sin(2 * np.pi * f * t) + 0.15 * np.sin(4 * np.pi * f * t)) * env(n, 0.01, 0.12) * g; return v, v
def kick(g):
    n = int(0.3 * SR); t = np.arange(n) / SR; f = 110 * np.exp(-t * 30) + 48
    v = np.sin(2 * np.pi * np.cumsum(f) / SR) * np.exp(-t * 11) * g; v += 0.3 * rng.standard_normal(n) * np.exp(-t * 400) * g; return v, v
def clap(g):
    n = int(0.18 * SR); v = rng.standard_normal(n); sos = butter(2, [900, 4500], btype="band", fs=SR, output="sos")
    e = np.exp(-np.arange(n) / SR * 28); v = sosfilt(sos, v) * e * g; return v, v
def hat(g, open_=False):
    n = int((0.22 if open_ else 0.045) * SR); v = rng.standard_normal(n); sos = butter(2, [6500, 14000], btype="band", fs=SR, output="sos")
    v = sosfilt(sos, v) * np.exp(-np.arange(n) / SR * (18 if open_ else 110)) * g; return v * 0.9, v * 1.1
def shaker(g):
    n = int(0.08 * SR); v = rng.standard_normal(n); sos = butter(2, [5000, 11000], btype="band", fs=SR, output="sos")
    v = sosfilt(sos, v) * env(n, 0.02, 0.04) * g; return v * 1.1, v * 0.9
def reverb(l, r, rt=1.8, wet=0.22):
    n = int(rt * SR); t = np.arange(n) / SR; dec = np.exp(-3 * t / rt); sos = butter(2, 7000, btype="low", fs=SR, output="sos")
    il = sosfilt(sos, rng.standard_normal(n) * dec); ir = sosfilt(sos, rng.standard_normal(n) * dec)
    il /= np.sqrt((il ** 2).sum()); ir /= np.sqrt((ir ** 2).sum())
    return l + wet * fftconvolve(l, il)[: len(l)], r + wet * fftconvolve(r, ir)[: len(r)]

def render(duration, sections, out):
    n = int(duration * SR); K = [np.zeros(n), np.zeros(n)]; P = [np.zeros(n), np.zeros(n)]; L = [np.zeros(n), np.zeros(n)]
    D = [np.zeros(n), np.zeros(n)]; M = [np.zeros(n), np.zeros(n)]
    for s_i, (t0, t1, chords, inten) in enumerate(sections):
        per = (t1 - t0) / len(chords)
        for c_i, name in enumerate(chords):
            ct = t0 + c_i * per; bass, notes = CH[name]; n8 = int(per / E8)
            place(P, pad(notes, per + 0.5, 0.20 * (0.4 + 0.6 * inten)), ct)
            if inten > 0.2:
                for b in range(max(1, int(per / BEAT))):
                    place(L, sub(hz(bass), BEAT * 0.95, 0.11 * inten), ct + b * BEAT)
            arp = [notes[i % len(notes)] + 12 for i in (0, 2, 1, 3, 0, 2, 4 % len(notes), 1)]
            for k in range(n8):
                if inten < 0.3 and k % 2: continue
                m = arp[k % len(arp)]
                place(K, pluck(hz(m), E8 * 1.6, 0.22 * (0.5 + 0.5 * inten) * (1.0 if k % 2 == 0 else 0.8), pan=((k % 4) - 1.5) * 0.25), ct + k * E8)
            if inten > 0.45 and rng.uniform() < 0.75:
                for k in range(2):
                    deg = (c_i * 2 + k + s_i) % len(LEAD)
                    place(M, lead(hz(LEAD[deg]), BEAT * 1.6, 0.09 * inten), ct + (1 + 2 * k) * BEAT)
            if inten >= 0.45:
                for b in range(int(per / BEAT)):
                    bt = ct + b * BEAT
                    if bt >= t1 - 0.1: continue
                    place(D, kick(0.26 * inten), bt)
                    if b % 2 == 1: place(D, clap(0.30 * inten), bt)
                    place(D, hat(0.26 * inten, open_=(b % 4 == 3)), bt + E8)
                    for q in (0.25, 0.75): place(D, shaker(0.14 * inten), bt + q * BEAT)
                    place(D, hat(0.18 * inten), bt)
    l = K[0] + P[0] + L[0] + D[0] + M[0]; r = K[1] + P[1] + L[1] + D[1] + M[1]
    l, r = reverb(l, r)
    sos = butter(2, 28, btype="high", fs=SR, output="sos"); l = sosfilt(sos, l); r = sosfilt(sos, r)
    mix = np.stack([l, r]); mix *= 0.11 / (np.sqrt((mix ** 2).mean()) + 1e-9); mix = np.tanh(mix * 1.4) / 1.4
    fin = int(1.0 * SR); fo = int(3.5 * SR); mix[:, :fin] *= np.linspace(0, 1, fin); mix[:, -fo:] *= np.cos(np.linspace(0, np.pi / 2, fo)) ** 2
    pk = np.abs(mix).max();
    if pk > 0.95: mix *= 0.95 / pk
    wavfile.write(out, SR, (mix.T * 32767).astype(np.int16)); print(out, "peak", round(float(np.abs(mix).max()), 3))

import os


def _main():
  BASE = os.getenv("DEMO_WORK", "/tmp/palivane-demo")
  os.makedirs(BASE, exist_ok=True)
  # 123.40s hero cut: title, the three browser blocks, the three agent blocks, infrastructure,
  # SaaS at rest, the console payoff, a settle. Keep in step with demo_video.py's length.
  render(123.40, [
    (0.0,   4.0,    ["Am"],                  0.2),
    (4.0,   32.5,   ["Am", "F", "C", "G"],   0.55),
    (32.5,  59.5,   ["Am", "F", "C", "G"],   0.7),
    (59.5,  79.0,   ["Dm", "Em", "Am", "F"], 0.85),
    (79.0,  98.5,   ["Am", "F", "C", "G"],   0.75),
    (98.5,  118.5,  ["Am", "F", "C", "G"],   0.6),
    (118.5, 123.40, ["F", "Am"],             0.3),
  ], f"{BASE}/score.wav")
  # 58.96s setup cut: title, Connect, the install terminal, Settings, the MDM push, Findings, close.
  render(58.96, [
    (0.0,   4.5,    ["Am"],                  0.2),
    (4.5,   17.0,   ["Am", "F", "C", "G"],   0.55),
    (17.0,  27.5,   ["Dm", "Em"],            0.7),
    (27.5,  36.0,   ["Am", "F"],             0.55),
    (36.0,  46.0,   ["Dm", "Em", "Am", "F"], 0.8),
    (46.0,  54.0,   ["Am", "F", "C", "G"],   0.6),
    (54.0,  58.96,  ["F", "Am"],             0.3),
  ], f"{BASE}/setup-score.wav")


if __name__ == "__main__":
    _main()
