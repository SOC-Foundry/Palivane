#!/usr/bin/env python3
"""Lo-fi soundtrack for the Warden hero video — synthesized, no samples.

A mellow ii–V–I–vi loop on a Rhodes-ish electric piano, warm sine bass, swung
boom-bap drums, and vinyl crackle, glued with a tape-warmth low-pass, a little
sidechain pump and soft saturation. Deterministic (fixed RNG seed) so re-renders
are identical. Writes soundtrack.wav (44.1k / 16-bit stereo), ~28s to match the
video's DURATION.

    .venv/bin/python soundtrack.py
"""
from __future__ import annotations

import wave
import numpy as np

SR = 44100
BPM = 72.0
BEAT = 60.0 / BPM            # 0.833s
BAR = 4 * BEAT               # 3.333s
DUR = 28.0
N = int(DUR * SR)
rng = np.random.default_rng(7)

buf = np.zeros((N, 2), dtype=np.float64)   # stereo accumulator


def midi(m: float) -> float:
    return 440.0 * 2 ** ((m - 69) / 12.0)


def add(sig: np.ndarray, at: float, pan: float = 0.0, gain: float = 1.0) -> None:
    """Mix a mono signal into the stereo buffer at time `at` (s), equal-power pan."""
    i = int(at * SR)
    if i >= N:
        return
    s = sig[: N - i]
    l = np.sqrt((1 - pan) / 2) * 2 ** 0.5 / 2 * 2   # equal-power, unity at center
    r = np.sqrt((1 + pan) / 2) * 2 ** 0.5 / 2 * 2
    buf[i : i + len(s), 0] += s * gain * l
    buf[i : i + len(s), 1] += s * gain * r


def env(n: int, a: float, d: float, sus: float, rel: float) -> np.ndarray:
    """Simple AD-S-R amplitude envelope of length n samples."""
    e = np.zeros(n)
    ai, di, ri = int(a * SR), int(d * SR), int(rel * SR)
    ai = min(ai, n)
    e[:ai] = np.linspace(0, 1, ai)
    di = min(di, n - ai)
    e[ai : ai + di] = np.linspace(1, sus, di)
    body = n - ai - di - ri
    if body > 0:
        e[ai + di : ai + di + body] = sus
    if ri > 0:
        j = n - ri
        e[j:] = np.linspace(e[j - 1] if j > 0 else sus, 0, ri)
    return e


# ---- Rhodes-ish electric piano note (additive + bell attack + tremolo + vibrato) ----
def ep(freq: float, dur: float) -> np.ndarray:
    n = int(dur * SR)
    t = np.arange(n) / SR
    vib = 1 + 0.004 * np.sin(2 * np.pi * 5.2 * t)          # tape/vibrato
    partials = [(1, 1.0, 2.2), (2, 0.5, 3.0), (3, 0.16, 5.0),
                (4, 0.09, 7.0), (6, 0.05, 9.0)]            # (mult, amp, decay-rate)
    y = np.zeros(n)
    for mult, amp, dec in partials:
        y += amp * np.exp(-dec * t) * np.sin(2 * np.pi * freq * mult * t * vib)
    y += 0.6 * np.exp(-16 * t) * np.sin(2 * np.pi * freq * 4 * t)   # bell-y attack tine
    trem = 1 - 0.12 * (0.5 + 0.5 * np.sin(2 * np.pi * 4.5 * t))
    y *= trem * env(n, 0.006, 0.10, 0.6, 0.25)
    return y


def chord(root_notes, dur, gain, pan_spread=0.16):
    """Sum EP voices for a chord (list of midi numbers), stereo-spread by voice."""
    out = np.zeros((int(dur * SR), 2))
    for k, m in enumerate(root_notes):
        v = ep(midi(m), dur)
        # slight per-voice detune for chorus width
        det = ep(midi(m) * (1.003 if k % 2 else 0.997), dur) * 0.5
        pan = pan_spread * (k - (len(root_notes) - 1) / 2)
        L = np.sqrt((1 - pan) / 2) * 1.414
        R = np.sqrt((1 + pan) / 2) * 1.414
        mono = (v + det)[: len(out)]
        out[:, 0] += mono * L
        out[:, 1] += mono * R
    return out * gain


# ---- drums ----
def kick(dur=0.3):
    n = int(dur * SR)
    t = np.arange(n) / SR
    f = 48 + 55 * np.exp(-t * 32)                      # pitch drop 103 -> 48 Hz
    y = np.sin(2 * np.pi * np.cumsum(f) / SR)
    y *= np.exp(-t * 7.5)
    y += 0.15 * np.exp(-t * 60) * rng.standard_normal(n)   # click
    return np.tanh(y * 1.4) * 0.9


def snare(dur=0.22):
    n = int(dur * SR)
    t = np.arange(n) / SR
    noise = rng.standard_normal(n)
    # dusty band-limited noise (crude bandpass via difference of decays)
    body = np.sin(2 * np.pi * 180 * t) * np.exp(-t * 22)
    y = (0.7 * noise * np.exp(-t * 26) + 0.5 * body)
    return y * 0.5


def hat(dur=0.05, open_=False):
    n = int(dur * SR)
    t = np.arange(n) / SR
    y = rng.standard_normal(n)
    y = np.diff(y, prepend=0)                          # crude high-pass (differentiator)
    y *= np.exp(-t * (18 if open_ else 55))
    return y * (0.22 if open_ else 0.16)


# ---- arrangement ----
# ii V I vi  (Dm7 G7 Cmaj7 Am7), twice, resolving on C
PROG = [
    [50, 53, 57, 60],   # Dm7  : D3 F3 A3 C4
    [43, 59, 62, 65],   # G7   : G2 B3 D4 F4
    [48, 52, 55, 59],   # Cmaj7: C3 E3 G3 B3
    [45, 60, 64, 67],   # Am7  : A2 C4 E4 G4
]
ROOTS = [38, 31, 36, 33]                               # bass roots (one octave down-ish)

kick_times, pad_bus = [], np.zeros((N, 2))
for bar in range(8):
    bar_t = bar * BAR
    ch = PROG[bar % 4]
    # EP chord: strike on beat 1, softer re-voice on beat 3
    c1 = chord(ch, BAR * 0.98, gain=0.22)
    pad_bus[int(bar_t * SR) : int(bar_t * SR) + len(c1)] += c1[: N - int(bar_t * SR)]
    c3 = chord(ch, BAR * 0.5, gain=0.12)
    o3 = int((bar_t + 2 * BEAT) * SR)
    pad_bus[o3 : o3 + len(c3)] += c3[: N - o3]
    # bass: root on beat 1 (long), fifth on beat 3
    for beat, note, g, dl in [(0, ROOTS[bar % 4], 0.5, 1.6 * BEAT),
                              (2, ROOTS[bar % 4] + 7, 0.32, 1.2 * BEAT)]:
        n = int(dl * SR); t = np.arange(n) / SR
        b = np.sin(2 * np.pi * midi(note) * t) + 0.3 * np.sin(2 * np.pi * midi(note) * 2 * t)
        b *= np.exp(-t * 2.2) * env(n, 0.01, 0.1, 0.7, 0.2)
        o = int((bar_t + beat * BEAT) * SR)
        pad_bus[o : o + n, 0] += b[: N - o] * g
        pad_bus[o : o + n, 1] += b[: N - o] * g
    # drums: kick 1 & swung "&of2"; snare 2 & 4; swung eighth hats
    for kt in (0.0, 2.75):
        add(kick(), bar_t + kt * BEAT, 0.0, 0.95); kick_times.append(bar_t + kt * BEAT)
    for st in (1.0, 3.0):
        add(snare(), bar_t + st * BEAT, 0.02, 0.6)
    for e8 in range(8):
        swing = 0.06 * BEAT if e8 % 2 else 0.0         # push off-beats a hair late
        add(hat(open_=(e8 == 5)), bar_t + e8 * 0.5 * BEAT + swing,
            0.18 * (1 if e8 % 2 else -1), 0.9 if e8 % 2 == 0 else 0.7)

# sidechain pump: duck the pad/bass bus on each kick
duck = np.ones(N)
for kt in kick_times:
    i = int(kt * SR)
    seg = min(int(0.28 * SR), N - i)
    if seg > 0:
        duck[i : i + seg] = np.minimum(duck[i : i + seg],
                                       1 - 0.35 * np.exp(-np.arange(seg) / SR * 9))
pad_bus *= duck[:, None]
buf += pad_bus

# ---- vinyl crackle + tape hiss ----
hiss = rng.standard_normal((N, 2)) * 0.006
crackle = np.zeros((N, 2))
pops = rng.random(N) < 0.0009
idx = np.where(pops)[0]
crackle[idx] = rng.standard_normal((len(idx), 1)) * rng.uniform(0.05, 0.25, (len(idx), 1))
buf += hiss + crackle

# ---- master: tape low-pass (FFT), soft saturation, fades, normalize ----
def lowpass_fft(x, fc, order=3):
    n = len(x)
    f = np.fft.rfftfreq(n, 1 / SR)
    mag = 1.0 / np.sqrt(1 + (f / fc) ** (2 * order))    # Butterworth-ish magnitude
    out = np.empty_like(x)
    for ch in range(x.shape[1]):
        out[:, ch] = np.fft.irfft(np.fft.rfft(x[:, ch]) * mag, n=n)
    return out

buf = lowpass_fft(buf, 3200.0)
buf = np.tanh(buf * 1.25)                               # glue / warmth
buf *= 0.9

fade = int(0.4 * SR)
buf[:fade] *= np.linspace(0, 1, fade)[:, None]
fo = int(2.2 * SR)
buf[-fo:] *= np.linspace(1, 0, fo)[:, None]

peak = np.max(np.abs(buf))
buf *= (10 ** (-1.5 / 20)) / peak                      # normalize to -1.5 dBFS

pcm = (np.clip(buf, -1, 1) * 32767).astype("<i2")
with wave.open("soundtrack.wav", "wb") as w:
    w.setnchannels(2); w.setsampwidth(2); w.setframerate(SR)
    w.writeframes(pcm.tobytes())
print(f"wrote soundtrack.wav  {DUR:.1f}s  {BPM:.0f}bpm  peak-normalized")
