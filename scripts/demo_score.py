"""Lofi score for the Warden marketing videos (scripts/demo_video.py renders the picture).

v3: 'less synthy, more lofi'. The sustained detuned-sine pads are gone; the bed is now
Rhodes-style keys comping 7th chords with tape wow/flutter, a plucked bass, a soft
boom-bap kit with swung hats (only in the fuller sections), and a dusty master:
gentle tape saturation, ~7.5kHz roll-off, and a whisper of vinyl crackle + hiss.
Same Am-F-C-G progression (now as Am7/Fmaj7/Cmaj7/G7), same section map, same loudness.
"""
import numpy as np
from scipy.io import wavfile
from scipy.signal import butter, fftconvolve, sosfilt

SR = 44100
rng = np.random.default_rng(11)

A4 = 440.0
def hz(m):
    return A4 * 2 ** ((m - 69) / 12)

BPM = 72
BEAT = 60 / BPM            # 0.833s
SWING = 0.58               # off-8ths land late

# 7th voicings (midi): name -> (bass, comp notes)
CHORDS = {
    "Am": (45, [57, 60, 64, 67]),      # Am7
    "F":  (41, [53, 57, 60, 64]),      # Fmaj7
    "C":  (48, [52, 55, 59, 64]),      # Cmaj7
    "G":  (43, [55, 59, 62, 65]),      # G7
}
SCALE = [69, 72, 74, 76, 79, 81, 84]   # A minor pentatonic-ish, mellow octave


def env(n, a, r, sr=SR):
    e = np.ones(n)
    na = min(int(a * sr), n)
    if na > 0:
        e[:na] = np.sin(np.linspace(0, np.pi / 2, na)) ** 2
    t = np.arange(n) / sr
    e *= np.exp(-np.maximum(0, t - max(0, n / sr - r)) / (r / 4 + 1e-9))
    return e


def place(buf, sig, t):
    i = int(t * SR)
    j = min(len(buf[0]), i + len(sig[0]))
    if j > i:
        buf[0][i:j] += sig[0][: j - i]
        buf[1][i:j] += sig[1][: j - i]


def wowphase(f, n):
    """Phase for a tape-warped tone: slow wow + faster flutter, per-note random."""
    t = np.arange(n) / SR
    wob = (0.0035 * np.sin(2 * np.pi * 0.9 * t + rng.uniform(0, 6))
           + 0.0012 * np.sin(2 * np.pi * 5.3 * t + rng.uniform(0, 6)))
    return 2 * np.pi * np.cumsum(f * (1 + wob)) / SR


def rhodes(f, dur, gain, pan=0.0):
    """Rhodes-ish tine: warm fundamental + fast-decaying bell partial, tape wow."""
    n = int(dur * SR)
    t = np.arange(n) / SR
    ph = wowphase(np.full(n, f), n)
    v = np.sin(ph)
    v += 0.42 * np.sin(2 * ph + 0.3) * np.exp(-t * 3.0)
    v += 0.16 * np.sin(3.53 * ph) * np.exp(-t * 7.0)      # tine bell
    v += 0.05 * np.sin(5 * ph) * np.exp(-t * 10.0)
    e = np.exp(-t / (dur * 0.42)) * env(n, a=0.004, r=dur * 0.35)
    v *= e * gain
    return v * (1 - pan) / 1.4, v * (1 + pan) / 1.4


def pluck_bass(f, dur, gain):
    n = int(dur * SR)
    t = np.arange(n) / SR
    ph = wowphase(np.full(n, f), n)
    v = np.sin(ph) + 0.18 * np.sin(2 * ph) * np.exp(-t * 4)
    e = np.exp(-t / 0.9) * env(n, a=0.008, r=0.3)
    v *= e * gain
    return v, v


def kick(gain):
    n = int(0.35 * SR)
    t = np.arange(n) / SR
    f = 95 * np.exp(-t * 22) + 46
    v = np.sin(2 * np.pi * np.cumsum(f) / SR) * np.exp(-t * 14) * gain
    return v, v


def rim(gain):
    n = int(0.12 * SR)
    v = rng.standard_normal(n)
    sos = butter(2, [900, 2600], btype="band", fs=SR, output="sos")
    v = sosfilt(sos, v) * np.exp(-np.arange(n) / SR * 55) * gain
    return v * 0.9, v * 1.1


def hat(gain):
    n = int(0.06 * SR)
    v = rng.standard_normal(n)
    sos = butter(2, [3000, 7000], btype="band", fs=SR, output="sos")
    v = sosfilt(sos, v) * np.exp(-np.arange(n) / SR * 90) * gain
    return v * 1.1, v * 0.9


def reverb(l, r, rt=1.7, wet=0.22):
    n = int(rt * SR)
    t = np.arange(n) / SR
    dec = np.exp(-3 * t / rt)
    sos = butter(2, 5200, btype="low", fs=SR, output="sos")
    ir_l = sosfilt(sos, rng.standard_normal(n) * dec)
    ir_r = sosfilt(sos, rng.standard_normal(n) * dec)
    ir_l /= np.sqrt((ir_l ** 2).sum()); ir_r /= np.sqrt((ir_r ** 2).sum())
    return (l + wet * fftconvolve(l, ir_l)[: len(l)],
            r + wet * fftconvolve(r, ir_r)[: len(r)])


def vinyl(n, gain_crackle=0.011, gain_hiss=0.0035):
    """Sparse lowpassed crackle + faint hiss — texture, not noise bed."""
    crack = np.zeros(n)
    n_pops = int(n / SR * 7)
    idx = rng.integers(0, n - 4, n_pops)
    crack[idx] = rng.uniform(-1, 1, n_pops) * rng.uniform(0.2, 1.0, n_pops) ** 2
    sos = butter(2, 2800, btype="low", fs=SR, output="sos")
    crack = sosfilt(sos, crack) * gain_crackle
    sos2 = butter(2, 4500, btype="low", fs=SR, output="sos")
    hiss_l = sosfilt(sos2, rng.standard_normal(n)) * gain_hiss
    hiss_r = sosfilt(sos2, rng.standard_normal(n)) * gain_hiss
    return crack + hiss_l, np.roll(crack, 31) + hiss_r


def render(duration, sections, out_path):
    n = int(duration * SR)
    keys = [np.zeros(n), np.zeros(n)]
    mel = [np.zeros(n), np.zeros(n)]
    low = [np.zeros(n), np.zeros(n)]
    drums = [np.zeros(n), np.zeros(n)]

    motif = [0, 2, 3, 2, 4, 3, 1, 0]
    for s_i, (t0, t1, chords, inten) in enumerate(sections):
        per = (t1 - t0) / len(chords)
        for c_i, name in enumerate(chords):
            ct = t0 + c_i * per
            bass_m, notes = CHORDS[name]
            beats = max(2, int(per / BEAT))
            # keys: lazy comp — rolled chord on 1, softer partial stab mid-slot
            for stab_b, full, g0 in ((0, True, 1.0), (beats / 2 + 0.5, False, 0.55)):
                st = ct + stab_b * BEAT
                if st >= t1 - 0.2 or (not full and inten < 0.35):
                    continue
                use = notes if full else notes[1:]
                for k, m in enumerate(use):
                    roll = k * rng.uniform(0.018, 0.035)          # lazy roll-in
                    g = 0.16 * g0 * (0.5 + 0.5 * inten) * rng.uniform(0.85, 1.0)
                    place(keys, rhodes(hz(m), per * 0.9, g, pan=(k - 1.5) * 0.25),
                          st + roll)
            # bass: root on 1, fifth-or-root on 3
            if inten > 0.2:
                place(low, pluck_bass(hz(bass_m), BEAT * 2.2, 0.24 * inten), ct)
                if beats >= 4:
                    alt = bass_m + (7 if rng.uniform() < 0.4 else 0)
                    place(low, pluck_bass(hz(alt), BEAT * 2.0, 0.19 * inten),
                          ct + 2 * BEAT)
            # melody: sparse pentatonic phrases, same EP voice
            if inten > 0.35 and rng.uniform() < 0.8:
                b0 = rng.choice([0, 1]) * BEAT
                for k in range(rng.integers(1, 3 + (inten > 0.7))):
                    deg = motif[(c_i * 3 + k + s_i) % len(motif)]
                    st = ct + b0 + k * BEAT * rng.choice([1.0, 1.5])
                    if st < t1 - 0.4:
                        place(mel, rhodes(hz(SCALE[deg % len(SCALE)]), BEAT * 2.4,
                                          0.11 * inten * rng.uniform(0.7, 1.0)), st)
            # drums: only the fuller sections, quiet, swung
            if inten >= 0.55:
                for b in range(beats):
                    bt = ct + b * BEAT
                    if bt >= t1 - 0.15:
                        continue
                    if b % 4 == 0:
                        place(drums, kick(0.30 * inten), bt)
                    if b % 4 == 2:
                        place(drums, kick(0.22 * inten), bt + rng.uniform(0, 0.012))
                    if b % 2 == 1:
                        place(drums, rim(0.10 * inten), bt + rng.uniform(0, 0.010))
                    for half, swung in ((0.0, False), (SWING, True)):
                        g = 0.045 * inten * (0.7 if swung else 1.0)
                        if rng.uniform() < 0.9:
                            place(drums, hat(g * rng.uniform(0.7, 1.0)), bt + half * BEAT)

    l = keys[0] + mel[0] + low[0] + drums[0]
    r = keys[1] + mel[1] + low[1] + drums[1]
    l, r = reverb(l, r)
    vl, vr = vinyl(n)
    l += vl; r += vr

    # dusty master: HPF 35, tape sat, LPF 7.5k, level, fades
    sos_h = butter(2, 35, btype="high", fs=SR, output="sos")
    l = sosfilt(sos_h, l); r = sosfilt(sos_h, r)
    mix = np.stack([l, r])
    rms = np.sqrt((mix ** 2).mean())
    mix *= 0.085 / (rms + 1e-9)
    mix = np.tanh(mix * 1.6) / 1.6
    sos_l = butter(2, 7500, btype="low", fs=SR, output="sos")
    mix = np.stack([sosfilt(sos_l, mix[0]), sosfilt(sos_l, mix[1])])
    fin = int(1.5 * SR); fout = int(4 * SR)
    mix[:, :fin] *= np.sin(np.linspace(0, np.pi / 2, fin)) ** 2
    mix[:, -fout:] *= np.cos(np.linspace(0, np.pi / 2, fout)) ** 2
    peak = np.abs(mix).max()
    if peak > 0.92:
        mix *= 0.92 / peak
    wavfile.write(out_path, SR, (mix.T * 32767).astype(np.int16))
    print(out_path, "peak", round(float(np.abs(mix).max()), 3),
          "rms", round(float(np.sqrt((mix ** 2).mean())), 4))


import os
BASE = os.getenv("DEMO_WORK", "/tmp/warden-demo")
os.makedirs(BASE, exist_ok=True)

# 90.28s hero cut. Sections follow the story: title, the three browser blocks, the three
# agent blocks, infrastructure (AWS + GitHub), then the console payoff and a settle.
render(104.24, [
    (0.0,   4.0,    ["Am"],                       0.15),   # title card
    (4.0,   32.5,   ["Am", "F", "C", "G"],        0.55),   # browser: claude / chatgpt / gemini
    (32.5,  61.0,   ["Am", "F", "C", "G"],        0.75),   # agents: claude code / codex / cursor
    (61.0,  78.0,   ["F", "G", "Am", "C"],        0.85),   # infrastructure: AWS + GitHub
    (78.0,  99.0,   ["Am", "F", "C", "G"],        0.62),   # console tour
    (99.0,  104.24, ["Am", "F"],                  0.30),   # settle out
], f"{BASE}/score.wav")
