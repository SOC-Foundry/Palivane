"""Score for the Palivane marketing videos (scripts/demo_video.py renders the picture).

v5: cleaner, more modern, subtle and melancholy. The lofi room is gone: no vinyl crackle,
no tape wow, no swung boom-bap, no 7.5 kHz roll-off. What plays now is a clean electric
piano, a slow filtered pad that breathes under it, a long sine sub, and, only in the fuller
sections, a soft straight pulse (a muted kick and a faint tick) well below the keys. The
harmony sits in A minor, Am9 at home with Fmaj9, Cmaj7 and G6 around it and a Dm9, Em7
descent for the builds, closing on Fmaj9 to Am9 so the end settles without brightening.
72 bpm, straight. Level is deliberately low: the voice-over of each clip is its captions,
and the music is the room they are read in.

The render API (duration, sections of (t0, t1, chord names, intensity), out_path) and the
chord names are unchanged, so agent_score.py and mcp_score.py keep their storyboards.
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

# Voicings (midi): name -> (bass, comp notes). The names are the old ones so the per-clip
# scripts keep working; the voicings are minor-key, ninths and sixths rather than dominant
# sevenths, which is most of what makes it melancholy rather than jazzy.
CHORDS = {
    "Am": (45, [60, 64, 67, 71]),      # Am9    - home
    "F":  (41, [57, 60, 64, 67]),      # Fmaj9  - the lift that never quite resolves
    "C":  (48, [55, 59, 64, 67]),      # Cmaj7  - relative major, passing light
    "G":  (43, [59, 62, 64, 67]),      # G6     - softer than G7, no leading-tone pull
    "Dm": (50, [57, 60, 64, 65]),      # Dm9    - the descent starts here
    "Em": (40, [59, 62, 64, 67]),      # Em7    - and rests here before home
}
# A minor pentatonic with the 2nd (B): the 9th over Am is where the ache lives.
SCALE = [69, 71, 72, 76, 79, 81, 83]


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


def ep(f, dur, gain, pan=0.0):
    """Clean electric piano: sine fundamental, a short second partial, a soft hammer
    transient. A couple of cents of static detune per note for warmth; no wobble."""
    n = int(dur * SR)
    t = np.arange(n) / SR
    f = f * 2 ** (rng.uniform(-2, 2) / 1200)
    ph = 2 * np.pi * f * t
    v = np.sin(ph)
    v += 0.34 * np.sin(2 * ph + 0.2) * np.exp(-t * 2.2)
    v += 0.14 * np.sin(3 * ph) * np.exp(-t * 6.0)
    v += 0.04 * np.sin(5.01 * ph) * np.exp(-t * 14.0)        # hammer
    e = np.exp(-t / (dur * 0.5)) * env(n, a=0.006, r=dur * 0.4)
    v *= e * gain
    return v * (1 - pan) / 1.4, v * (1 + pan) / 1.4


def pad(notes, dur, gain):
    """Two detuned voices per note, a slow swell in and out, through a dark low-pass: the
    thing that breathes under the keys and is felt more than heard."""
    n = int(dur * SR)
    t = np.arange(n) / SR
    l = np.zeros(n); r = np.zeros(n)
    for k, m in enumerate(notes):
        for det, side in ((-4, -1), (4, 1)):
            f = hz(m) * 2 ** (det / 1200)
            ph = 2 * np.pi * f * t + rng.uniform(0, 6)
            v = np.sin(ph) + 0.12 * np.sin(3 * ph) / 3 + 0.05 * np.sin(5 * ph) / 5
            pan = 0.35 * side + (k - 1.5) * 0.12
            l += v * (1 - pan); r += v * (1 + pan)
    sos = butter(2, 2600, btype="low", fs=SR, output="sos")
    l = sosfilt(sos, l); r = sosfilt(sos, r)
    a = min(1.4, dur * 0.35)
    e = env(n, a=a, r=min(2.0, dur * 0.45)) * gain / (len(notes) * 2)
    return l * e, r * e


def sub(f, dur, gain):
    """Long sine sub with a touch of second harmonic, legato per chord."""
    n = int(dur * SR)
    t = np.arange(n) / SR
    ph = 2 * np.pi * f * t
    v = np.sin(ph) + 0.10 * np.sin(2 * ph)
    e = env(n, a=0.04, r=min(0.6, dur * 0.3)) * gain
    v *= e
    return v, v


def soft_kick(gain):
    n = int(0.28 * SR)
    t = np.arange(n) / SR
    f = 70 * np.exp(-t * 26) + 44
    v = np.sin(2 * np.pi * np.cumsum(f) / SR) * np.exp(-t * 18) * gain
    return v, v


def tick(gain):
    """A faint, short, high tick: the pulse you notice only when it stops."""
    n = int(0.035 * SR)
    v = rng.standard_normal(n)
    sos = butter(2, [5500, 9500], btype="band", fs=SR, output="sos")
    v = sosfilt(sos, v) * np.exp(-np.arange(n) / SR * 160) * gain
    return v * 0.9, v * 1.1


def reverb(l, r, rt=2.6, wet=0.30):
    """A long, dark hall: the space is most of the mood."""
    n = int(rt * SR)
    t = np.arange(n) / SR
    dec = np.exp(-3 * t / rt)
    sos = butter(2, 5600, btype="low", fs=SR, output="sos")
    ir_l = sosfilt(sos, rng.standard_normal(n) * dec)
    ir_r = sosfilt(sos, rng.standard_normal(n) * dec)
    ir_l /= np.sqrt((ir_l ** 2).sum()); ir_r /= np.sqrt((ir_r ** 2).sum())
    return (l + wet * fftconvolve(l, ir_l)[: len(l)],
            r + wet * fftconvolve(r, ir_r)[: len(r)])


def render(duration, sections, out_path):
    n = int(duration * SR)
    keys = [np.zeros(n), np.zeros(n)]
    mel = [np.zeros(n), np.zeros(n)]
    pads = [np.zeros(n), np.zeros(n)]
    low = [np.zeros(n), np.zeros(n)]
    pulse = [np.zeros(n), np.zeros(n)]

    # The motif falls more than it rises: degrees of SCALE, the 9th (index 1) leaned on.
    motif = [4, 3, 1, 0, 3, 1, 2, 0]
    for s_i, (t0, t1, chords, inten) in enumerate(sections):
        per = (t1 - t0) / len(chords)
        for c_i, name in enumerate(chords):
            ct = t0 + c_i * per
            bass_m, notes = CHORDS[name]
            beats = max(2, int(per / BEAT))
            # pad: one swell per chord, always there, quieter in the thin sections
            place(pads, pad(notes, per + 0.8, 0.10 * (0.45 + 0.55 * inten)), ct)
            # keys: one soft rolled chord on the one; a thinner echo mid-slot in fuller parts
            for stab_b, full, g0 in ((0, True, 1.0), (beats / 2, False, 0.45)):
                st = ct + stab_b * BEAT
                if st >= t1 - 0.3 or (not full and inten < 0.5):
                    continue
                use = notes if full else notes[2:]
                for k, m in enumerate(use):
                    roll = k * rng.uniform(0.022, 0.040)
                    g = 0.17 * g0 * (0.45 + 0.55 * inten) * rng.uniform(0.85, 1.0)
                    # keys sit an octave above the pad voicing: the pad holds the low-mid,
                    # the piano speaks above it instead of thickening it
                    place(keys, ep(hz(m + 12), per * 1.1, g, pan=(k - 1.5) * 0.22), st + roll)
            # sub: the root, held for the chord
            if inten > 0.12:
                place(low, sub(hz(bass_m), per * 0.98, 0.09 * (0.5 + 0.5 * inten)), ct)
            # melody: sparse, long tails, never more than two notes a chord
            if inten > 0.4 and rng.uniform() < 0.65:
                b0 = rng.choice([0.5, 1.0, 1.5]) * BEAT
                for k in range(rng.integers(1, 3)):
                    deg = motif[(c_i * 3 + k + s_i) % len(motif)]
                    st = ct + b0 + k * BEAT * rng.choice([1.5, 2.0])
                    if st < t1 - 0.6:
                        place(mel, ep(hz(SCALE[deg % len(SCALE)] + 12), BEAT * 3.2,
                                      0.16 * inten * rng.uniform(0.7, 1.0),
                                      pan=rng.uniform(-0.2, 0.2)), st)
            # pulse: only the fuller sections, straight, far below the keys
            if inten >= 0.55:
                for b in range(beats):
                    bt = ct + b * BEAT
                    if bt >= t1 - 0.15:
                        continue
                    if b % 2 == 0:
                        place(pulse, soft_kick(0.11 * inten), bt)
                    for half in (0.0, 0.5):
                        g = 0.09 * inten * (1.0 if half == 0.0 else 0.6)
                        if rng.uniform() < 0.92:
                            place(pulse, tick(g * rng.uniform(0.8, 1.0)), bt + half * BEAT)

    l = keys[0] + mel[0] + low[0] + pulse[0]
    r = keys[1] + mel[1] + low[1] + pulse[1]
    l, r = reverb(l, r)
    # the pad gets its own, longer tail, then joins
    pl, pr = reverb(pads[0], pads[1], rt=3.6, wet=0.5)
    l += pl; r += pr

    # clean master: HPF 30, a touch of soft saturation, gentle 12k shelf-off, low level, fades
    sos_h = butter(2, 30, btype="high", fs=SR, output="sos")
    l = sosfilt(sos_h, l); r = sosfilt(sos_h, r)
    mix = np.stack([l, r])
    rms = np.sqrt((mix ** 2).mean())
    mix *= 0.060 / (rms + 1e-9)
    mix = np.tanh(mix * 1.15) / 1.15
    sos_l = butter(1, 12000, btype="low", fs=SR, output="sos")
    mix = np.stack([sosfilt(sos_l, mix[0]), sosfilt(sos_l, mix[1])])
    fin = int(2.0 * SR); fout = int(4.5 * SR)
    mix[:, :fin] *= np.sin(np.linspace(0, np.pi / 2, fin)) ** 2
    mix[:, -fout:] *= np.cos(np.linspace(0, np.pi / 2, fout)) ** 2
    peak = np.abs(mix).max()
    if peak > 0.80:
        mix *= 0.80 / peak
    wavfile.write(out_path, SR, (mix.T * 32767).astype(np.int16))
    print(out_path, "peak", round(float(np.abs(mix).max()), 3),
          "rms", round(float(np.sqrt((mix ** 2).mean())), 4))


import os


def _main():
  BASE = os.getenv("DEMO_WORK", "/tmp/palivane-demo")
  os.makedirs(BASE, exist_ok=True)

  # 123.40s hero cut. Sections follow the story: title, the three browser blocks, the three
  # agent blocks, infrastructure (AWS + GitHub), then the console payoff and a settle. The
  # length is whatever demo_video.py last printed; keep it in step or the mux trims the tail.
  render(123.40, [
    (0.0,   4.0,    ["Am"],                       0.15),   # title card: sit at home
    (4.0,   32.5,   ["Am", "F", "C", "G"],        0.50),   # browser: claude / chatgpt / gemini
    (32.5,  59.5,   ["Am", "F", "C", "G"],        0.68),   # agents: claude code / codex / cursor
    (59.5,  79.0,   ["Dm", "Em", "Am", "F"],      0.80),   # infrastructure: S3, GitHub Actions
    (79.0,  98.5,   ["Am", "F", "C", "G"],        0.72),   # SaaS at rest: Drive, Slack
    (98.5,  118.5,  ["Am", "F", "C", "G"],        0.56),   # console tour
    (118.5, 123.40, ["F", "Am"],                  0.25),   # settle out, Fmaj9 to home
  ], f"{BASE}/score.wav")

  # 58.96s setup cut. Its storyboard is calmer than the hero (title, Connect, the install
  # terminal, Settings, a second card, the MDM push, Findings, a closing brand card), so the
  # bed stays lower and only lifts for the two terminal beats.
  render(58.96, [
    (0.0,   4.5,    ["Am"],                       0.15),   # title card
    (4.5,   17.0,   ["Am", "F", "C", "G"],        0.45),   # Connect page
    (17.0,  27.5,   ["Dm", "Em"],                 0.62),   # one-command install terminal
    (27.5,  36.0,   ["Am", "F"],                  0.48),   # Settings page
    (36.0,  46.0,   ["Dm", "Em", "Am", "F"],      0.66),   # MDM push terminal
    (46.0,  54.0,   ["Am", "F", "C", "G"],        0.52),   # Findings page
    (54.0,  58.96,  ["F", "Am"],                  0.25),   # closing brand card
  ], f"{BASE}/setup-score.wav")


if __name__ == "__main__":
    _main()
