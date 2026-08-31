"""The confidential-content classifier, both tiers.

The shipped marker-based detector fires on the word "confidential" and on applied
sensitivity labels. Measured against unlabelled confidential prose it finds none of it,
which is what these two tiers exist to fix. Most of what follows is about the classifier
staying OFF, staying local, and staying subordinate to the marker path — because a model
that quietly starts blocking people's work on its own opinion is worse than no model.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

from app.detectors import AnalysisInput, Surface
from app.detectors.shadow_ai import ML_CONFIDENTIAL_TITLE, ShadowAIDetector
from app.ml import confidential, encoder
from app.ml.classifier import LogisticClassifier

_ROOT = pathlib.Path(__file__).resolve().parents[2]

UNLABELLED = ("Draft terms for the Northwind acquisition: 8x forward revenue, 40% cash at "
              "close, the rest in Acme stock vesting over three years.")


@pytest.fixture(autouse=True)
def _clean():
    confidential.reset()
    encoder.reset()
    yield
    confidential.reset()
    encoder.reset()


def _signals(text, meta=None):
    return ShadowAIDetector().analyze(
        AnalysisInput(content=text, surface=Surface.AI_USAGE, channel="chatgpt.com",
                      metadata=meta or {}))


def _confidential_signals(text, meta=None):
    return [s for s in _signals(text, meta) if s.category.value == "confidential_data"]


# --- the gap this exists to close -----------------------------------------------------

def test_marker_detector_misses_unlabelled_confidential_content():
    """Pinning the gap. If someone later teaches the regex to catch this, this test fails
    and the classifier's justification needs revisiting — which is the point of asserting it."""
    assert _confidential_signals(UNLABELLED) == []


def test_marker_detector_still_catches_a_labelled_document():
    sigs = _confidential_signals("CONFIDENTIAL — internal only. Q3 revenue attached.")
    assert sigs and sigs[0].title != ML_CONFIDENTIAL_TITLE


# --- tier 1: the linear model ----------------------------------------------------------

def _train_tiny(tmp_path):
    """A real model over the shipped generator's corpus, written where config points."""
    sys.path.insert(0, str(_ROOT / "scripts"))
    from build_confidential_corpus import build
    rows = build(per_template=8)
    model = LogisticClassifier.train(
        [(r["content"], 1 if r["label"] == "confidential" else 0) for r in rows], epochs=30)
    path = tmp_path / "model.json"
    path.write_text(model.to_json(), encoding="utf-8")
    return str(path)


def test_no_weights_means_no_signal_and_no_behaviour_change(monkeypatch):
    import app.config as cfg
    monkeypatch.setattr(cfg.settings, "ml_confidential_model", "")
    assert confidential.available() is False
    assert confidential.score(UNLABELLED) is None
    assert _confidential_signals(UNLABELLED) == []


def test_a_missing_weights_file_is_not_an_error(monkeypatch):
    import app.config as cfg
    monkeypatch.setattr(cfg.settings, "ml_confidential_model", "/nope/model.json")
    assert confidential.score(UNLABELLED) is None


def test_corrupt_weights_do_not_break_detection(monkeypatch, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    import app.config as cfg
    monkeypatch.setattr(cfg.settings, "ml_confidential_model", str(bad))
    assert confidential.score(UNLABELLED) is None
    assert _confidential_signals("CONFIDENTIAL — internal only.")   # regex path unharmed


def test_the_classifier_catches_what_the_marker_path_misses(monkeypatch, tmp_path):
    import app.config as cfg
    monkeypatch.setattr(cfg.settings, "ml_confidential_model", _train_tiny(tmp_path))
    confidential.reset()
    sigs = _confidential_signals(UNLABELLED)
    assert sigs and sigs[0].title == ML_CONFIDENTIAL_TITLE


def test_it_stays_quiet_on_ordinary_work(monkeypatch, tmp_path):
    import app.config as cfg
    monkeypatch.setattr(cfg.settings, "ml_confidential_model", _train_tiny(tmp_path))
    confidential.reset()
    assert _confidential_signals(
        "Can you review this pull request and suggest a cleaner retry structure?") == []


def test_the_model_never_outranks_a_real_label(monkeypatch, tmp_path):
    """A marker is evidence; a model is an opinion. When both could speak, the marker does,
    and the model's weight is lower besides — so a classifier cannot escalate on its own."""
    import app.config as cfg
    monkeypatch.setattr(cfg.settings, "ml_confidential_model", _train_tiny(tmp_path))
    confidential.reset()
    labelled = "CONFIDENTIAL. " + UNLABELLED
    sigs = _confidential_signals(labelled)
    assert len(sigs) == 1 and sigs[0].title != ML_CONFIDENTIAL_TITLE
    ml = ShadowAIDetector()._scan_proprietary(UNLABELLED)
    ml_sig = next(s for s in ml if s.title == ML_CONFIDENTIAL_TITLE)
    assert ml_sig.weight < 0.6 and ml_sig.confidence < 0.65


def test_evidence_carries_no_content(monkeypatch, tmp_path):
    """The evidence string is stored and shown. It must describe the verdict, never quote
    the document the verdict is about."""
    import app.config as cfg
    monkeypatch.setattr(cfg.settings, "ml_confidential_model", _train_tiny(tmp_path))
    confidential.reset()
    sig = next(s for s in _confidential_signals(UNLABELLED) if s.title == ML_CONFIDENTIAL_TITLE)
    assert "Northwind" not in sig.evidence and "confident" in sig.evidence


# --- tier 2: the encoder ---------------------------------------------------------------

def test_encoder_is_inert_without_its_dependencies():
    assert encoder.score("anything") is None
    assert encoder.available() is False


def test_encoder_is_plan_gated(monkeypatch):
    """Better-than-regex detection is not a paid feature; a 149M-parameter encoder is."""
    from app.models import Tenant
    monkeypatch.setattr(encoder, "_load", lambda: ("session", "tok"))
    assert encoder.available(Tenant(slug="a", name="A", plan="enterprise")) is True
    assert encoder.available(Tenant(slug="b", name="B", plan="team")) is False
    assert encoder.available(Tenant(slug="c", name="C", plan="free")) is False


def test_encoder_result_is_preferred_when_the_plan_allows(monkeypatch, tmp_path):
    """With both tiers loadable the encoder answers, and the linear model is the fallback
    rather than a second vote."""
    import app.config as cfg
    monkeypatch.setattr(cfg.settings, "ml_confidential_model", _train_tiny(tmp_path))
    confidential.reset()
    called = []
    monkeypatch.setattr("app.ml.encoder.score",
                        lambda text, tenant=None: called.append(text) or 0.99)
    sig = next(s for s in _confidential_signals("routine standup notes, nothing special",
                                                {"ml_encoder": True})
               if s.title == ML_CONFIDENTIAL_TITLE)
    assert called, "encoder was not consulted"
    assert "99%" in sig.evidence


def test_a_failing_encoder_falls_back_to_the_linear_model(monkeypatch, tmp_path):
    import app.config as cfg
    monkeypatch.setattr(cfg.settings, "ml_confidential_model", _train_tiny(tmp_path))
    confidential.reset()
    monkeypatch.setattr("app.ml.encoder.score", lambda text, tenant=None: None)
    sigs = _confidential_signals(UNLABELLED, {"ml_encoder": True})
    assert sigs and sigs[0].title == ML_CONFIDENTIAL_TITLE


def test_neither_tier_ever_calls_out_to_a_network():
    """The product's central claim is that detection runs where the data is. Harmonic's
    equivalent runs on GPU instances in their cloud. If either of these files grows an HTTP
    client, that difference disappears — so it is asserted, not just intended."""
    for name in ("confidential.py", "encoder.py"):
        src = (_ROOT / "backend" / "app" / "ml" / name).read_text()
        for forbidden in ("http://", "https://", "requests", "urllib", "boto3",
                          "openai", "anthropic", "socket"):
            assert forbidden not in src, f"{name} must stay local, found {forbidden!r}"


# --- the corpus generator ---------------------------------------------------------------

def test_generator_produces_near_misses_in_volume():
    """Near-misses are the whole reason the model can be trusted on business prose. If they
    stop being generated, the false-positive rate goes with them."""
    sys.path.insert(0, str(_ROOT / "scripts"))
    from build_confidential_corpus import build
    rows = build(per_template=6)
    near = [r for r in rows if r["category"] == "near_miss"]
    pos = [r for r in rows if r["label"] == "confidential"]
    assert near and pos
    assert len(near) >= 0.3 * len(pos), "near-misses must not be a token gesture"
    assert all(r["source"] == "synthetic" for r in rows), \
        "every row must be tagged synthetic so the gate can disqualify a synthetic holdout"


def test_generator_avoids_the_words_the_regex_already_catches():
    """A template containing "confidential" would teach the model to duplicate the regex
    instead of covering the case the regex misses."""
    sys.path.insert(0, str(_ROOT / "scripts"))
    from build_confidential_corpus import build
    for r in build(per_template=4):
        if r["label"] == "confidential":
            low = r["content"].lower()
            assert "confidential" not in low and "internal only" not in low


def test_generator_runs_as_a_script():
    out = subprocess.run([sys.executable, str(_ROOT / "scripts" / "build_confidential_corpus.py"),
                          "--per-template", "2"],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0
    rows = [json.loads(l) for l in out.stdout.splitlines() if l.strip()]
    assert rows and {"content", "label", "category", "source"} <= set(rows[0])
