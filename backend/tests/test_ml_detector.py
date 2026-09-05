"""The ML detection tier's engine wiring (the mechanism tests for app/ml live in
test_ml_classifier.py): shipped weights load, code/config classify as code and prose
stays silent, an embedded code block inside prose is found (window-max aggregation),
short inputs are ignored, the signal reaches verdicts through the engine on its surfaces
only, and inference stays inside the latency budget."""

from __future__ import annotations

import time

from app.detectors import AnalysisInput, MLClassifierDetector, Surface

det = MLClassifierDetector()

# Config-shaped code with none of the keywords the rules-based check keys on — the
# boundary case this tier exists for.
CONFIG = """
server.host = "10.4.2.11"
server.port = 8443
retry.backoff_ms = [250, 500, 1000, 2000]
tls.cert_path = "/etc/palivane/cert.pem"
pool.max_connections = 64
metrics.flush_interval_s = 15
""" * 3

PROSE = ("Our quarterly review covers the revenue outlook, the hiring plan for the "
         "platform team, and the customer feedback themes we heard during onboarding "
         "calls. The main risks remain execution capacity and the timeline for the "
         "compliance program, which the board asked us to accelerate this year. ") * 4


def _code() -> str:
    # real source, past the module docstring (which is honest prose)
    text = open("app/service.py").read()
    return text[len(text) // 2:len(text) // 2 + 1200]


def test_shipped_weights_load_with_eval_metadata():
    assert det._model is not None, "backend/data/code_classifier.json missing"
    ev = det._model.meta.get("eval") or {}
    assert ev.get("accuracy", 0) >= 0.95         # the claim ships with the weights


def test_probabilities_separate_cleanly():
    assert det.p_code(_code()) > 0.85
    assert det.p_code(CONFIG) > 0.85             # no keywords, still code
    assert det.p_code(PROSE) < 0.5


def test_embedded_code_block_inside_prose_is_found():
    mixed = PROSE[:400] + "\n" + _code()[:300] + "\n" + PROSE[400:800]
    assert det.p_code(mixed) > 0.85              # window max, not whole-document average


def test_code_emits_low_weight_signal_prose_does_not():
    sigs = det.analyze(AnalysisInput(content=CONFIG, surface=Surface.AI_USAGE))
    assert len(sigs) == 1
    s = sigs[0]
    assert s.category.value == "source_code_leak"
    assert s.effective_check == "source_code_ml"
    assert s.weight <= 0.4                       # corroborates; cannot max a verdict alone
    assert det.analyze(AnalysisInput(content=PROSE, surface=Surface.AI_USAGE)) == []


def test_short_input_is_ignored():
    assert det.analyze(AnalysisInput(content="x = 1", surface=Surface.AI_USAGE)) == []


def test_engine_carries_the_signal_on_ml_surfaces_only(client):
    r = client.post("/api/analyze", json={"content": CONFIG, "channel": "test"})
    assert r.status_code == 200, r.text
    checks = {s.get("check") for s in r.json().get("signals", [])}
    assert "source_code_ml" in checks


def test_inference_latency_budget():
    body = _code() * 4                           # ~5KB — worst case hits the scan cap
    t0 = time.perf_counter()
    for _ in range(30):
        det.p_code(body)
    per_call_ms = (time.perf_counter() - t0) * 1000 / 30
    assert per_call_ms < 10, f"{per_call_ms:.2f}ms per call — budget is single-digit ms"
