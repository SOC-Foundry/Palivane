"""False positives seen live, 2026-11-08: a setup script with fill-in placeholders was
hard-blocked as a credential leak, and a web page whose prose says "you can return by…" and
names a few CamelCase products scored as proprietary source code. Real values still flag.
"""
from __future__ import annotations

import importlib.util
import secrets
from pathlib import Path

import pytest

from app.detectors import AnalysisInput, Surface
from app.detectors.patterns import find_secrets
from app.detectors.shadow_ai import ShadowAIDetector

_PATH = Path(__file__).resolve().parents[2] / "cli" / "palivane_detect.py"
_spec = importlib.util.spec_from_file_location("palivane_detect_fillin", _PATH)
detect = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(detect)

FILL_INS = ["PASTE_CLIENT_SECRET_HERE", "your_token_here", "REPLACE_ME", "insert-key", "ENTER_SECRET"]


@pytest.mark.parametrize("value", FILL_INS, ids=FILL_INS)
def test_fill_in_placeholders_are_not_credentials(value):
    line = f"SLACK_SIGNING_SECRET='{value}'"
    assert not find_secrets(line)
    assert not [lbl for lbl, _ln, _m in detect.scan_text(line) if lbl == "Credential assignment"]


def test_a_real_value_in_the_same_place_still_flags():
    line = "SLACK_SIGNING_SECRET='" + secrets.token_hex(16) + "'"
    assert find_secrets(line)
    assert detect.scan_text(line)


def _code_signals(text: str):
    item = AnalysisInput(content=text, surface=Surface.AI_USAGE)
    return [s for s in ShadowAIDetector().analyze(item) if s.category.value == "source_code_leak"]


PROSE = [
    "You can return by using the Back button. Tools: TensorFlow, MathWorks, DevOps pipelines.",
    "A world class team built PaymentGateway and FraudScoring for our customers.",
    "New import tariffs hit CustomerOrders and InvoiceLedger volumes this quarter.",
    "Please select an option from the menu to open AccountSettings or BillingHistory.",
]


@pytest.mark.parametrize("text", PROSE, ids=["return", "class", "import", "select"])
def test_prose_is_not_source_code(text):
    assert not _code_signals(text)


def test_real_code_with_domain_identifiers_still_flags():
    code = ("def settle_invoice_ledger(customer_orders):\n"
            "    fraud_score = FraudScoring.evaluate(customer_orders)\n"
            "    return InvoiceLedger.post(customer_orders, fraud_score)\n")
    assert _code_signals(code)
