"""A repeat of a signed inference-hook request (a retry, or a replay inside the signature
window) gets the first answer back and is not scored or recorded again (security review, low)."""
from __future__ import annotations

from app import inference_hooks as ih


def test_a_repeat_gets_the_first_verdict():
    ih.remember_verdict(1, "msg_1:abc", {"action": "deny", "deny_reason": "x"}, now=1000.0)
    assert ih.recall_verdict(1, "msg_1:abc", now=1001.0) == {"action": "deny", "deny_reason": "x"}
    assert ih.recall_verdict(2, "msg_1:abc", now=1001.0) is None             # another tenant
    assert ih.recall_verdict(1, "msg_1:abc", now=1000.0 + ih._SEEN_TTL_S + 1) is None


def test_the_memory_is_bounded(monkeypatch):
    monkeypatch.setattr(ih, "_SEEN_MAX", 3)
    for i in range(10):
        ih.remember_verdict(1, f"m{i}", {"action": "allow"}, now=1000.0)
    assert len(ih._seen) <= 3 and ih.recall_verdict(1, "m9", now=1000.0) is not None


def test_model_ids_are_encoded_into_upstream_paths():
    from app import gateway
    url, _ = gateway._openai_upstream("https://acme.openai.azure.com", "k", "/chat/completions",
                                      "gpt-4o/../../other?x=1#")
    assert "/openai/deployments/gpt-4o%2F..%2F..%2Fother%3Fx%3D1%23/chat/completions" in url
