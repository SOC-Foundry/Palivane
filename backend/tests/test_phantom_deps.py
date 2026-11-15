"""Phantom dependencies: install lines in a model's reply or an agent's command are checked
against the registries (detectors/phantom_deps.py, registry_lookup.py). Offline: the lookup
is faked per test."""
from __future__ import annotations

import pytest

from app import registry_lookup
from app.config import settings
from app.detectors import phantom_deps as pd
from app.detectors.base import AnalysisInput, Surface
from app.engine import Engine


@pytest.fixture(autouse=True)
def _on(monkeypatch):
    monkeypatch.setattr(settings, "phantom_deps_enabled", True)
    registry_lookup.clear_cache()


def _fake(table: dict):
    def lookup(eco, name):
        return table.get((eco, name))
    return lookup


# --- parsing -----------------------------------------------------------------------------------

def test_extracts_installs_across_ecosystems():
    text = """Install the helpers first:

    pip install requests fastapi-sqlmodel-utils==1.2 "typing-extensions>=4"
    $ npm i -D @acme/react-magic lodash
    npx cool-scaffold@latest init
    cargo add tokio serde-magic
    gem install nokogiri
    go get github.com/acme/notreal/v2@latest
    pip install -r requirements.txt
    """
    got = pd.extract_installs(text)
    names = {(e, n) for e, n, _ in got}
    assert ("pypi", "requests") in names and ("pypi", "fastapi-sqlmodel-utils") in names
    assert ("pypi", "typing-extensions") in names
    assert ("npm", "@acme/react-magic") in names and ("npm", "lodash") in names
    assert ("npm", "cool-scaffold") in names
    assert ("crates", "tokio") in names and ("crates", "serde-magic") in names
    assert ("gem", "nokogiri") in names
    assert ("go", "github.com/acme/notreal/v2") in names
    assert not any(n == "requirements.txt" for _, n, _ in got)
    assert all(line.startswith(("pip", "$ npm", "npx", "cargo", "gem", "go")) for _, _, line in got)


def test_prose_without_install_lines_is_ignored():
    assert pd.extract_installs("You could install it with your package manager. pip is fine.") == []
    assert pd.extract_installs("Run the tests: pytest -q") == []


# --- detector -----------------------------------------------------------------------------------

def _resp(text: str) -> AnalysisInput:
    return AnalysisInput(content=text, subject="LLM response (chatgpt)", surface=Surface.AI_USAGE,
                         metadata={"direction": "response"})


def test_nonexistent_suggestion_is_flagged_and_known_one_is_not(monkeypatch):
    monkeypatch.setattr(registry_lookup, "lookup", _fake({
        ("pypi", "fastapi-sqlmodel-utils"): {"exists": False},
    }))
    sig = pd.PhantomDepsDetector().analyze(_resp("Run:\n\npip install requests fastapi-sqlmodel-utils\n"))
    assert len(sig) == 1
    s = sig[0]
    assert s.check == "phantom_dependency" and s.category.value == "dependency_risk"
    assert "does not exist" in s.title and "fastapi-sqlmodel-utils" in s.detail
    assert s.evidence.startswith("pip install")


def test_brand_new_package_is_a_softer_signal(monkeypatch):
    monkeypatch.setattr(registry_lookup, "lookup", _fake({("npm", "react-magic-hooks"): {"exists": True, "age_days": 3}}))
    sig = pd.PhantomDepsDetector().analyze(_resp("npm install react-magic-hooks"))
    assert len(sig) == 1 and "brand new" in sig[0].title and sig[0].weight < 0.8


def test_established_package_raises_nothing(monkeypatch):
    monkeypatch.setattr(registry_lookup, "lookup", _fake({("npm", "left-padder"): {"exists": True, "age_days": 900}}))
    assert pd.PhantomDepsDetector().analyze(_resp("npm install left-padder")) == []


def test_registry_outage_raises_nothing(monkeypatch):
    monkeypatch.setattr(registry_lookup, "lookup", lambda eco, name: None)
    assert pd.PhantomDepsDetector().analyze(_resp("pip install totally-made-up-pkg")) == []


def test_prompts_are_not_checked_only_responses(monkeypatch):
    monkeypatch.setattr(registry_lookup, "lookup", _fake({("pypi", "made-up"): {"exists": False}}))
    prompt = AnalysisInput(content="should I pip install made-up?", surface=Surface.AI_USAGE)
    assert pd.PhantomDepsDetector().analyze(prompt) == []


def test_agent_install_command_is_checked_before_it_runs(monkeypatch):
    monkeypatch.setattr(registry_lookup, "lookup", _fake({("pypi", "made-up"): {"exists": False}}))
    call = AnalysisInput(content="pip install made-up", subject="Agent tool: Bash",
                         surface=Surface.AGENT_TOOLS, metadata={"tool": "Bash", "args_text": "pip install made-up"})
    sig = pd.PhantomDepsDetector().analyze(call)
    assert len(sig) == 1 and sig[0].title.startswith("Installing")


def test_engine_scores_a_phantom_response_high(monkeypatch):
    monkeypatch.setattr(registry_lookup, "lookup", _fake({("pypi", "fastapi-sqlmodel-utils"): {"exists": False}}))
    res = Engine().analyze(_resp("pip install fastapi-sqlmodel-utils"))
    cats = {s.category.value for s in res.signals}
    assert "dependency_risk" in cats and res.severity in ("high", "critical")


def test_switch_off(monkeypatch):
    monkeypatch.setattr(settings, "phantom_deps_enabled", False)
    monkeypatch.setattr(registry_lookup, "lookup", _fake({("pypi", "x-y-z"): {"exists": False}}))
    assert pd.PhantomDepsDetector().analyze(_resp("pip install x-y-z")) == []


# --- the response ingest keeps the category ---------------------------------------------------

def test_proxy_response_ingest_records_the_phantom(client, raw_client, monkeypatch):
    monkeypatch.setattr(registry_lookup, "lookup", _fake({("pypi", "fastapi-sqlmodel-utils"): {"exists": False}}))
    tok = client.post("/api/apikeys", json={"label": "laptop", "actor": "dev@acme.com"}).json()["token"]
    import json
    reply = {"choices": [{"message": {"role": "assistant",
                                      "content": "Sure. First:\n\npip install fastapi-sqlmodel-utils\n\nThen import it."}}]}
    r = raw_client.post("/api/ingest/ai-usage",
                        json={"content": json.dumps(reply), "direction": "response", "response_format": "json",
                              "tool": "chatgpt", "destination": "api.openai.com"},
                        headers={"X-Palivane-Token": tok, "User-Agent": "palivane-proxy/1.5.0"})
    assert r.status_code == 200, r.text
    v = r.json()
    assert v["direction"] == "response" and v["action"] == "allow"
    assert any(s.get("check") == "phantom_dependency" for s in v["signals"]), v["signals"]
