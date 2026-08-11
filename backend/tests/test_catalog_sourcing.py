"""Catalog sourcing — host extraction from tools lists and section-aware row insertion."""

from __future__ import annotations

import pytest

from app.catalog_sourcing import extract_hosts, insert_rows, update_readme_count


def test_extract_hosts_from_markdown_list():
    md = """
    # Awesome AI
    - [CoolChat](https://www.coolchat.ai) — a chatbot ([repo](https://github.com/x/coolchat))
    - [VidGen](https://vidgen.example/product?ref=list) demo on [YouTube](https://youtube.com/watch?v=1)
    ![badge](https://img.shields.io/badge/x-y)
    """
    assert extract_hosts(md) == ["coolchat.ai", "vidgen.example"]


def test_extract_hosts_filters_noise_and_dedupes():
    md = ("https://twitter.com/a https://REDDIT.com/r/ai https://10.0.0.1/x "
          "https://gist.github.com/y https://coolchat.ai/a https://coolchat.ai/b")
    assert extract_hosts(md) == ["coolchat.ai"]   # denylist (incl. subdomains), IPs, dupes


def test_extract_hosts_preserves_feed_order():
    assert extract_hosts("https://b.example https://a.example") == ["b.example", "a.example"]


def test_extract_hosts_drops_press_research_and_edu():
    md = ("https://nytimes.com/ai https://hai.stanford.edu/x https://blog.google/y "
          "https://research.ox.ac.uk/z https://llama.com")
    assert extract_hosts(md) == ["llama.com"]


_MINI = '''CATALOG: dict[str, tuple[str, str]] = {
    # --- General assistants / chatbots ---
    "chatgpt.com": ("ChatGPT", "assistant"),

    # --- ML platforms / model hubs / API providers ---
    "huggingface.co": ("Hugging Face", "ml_platform"),
}
'''


def test_insert_rows_lands_in_the_right_section():
    out = insert_rows(_MINI, [
        {"host": "newbot.ai", "name": "NewBot", "category": "assistant"},
        {"host": "api.newllm.ai", "name": "NewLLM API", "category": "api"},
    ])
    lines = out.splitlines()
    assistants = lines.index('    # --- General assistants / chatbots ---')
    ml = lines.index('    # --- ML platforms / model hubs / API providers ---')
    newbot = lines.index('    "newbot.ai": ("NewBot", "assistant"),')
    newapi = lines.index('    "api.newllm.ai": ("NewLLM API", "api"),')
    assert assistants < newbot < ml < newapi          # each under its own section
    assert out.rstrip().endswith("}")
    compile(out, "<mini>", "exec")                    # still valid python


def test_insert_rows_fails_loudly_on_missing_section():
    with pytest.raises(ValueError):
        insert_rows("CATALOG = {\n}\n",
                    [{"host": "a.ai", "name": "A", "category": "assistant"}])


def test_update_readme_count_rounds_down_and_is_noop_without_claim():
    assert "~520-tool catalog" in update_readme_count("a ~470-tool catalog here", 529)
    assert update_readme_count("no claim", 529) == "no claim"
