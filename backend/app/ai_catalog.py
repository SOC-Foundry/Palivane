"""Catalog of known AI tools/services for shadow-AI discovery.

Maps a destination (domain, URL, or free-text tool name) to a canonical tool name and a
category. Used by:
  - the shadow-AI detector, to name an unsanctioned destination, and
  - the discovery module, to classify AI usage seen in CASB / SWG / proxy / DNS logs.

Intentionally broad and easy to extend — "stay updated as new AI tools emerge" is a first-
class requirement. Add a row to CATALOG (domain-or-alias -> (name, category)); matching is
case-insensitive substring, so "chatgpt.com", "https://chatgpt.com/c/…", and a bare
"chatgpt" all resolve to the same tool.
"""

from __future__ import annotations

# category keys: assistant | coding | image_video | writing | meeting | search | agent | ml_platform | api
CATALOG: dict[str, tuple[str, str]] = {
    # --- General assistants / chatbots ---
    "chat.openai.com": ("ChatGPT", "assistant"), "chatgpt.com": ("ChatGPT", "assistant"),
    "openai.com": ("OpenAI", "assistant"), "claude.ai": ("Claude", "assistant"),
    "anthropic.com": ("Anthropic", "assistant"), "gemini.google.com": ("Gemini", "assistant"),
    "bard.google.com": ("Gemini (Bard)", "assistant"), "aistudio.google.com": ("Google AI Studio", "assistant"),
    "copilot.microsoft.com": ("Microsoft Copilot", "assistant"), "m365.cloud.microsoft": ("Microsoft 365 Copilot", "assistant"),
    "bing.com/chat": ("Bing Copilot", "assistant"), "poe.com": ("Poe", "assistant"),
    "character.ai": ("Character.AI", "assistant"), "meta.ai": ("Meta AI", "assistant"),
    "deepseek.com": ("DeepSeek", "assistant"), "chat.deepseek.com": ("DeepSeek", "assistant"),
    "mistral.ai": ("Mistral", "assistant"), "chat.mistral.ai": ("Le Chat (Mistral)", "assistant"),
    "grok.com": ("Grok", "assistant"), "x.ai": ("Grok", "assistant"), "pi.ai": ("Pi", "assistant"),
    "claude.com": ("Claude", "assistant"), "qwen.ai": ("Qwen", "assistant"),
    "kimi.moonshot.cn": ("Kimi", "assistant"), "doubao.com": ("Doubao", "assistant"),
    "hailuo.ai": ("Hailuo", "assistant"), "clovax.naver.com": ("CLOVA X", "assistant"),

    # --- Search / answer engines ---
    "perplexity.ai": ("Perplexity", "search"), "you.com": ("You.com", "search"),
    "phind.com": ("Phind", "search"), "komo.ai": ("Komo", "search"),
    "andi.com": ("Andi", "search"), "consensus.app": ("Consensus", "search"),
    "elicit.com": ("Elicit", "search"), "scholarai.io": ("ScholarAI", "search"),

    # --- Coding assistants / agents ---
    "github.com/copilot": ("GitHub Copilot", "coding"), "githubcopilot.com": ("GitHub Copilot", "coding"),
    "cursor.com": ("Cursor", "coding"), "cursor.sh": ("Cursor", "coding"),
    "cursor": ("Cursor", "coding"),   # bare alias: the Cursor hook reports destination="cursor"
    "codeium.com": ("Codeium", "coding"), "windsurf.com": ("Windsurf", "coding"),
    "tabnine.com": ("Tabnine", "coding"), "sourcegraph.com": ("Sourcegraph Cody", "coding"),
    "replit.com": ("Replit AI", "coding"), "codium.ai": ("Qodo (CodiumAI)", "coding"),
    "bolt.new": ("Bolt", "coding"), "v0.dev": ("v0", "coding"), "lovable.dev": ("Lovable", "coding"),
    "aws.amazon.com/q": ("Amazon Q", "coding"), "blackbox.ai": ("Blackbox AI", "coding"),
    "codegeex.cn": ("CodeGeeX", "coding"), "continue.dev": ("Continue", "coding"),

    # --- Agents / automation ---
    "manus.im": ("Manus", "agent"), "devin.ai": ("Devin", "agent"),
    "flowith.io": ("Flowith", "agent"), "lindy.ai": ("Lindy", "agent"),
    "relevanceai.com": ("Relevance AI", "agent"), "crewai.com": ("CrewAI", "agent"),
    "n8n.io": ("n8n (AI)", "agent"), "make.com": ("Make (AI)", "agent"),
    "zapier.com/ai": ("Zapier AI", "agent"),

    # --- Writing / productivity ---
    "jasper.ai": ("Jasper", "writing"), "copy.ai": ("Copy.ai", "writing"),
    "writesonic.com": ("Writesonic", "writing"), "rytr.me": ("Rytr", "writing"),
    "grammarly.com": ("Grammarly (AI)", "writing"), "quillbot.com": ("QuillBot", "writing"),
    "notion.so/ai": ("Notion AI", "writing"), "notion.ai": ("Notion AI", "writing"),
    "sudowrite.com": ("Sudowrite", "writing"), "wordtune.com": ("Wordtune", "writing"),
    "gamma.app": ("Gamma", "writing"), "tome.app": ("Tome", "writing"),

    # --- Image / video / audio ---
    "midjourney.com": ("Midjourney", "image_video"), "labs.openai.com": ("DALL·E", "image_video"),
    "stability.ai": ("Stability AI", "image_video"), "leonardo.ai": ("Leonardo.Ai", "image_video"),
    "runwayml.com": ("Runway", "image_video"), "pika.art": ("Pika", "image_video"),
    "elevenlabs.io": ("ElevenLabs", "image_video"), "synthesia.io": ("Synthesia", "image_video"),
    "heygen.com": ("HeyGen", "image_video"), "descript.com": ("Descript", "image_video"),
    "suno.com": ("Suno", "image_video"), "udio.com": ("Udio", "image_video"),
    "ideogram.ai": ("Ideogram", "image_video"), "krea.ai": ("Krea", "image_video"),
    "civitai.com": ("Civitai", "image_video"), "kling.ai": ("Kling", "image_video"),

    # --- Meeting / transcription notetakers (high data-exposure risk) ---
    "otter.ai": ("Otter.ai", "meeting"), "fireflies.ai": ("Fireflies.ai", "meeting"),
    "fathom.video": ("Fathom", "meeting"), "read.ai": ("Read AI", "meeting"),
    "tldv.io": ("tl;dv", "meeting"), "avoma.com": ("Avoma", "meeting"),
    "gong.io": ("Gong", "meeting"), "sembly.ai": ("Sembly", "meeting"),

    # --- ML platforms / model hubs / API providers ---
    "huggingface.co": ("Hugging Face", "ml_platform"), "replicate.com": ("Replicate", "ml_platform"),
    "together.ai": ("Together AI", "api"), "fireworks.ai": ("Fireworks AI", "api"),
    "groq.com": ("Groq", "api"), "openrouter.ai": ("OpenRouter", "api"),
    "cohere.com": ("Cohere", "api"), "ai21.com": ("AI21", "api"),
    "api.anthropic.com": ("Anthropic API", "api"), "api.openai.com": ("OpenAI API", "api"),
    "generativelanguage.googleapis.com": ("Gemini API", "api"),
    "bedrock.amazonaws.com": ("Amazon Bedrock", "api"), "perplexity.ai/api": ("Perplexity API", "api"),
}

CATEGORY_LABEL = {
    "assistant": "AI assistant", "coding": "Coding assistant", "image_video": "Image / video / audio",
    "writing": "Writing / docs", "search": "AI search", "meeting": "Meeting notetaker",
    "agent": "Agent / automation", "ml_platform": "ML platform", "api": "Model API",
}

# Local capture planes → the AI tool/platform they govern. MCP-surface captures (Cursor
# shell/tool calls, Claude Code / Gemini / Codex hooks, agent MCP) carry no destination
# domain, so the *plane's identity* (its User-Agent) is what names the tool for discovery.
CLIENT_TOOLS: dict[str, tuple[str, str]] = {
    "warden-cursor-hook": ("Cursor", "coding"),
    "warden-hook": ("Claude Code", "coding"),
    "warden-gemini-hook": ("Gemini CLI", "coding"),
    "warden-codex-hook": ("Codex CLI", "coding"),
    "warden-mcp": ("MCP client", "agent"),
}


def classify_client(user_agent: str) -> dict | None:
    """Map a capture-plane User-Agent (e.g. 'warden-cursor-hook/1.0') to the AI tool it
    governs — for discovery of MCP-surface usage that has no destination domain. None if the
    UA isn't a recognized local plane (e.g. the egress proxy, which fronts many tools)."""
    ua = (user_agent or "").strip().lower()
    if not ua:
        return None
    for key, (name, cat) in CLIENT_TOOLS.items():
        if key in ua:
            return {"tool": name, "category": cat, "domain": key}
    return None


def classify(text: str) -> dict | None:
    """Resolve a destination (URL / domain / tool name) to {tool, category, domain}.
    Longest key first so 'github.com/copilot' wins over a bare 'github.com'. None if unknown."""
    if not text:
        return None
    low = text.strip().lower()
    for key in sorted(CATALOG, key=len, reverse=True):
        if key in low:
            name, cat = CATALOG[key]
            return {"tool": name, "category": cat, "domain": key}
    return None
