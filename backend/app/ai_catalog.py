"""Catalog of known AI tools/services for shadow-AI discovery.

Maps a destination (domain, URL, or free-text tool name) to a canonical tool name and a
category. Used by:
  - the shadow-AI detector, to name an unsanctioned destination, and
  - the discovery module, to classify AI usage seen in CASB / SWG / proxy / DNS logs.

Intentionally broad and easy to extend — "stay updated as new AI tools emerge" is a first-
class requirement. Add a row to CATALOG (domain-or-alias -> (name, category)); matching is
case-insensitive substring anchored at label boundaries, so "chatgpt.com",
"https://chatgpt.com/c/…", and a bare "chatgpt" all resolve to the same tool, but "x.ai"
does not claim "llamaindex.ai".
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
    "duck.ai": ("Duck.ai (DuckDuckGo)", "assistant"),
    "venice.ai": ("Venice AI", "assistant"),
    "inflection.ai": ("Inflection Pi", "assistant"),
    "monica.im": ("Monica", "assistant"),
    "sider.ai": ("Sider", "assistant"),
    "getmerlin.in": ("Merlin AI", "assistant"),
    "maxai.me": ("MaxAI", "assistant"),
    "getliner.com": ("Liner", "assistant"),
    "mammouth.ai": ("Mammouth AI", "assistant"),
    "t3.chat": ("T3 Chat", "assistant"),
    "abacus.ai": ("Abacus.AI ChatLLM", "assistant"),
    "typingmind.com": ("TypingMind", "assistant"),
    "lobehub.com": ("LobeChat", "assistant"),
    "chatpdf.com": ("ChatPDF", "assistant"),
    "askyourpdf.com": ("AskYourPDF", "assistant"),
    "humata.ai": ("Humata", "assistant"),
    "julius.ai": ("Julius AI", "assistant"),
    "replika.com": ("Replika", "assistant"),
    "nomi.ai": ("Nomi", "assistant"),
    "janitorai.com": ("JanitorAI", "assistant"),
    "lmarena.ai": ("LMArena", "assistant"),
    "reka.ai": ("Reka", "assistant"),
    "notebooklm.google": ("NotebookLM", "assistant"),
    "moveworks.com": ("Moveworks", "assistant"),
    "harvey.ai": ("Harvey", "assistant"),
    "casetext.com": ("CoCounsel (Casetext)", "assistant"),
    "spellbook.legal": ("Spellbook", "assistant"),
    "chatglm.cn": ("ChatGLM (Zhipu)", "assistant"),
    "zhipuai.cn": ("Zhipu AI", "assistant"),
    "yiyan.baidu.com": ("ERNIE Bot", "assistant"),
    "tongyi.aliyun.com": ("Tongyi Qianwen", "assistant"),
    "xinghuo.xfyun.cn": ("iFlytek Spark", "assistant"),
    "hunyuan.tencent.com": ("Tencent Hunyuan", "assistant"),
    "yuanbao.tencent.com": ("Tencent Yuanbao", "assistant"),
    "stepfun.com": ("StepFun", "assistant"),
    "minimaxi.com": ("MiniMax", "assistant"),
    "baichuan-ai.com": ("Baichuan", "assistant"),
    "moonshot.cn": ("Moonshot (Kimi)", "assistant"),
    "kimi.com": ("Kimi", "assistant"),
    "pdf.ai": ("PDF.ai", "assistant"),
    "lingyiwanwu.com": ("01.AI (Yi)", "assistant"),
    "01.ai": ("01.AI (Yi)", "assistant"),
    "z.ai": ("Z.ai (Zhipu)", "assistant"),
    "wrtn.ai": ("Wrtn", "assistant"),
    "robinai.com": ("Robin AI", "assistant"),
    "luminance.com": ("Luminance", "assistant"),
    "diabrowser.com": ("Dia (Browser Co)", "assistant"),  # PROVISIONAL — see set below
    "flowgpt.com": ("FlowGPT", "assistant"),
    "ai.meta.com": ("Meta AI", "assistant"),
    "deepmind.google": ("Google DeepMind", "assistant"),
    "lmsys.org": ("LMSYS (Chatbot Arena)", "assistant"),
    "minimax.io": ("MiniMax", "assistant"),
    "chat.qwenlm.ai": ("Qwen Chat", "assistant"),
    "librechat.ai": ("LibreChat", "assistant"),
    "chatbotui.com": ("Chatbot UI", "assistant"),
    "sharegpt.com": ("ShareGPT", "assistant"),
    "forefront.ai": ("Forefront", "assistant"),
    "open-notebook.ai": ("Open Notebook", "assistant"),
    "elicit.org": ("Elicit", "assistant"),
    "genei.io": ("Genei", "assistant"),
    "explainpaper.com": ("Explainpaper", "assistant"),
    "scispace.com": ("SciSpace", "assistant"),
    "alphaxiv.org": ("alphaXiv", "assistant"),
    "asreview.nl": ("ASReview", "assistant"),
    "rayyan.ai": ("Rayyan", "assistant"),
    "ai2sql.io": ("AI2sql", "assistant"),
    "dataline.app": ("DataLine", "assistant"),
    "vanna.ai": ("Vanna", "assistant"),
    "getwren.ai": ("Wren AI", "assistant"),
    "jan.ai": ("Jan.ai", "assistant"),   # not bare "Jan": classify_name() would claim "Jan <surname>"
    "msty.ai": ("Msty", "assistant"),
    "pygpt.net": ("Pygpt", "assistant"),
    "llm.datasette.io": ("Datasette", "assistant"),
    "runthisllm.com": ("Runthisllm", "assistant"),
    "sauna.ai": ("Sauna", "assistant"),
    "geminicli.com": ("Geminicli", "assistant"),
    "mastra.ai": ("Mastra", "assistant"),
    "openclaw.ai": ("Openclaw", "assistant"),
    "moltbook.com": ("Moltbook", "assistant"),
    "openwork.bot": ("Openwork", "assistant"),
    "craiyon.com": ("Craiyon", "assistant"),
    "magicstudio.com": ("Magicstudio", "assistant"),
    "getalpaca.io": ("Getalpaca", "assistant"),
    "patience.ai": ("Patience", "assistant"),
    "genshare.io": ("Genshare", "assistant"),
    "modyfi.com": ("Modyfi", "assistant"),
    "prisma-ai.com": ("Prisma Ai", "assistant"),
    "bing.com": ("Bing", "assistant"),
    "reve.com": ("Reve", "assistant"),
    "magnific.com": ("Magnific", "assistant"),
    "figurelabs.ai": ("Figurelabs", "assistant"),
    "brandmark.io": ("Brandmark", "assistant"),
    "designer.microsoft.com": ("Microsoft", "assistant"),
    "prompthero.com": ("Prompthero", "assistant"),
    "promptbase.com": ("Promptbase", "assistant"),
    "rentry.org": ("Rentry", "assistant"),
    "stablehorde.net": ("Stablehorde", "assistant"),
    "airtable.com": ("Airtable", "assistant"),
    "seed.bytedance.com": ("Bytedance", "assistant"),
    "affogato.ai": ("Affogato", "assistant"),

    # --- Search / answer engines ---
    "perplexity.ai": ("Perplexity", "search"), "you.com": ("You.com", "search"),
    "phind.com": ("Phind", "search"), "komo.ai": ("Komo", "search"),
    "andi.com": ("Andi", "search"), "consensus.app": ("Consensus", "search"),
    "elicit.com": ("Elicit", "search"), "scholarai.io": ("ScholarAI", "search"),
    "kagi.com": ("Kagi Assistant", "search"),
    "exa.ai": ("Exa", "search"),
    "iask.ai": ("iAsk", "search"),
    "andisearch.com": ("Andi", "search"),
    "genspark.ai": ("Genspark", "search"),
    "myninja.ai": ("Ninja AI", "search"),
    "glean.com": ("Glean", "search"),
    "dashworks.ai": ("Dashworks", "search"),
    "hebbia.com": ("Hebbia", "search"),
    "alphasense.com": ("AlphaSense", "search"),
    "openevidence.com": ("OpenEvidence", "search"),
    "scite.ai": ("Scite", "search"),
    "typeset.io": ("SciSpace", "search"),
    "felo.ai": ("Felo", "search"),
    "fintool.com": ("Fintool", "search"),
    "rogo.ai": ("Rogo", "search"),
    "onyx.app": ("Onyx", "search"),
    "hermes-agent.nousresearch.com": ("Nousresearch", "search"),

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
    "devv.ai": ("Devv", "coding"),
    "jetbrains.com/ai": ("JetBrains AI", "coding"),
    "augmentcode.com": ("Augment Code", "coding"),
    "supermaven.com": ("Supermaven", "coding"),
    "aider.chat": ("Aider", "coding"),
    "cline.bot": ("Cline", "coding"),
    "roocode.com": ("Roo Code", "coding"),
    "kilocode.ai": ("Kilo Code", "coding"),
    "warp.dev": ("Warp AI", "coding"),
    "zed.dev": ("Zed AI", "coding"),
    "trae.ai": ("Trae", "coding"),
    "factory.ai": ("Factory", "coding"),
    "all-hands.dev": ("OpenHands", "coding"),
    "qodo.ai": ("Qodo", "coding"),
    "tabbyml.com": ("TabbyML", "coding"),
    "sweep.dev": ("Sweep AI", "coding"),
    "ellipsis.dev": ("Ellipsis", "coding"),
    "coderabbit.ai": ("CodeRabbit", "coding"),
    "greptile.com": ("Greptile", "coding"),
    "graphite.dev": ("Graphite", "coding"),
    "codegen.com": ("Codegen", "coding"),
    "cognition.ai": ("Cognition (Devin)", "coding"),
    "jules.google.com": ("Jules", "coding"),
    "firebase.studio": ("Firebase Studio", "coding"),
    "idx.dev": ("Project IDX", "coding"),
    "ampcode.com": ("Amp (Sourcegraph)", "coding"),
    "pieces.app": ("Pieces", "coding"),
    "bito.ai": ("Bito", "coding"),
    "refact.ai": ("Refact", "coding"),
    "opencode.ai": ("opencode", "coding"),
    "kiro.dev": ("Kiro", "coding"),
    "poolside.ai": ("Poolside", "coding"),
    "magic.dev": ("Magic", "coding"),
    "tessl.io": ("Tessl", "coding"),
    "diffblue.com": ("Diffblue", "coding"),
    "testim.io": ("Testim", "coding"),
    "mabl.com": ("mabl", "coding"),
    "swimm.io": ("Swimm", "coding"),
    "sourcery.ai": ("Sourcery", "coding"),
    "emergent.sh": ("Emergent", "coding"),
    "create.xyz": ("Create", "coding"),
    "databutton.com": ("Databutton", "coding"),
    "base44.com": ("Base44", "coding"),
    "tempo.new": ("Tempo", "coding"),
    "kilo.ai": ("Kilo Code", "coding"),
    # Repo-to-prompt packagers: the entire point is shipping a codebase into an LLM, which
    # makes them a source-code egress path, not a general assistant.
    "gitingest.com": ("Gitingest", "coding"),
    "repomix.com": ("Repomix", "coding"),
    "stenography.dev": ("Stenography", "coding"),

    # --- Agents / automation ---
    "manus.im": ("Manus", "agent"), "devin.ai": ("Devin", "agent"),
    "flowith.io": ("Flowith", "agent"), "lindy.ai": ("Lindy", "agent"),
    "relevanceai.com": ("Relevance AI", "agent"), "crewai.com": ("CrewAI", "agent"),
    "n8n.io": ("n8n (AI)", "agent"), "make.com": ("Make (AI)", "agent"),
    "zapier.com/ai": ("Zapier AI", "agent"),
    "browser-use.com": ("Browser Use", "agent"),
    "hcompany.ai": ("H Company (Runner H)", "agent"),
    "adept.ai": ("Adept", "agent"),
    "gumloop.com": ("Gumloop", "agent"),
    "wordware.ai": ("Wordware", "agent"),
    "dust.tt": ("Dust", "agent"),
    "lutra.ai": ("Lutra", "agent"),
    "bardeen.ai": ("Bardeen", "agent"),
    "taskade.com": ("Taskade AI", "agent"),
    "ada.cx": ("Ada", "agent"),
    "fin.ai": ("Fin (Intercom)", "agent"),
    "sierra.ai": ("Sierra", "agent"),
    "decagon.ai": ("Decagon", "agent"),
    "11x.ai": ("11x", "agent"),
    "artisan.co": ("Artisan", "agent"),
    "langflow.org": ("Langflow", "agent"),
    "flowiseai.com": ("Flowise", "agent"),
    "stack-ai.com": ("StackAI", "agent"),
    "voiceflow.com": ("Voiceflow", "agent"),
    "botpress.com": ("Botpress", "agent"),
    "chatbase.co": ("Chatbase", "agent"),
    "composio.dev": ("Composio", "agent"),
    "vapi.ai": ("Vapi", "agent"),
    "retellai.com": ("Retell AI", "agent"),
    "bland.ai": ("Bland", "agent"),
    "synthflow.ai": ("Synthflow", "agent"),
    "forethought.ai": ("Forethought", "agent"),
    "kore.ai": ("Kore.ai", "agent"),
    "yellow.ai": ("Yellow.ai", "agent"),
    "clay.com": ("Clay", "agent"),
    "browserbase.com": ("Browserbase", "agent"),
    "griptape.ai": ("Griptape", "agent"),
    "letta.com": ("Letta", "agent"),
    "superagi.com": ("SuperAGI", "agent"),
    "relay.app": ("Relay", "agent"),
    "cassidyai.com": ("Cassidy", "agent"),
    "orby.ai": ("Orby", "agent"),
    "mavenagi.com": ("Maven AGI", "agent"),
    "paradox.ai": ("Paradox", "agent"),
    "nekton.ai": ("Nekton", "agent"),
    "agentset.ai": ("Agentset", "agent"),
    "agentmail.to": ("Agentmail", "agent"),
    "agentskills.io": ("Agentskills", "agent"),
    "autodesk.com": ("Autodesk", "agent"),

    # --- Writing / productivity ---
    "jasper.ai": ("Jasper", "writing"), "copy.ai": ("Copy.ai", "writing"),
    "writesonic.com": ("Writesonic", "writing"), "rytr.me": ("Rytr", "writing"),
    "grammarly.com": ("Grammarly (AI)", "writing"), "quillbot.com": ("QuillBot", "writing"),
    # Notion. The AI paths come first only for readability — classify() sorts by key length,
    # so "notion.so/ai" beats the bare host on a URL that really is the AI surface, and the
    # host answers for everything else. notion.com is the primary domain now; notion.so
    # still resolves and is what older CASB/DNS exports contain, so both are listed.
    #
    # The bare hosts are a deliberate broad net, unlike "aws.amazon.com" (see
    # catalog_pipeline.NEVER_CATALOG). Notion names one product and that product ships AI
    # into every page, so "someone is putting documents in Notion" is a finding worth
    # raising; an org that has approved it sanctions the tool once and the noise stops.
    # There is no hostname or stable public path that isolates a Notion AI call from an
    # ordinary page load — the in-product calls go to Notion's own undocumented client API
    # on the same host — so host-level is the only coverage available for DNS/CASB
    # telemetry, which carries no path at all.
    "notion.so/ai": ("Notion AI", "writing"), "notion.ai": ("Notion AI", "writing"),
    "notion.com/product/ai": ("Notion AI", "writing"), "notion.com/ai": ("Notion AI", "writing"),
    "notion.so": ("Notion", "writing"), "notion.com": ("Notion", "writing"),
    "sudowrite.com": ("Sudowrite", "writing"), "wordtune.com": ("Wordtune", "writing"),
    "gamma.app": ("Gamma", "writing"), "tome.app": ("Tome", "writing"),
    "writer.com": ("Writer", "writing"),
    "hyperwriteai.com": ("HyperWrite", "writing"),
    "lex.page": ("Lex", "writing"),
    "anyword.com": ("Anyword", "writing"),
    "simplified.com": ("Simplified", "writing"),
    "frase.io": ("Frase", "writing"),
    "surferseo.com": ("Surfer", "writing"),
    "scalenut.com": ("Scalenut", "writing"),
    "deepl.com": ("DeepL", "writing"),
    "languagetool.org": ("LanguageTool", "writing"),
    "prowritingaid.com": ("ProWritingAid", "writing"),
    "superhuman.com": ("Superhuman AI", "writing"),
    "shortwave.com": ("Shortwave", "writing"),
    "mem.ai": ("Mem", "writing"),
    "reflect.app": ("Reflect", "writing"),
    "slidesai.io": ("SlidesAI", "writing"),
    "beautiful.ai": ("Beautiful.ai", "writing"),
    "decktopus.com": ("Decktopus", "writing"),
    "presentations.ai": ("Presentations.AI", "writing"),
    "napkin.ai": ("Napkin", "writing"),
    "lavender.ai": ("Lavender", "writing"),
    "regie.ai": ("Regie.ai", "writing"),
    "hix.ai": ("HIX.AI", "writing"),
    "unbabel.com": ("Unbabel", "writing"),
    "lilt.com": ("Lilt", "writing"),
    "smartcat.com": ("Smartcat", "writing"),
    "textio.com": ("Textio", "writing"),
    "persado.com": ("Persado", "writing"),
    "compose.ai": ("Compose AI", "writing"),
    "paperpal.com": ("Paperpal", "writing"),
    "jenni.ai": ("Jenni", "writing"),
    "writefull.com": ("Writefull", "writing"),
    "trinka.ai": ("Trinka", "writing"),
    "copyleaks.com": ("Copyleaks", "writing"),
    "gptzero.me": ("GPTZero", "writing"),
    "originality.ai": ("Originality.ai", "writing"),
    "zerogpt.com": ("ZeroGPT", "writing"),
    "undetectable.ai": ("Undetectable AI", "writing"),
    "mintlify.com": ("Mintlify", "writing"),
    "tana.inc": ("Tana", "writing"),
    "fyxer.com": ("Fyxer", "writing"),
    "copysmith.ai": ("Copysmith", "writing"),
    "jetwriter.ai": ("JetWriter", "writing"),
    "gomoonbeam.com": ("Moonbeam", "writing"),
    "hypotenuse.ai": ("Hypotenuse AI", "writing"),
    "postwise.ai": ("Postwise", "writing"),
    "editgpt.app": ("editGPT", "writing"),
    "emailtriager.com": ("EmailTriager", "writing"),
    "aipoemgenerator.org": ("AI Poem Generator", "writing"),

    # --- Image / video / audio ---
    "midjourney.com": ("Midjourney", "image_video"), "labs.openai.com": ("DALL·E", "image_video"),
    "stability.ai": ("Stability AI", "image_video"), "leonardo.ai": ("Leonardo.Ai", "image_video"),
    "runwayml.com": ("Runway", "image_video"), "pika.art": ("Pika", "image_video"),
    "elevenlabs.io": ("ElevenLabs", "image_video"), "synthesia.io": ("Synthesia", "image_video"),
    "heygen.com": ("HeyGen", "image_video"), "descript.com": ("Descript", "image_video"),
    "suno.com": ("Suno", "image_video"), "udio.com": ("Udio", "image_video"),
    "ideogram.ai": ("Ideogram", "image_video"), "krea.ai": ("Krea", "image_video"),
    "civitai.com": ("Civitai", "image_video"), "kling.ai": ("Kling", "image_video"),
    "sora.com": ("Sora", "image_video"),
    "labs.google": ("Google Labs (ImageFX/Flow)", "image_video"),
    "firefly.adobe.com": ("Adobe Firefly", "image_video"),
    "lumalabs.ai": ("Luma Dream Machine", "image_video"),
    "pixverse.ai": ("PixVerse", "image_video"),
    "haiper.ai": ("Haiper", "image_video"),
    "genmo.ai": ("Genmo", "image_video"),
    "kaiber.ai": ("Kaiber", "image_video"),
    "opus.pro": ("OpusClip", "image_video"),
    "veed.io": ("VEED", "image_video"),
    "capcut.com": ("CapCut", "image_video"),
    "invideo.io": ("InVideo", "image_video"),
    "fliki.ai": ("Fliki", "image_video"),
    "pictory.ai": ("Pictory", "image_video"),
    "d-id.com": ("D-ID", "image_video"),
    "colossyan.com": ("Colossyan", "image_video"),
    "blackforestlabs.ai": ("Black Forest Labs (FLUX)", "image_video"),
    "recraft.ai": ("Recraft", "image_video"),
    "playground.com": ("Playground", "image_video"),
    "getimg.ai": ("Getimg", "image_video"),
    "nightcafe.studio": ("NightCafe", "image_video"),
    "openart.ai": ("OpenArt", "image_video"),
    "seaart.ai": ("SeaArt", "image_video"),
    "tensor.art": ("TensorArt", "image_video"),
    "dreamstudio.ai": ("DreamStudio", "image_video"),
    "clipdrop.co": ("Clipdrop", "image_video"),
    "photoroom.com": ("PhotoRoom", "image_video"),
    "remove.bg": ("remove.bg", "image_video"),
    "cutout.pro": ("Cutout.Pro", "image_video"),
    "fotor.com": ("Fotor AI", "image_video"),
    "canva.com": ("Canva (AI)", "image_video"),
    "topazlabs.com": ("Topaz Labs", "image_video"),
    "magnific.ai": ("Magnific", "image_video"),
    "freepik.com": ("Freepik AI", "image_video"),
    "lexica.art": ("Lexica", "image_video"),
    "resemble.ai": ("Resemble AI", "image_video"),
    "murf.ai": ("Murf", "image_video"),
    "wellsaidlabs.com": ("WellSaid", "image_video"),
    "lovo.ai": ("LOVO", "image_video"),
    "speechify.com": ("Speechify", "image_video"),
    "mubert.com": ("Mubert", "image_video"),
    "soundraw.io": ("Soundraw", "image_video"),
    "aiva.ai": ("AIVA", "image_video"),
    "podcast.adobe.com": ("Adobe Podcast", "image_video"),
    "rask.ai": ("Rask", "image_video"),
    "wondercraft.ai": ("Wondercraft", "image_video"),
    "captions.ai": ("Captions", "image_video"),
    "submagic.co": ("Submagic", "image_video"),
    "vizard.ai": ("Vizard", "image_video"),
    "klap.app": ("Klap", "image_video"),
    "higgsfield.ai": ("Higgsfield", "image_video"),
    "viggle.ai": ("Viggle", "image_video"),
    "pollo.ai": ("Pollo", "image_video"),
    "flair.ai": ("Flair", "image_video"),
    "interiorai.com": ("InteriorAI", "image_video"),
    "photoai.com": ("PhotoAI", "image_video"),
    "headshotpro.com": ("HeadshotPro", "image_video"),
    "looka.com": ("Looka", "image_video"),
    "designs.ai": ("Designs.ai", "image_video"),
    "uizard.io": ("Uizard", "image_video"),
    "tavus.io": ("Tavus", "image_video"),
    "argil.ai": ("Argil", "image_video"),
    "creatify.ai": ("Creatify", "image_video"),
    "arcads.ai": ("Arcads", "image_video"),
    "hedra.com": ("Hedra", "image_video"),
    "stableaudio.com": ("Stable Audio", "image_video"),
    "beatoven.ai": ("Beatoven", "image_video"),
    "fish.audio": ("Fish Audio", "image_video"),
    "imagen.research.google": ("Research", "image_video"),
    "artbreeder.com": ("Artbreeder", "image_video"),
    "rundiffusion.com": ("Rundiffusion", "image_video"),
    "publicprompts.art": ("Publicprompts", "image_video"),
    "hailuoai.video": ("Hailuoai", "image_video"),
    "maxvideoai.com": ("Maxvideoai", "image_video"),

    # --- Meeting / transcription notetakers (high data-exposure risk) ---
    "otter.ai": ("Otter.ai", "meeting"), "fireflies.ai": ("Fireflies.ai", "meeting"),
    "fathom.video": ("Fathom", "meeting"), "read.ai": ("Read AI", "meeting"),
    "tldv.io": ("tl;dv", "meeting"), "avoma.com": ("Avoma", "meeting"),
    "gong.io": ("Gong", "meeting"), "sembly.ai": ("Sembly", "meeting"),
    "granola.ai": ("Granola", "meeting"),
    "krisp.ai": ("Krisp", "meeting"),
    "circleback.ai": ("Circleback", "meeting"),
    "fellow.app": ("Fellow", "meeting"),
    "notta.ai": ("Notta", "meeting"),
    "chorus.ai": ("Chorus", "meeting"),
    "meetjamie.ai": ("Jamie", "meeting"),
    "tactiq.io": ("Tactiq", "meeting"),
    "supernormal.com": ("Supernormal", "meeting"),
    "nabla.com": ("Nabla", "meeting"),
    "abridge.com": ("Abridge", "meeting"),
    "suki.ai": ("Suki", "meeting"),
    "heidihealth.com": ("Heidi Health", "meeting"),
    "grain.com": ("Grain", "meeting"),
    "colibri.ai": ("Colibri", "meeting"),
    "timeos.ai": ("timeOS", "meeting"),
    "bluedothq.com": ("Bluedot", "meeting"),
    "ambiencehealthcare.com": ("Ambience", "meeting"),
    "deepscribe.ai": ("DeepScribe", "meeting"),
    "freed.ai": ("Freed", "meeting"),
    "plaud.ai": ("Plaud", "meeting"),
    "limitless.ai": ("Limitless", "meeting"),
    "rewind.ai": ("Rewind", "meeting"),
    "cogram.com": ("Cogram", "meeting"),
    "sybill.ai": ("Sybill", "meeting"),
    "loopinhq.com": ("Loopin", "meeting"),

    # --- ML platforms / model hubs / API providers ---
    "huggingface.co": ("Hugging Face", "ml_platform"), "replicate.com": ("Replicate", "ml_platform"),
    "together.ai": ("Together AI", "api"), "fireworks.ai": ("Fireworks AI", "api"),
    "groq.com": ("Groq", "api"), "openrouter.ai": ("OpenRouter", "api"),
    "cohere.com": ("Cohere", "api"), "ai21.com": ("AI21", "api"),
    "api.anthropic.com": ("Anthropic API", "api"), "api.openai.com": ("OpenAI API", "api"),
    "generativelanguage.googleapis.com": ("Gemini API", "api"),
    "bedrock.amazonaws.com": ("Amazon Bedrock", "api"), "perplexity.ai/api": ("Perplexity API", "api"),
    "langchain.com": ("LangChain / LangSmith", "ml_platform"),
    "llamaindex.ai": ("LlamaIndex", "ml_platform"),
    "ollama.com": ("Ollama", "ml_platform"),
    "lmstudio.ai": ("LM Studio", "ml_platform"),
    "modal.com": ("Modal", "ml_platform"),
    "baseten.co": ("Baseten", "ml_platform"),
    "anyscale.com": ("Anyscale", "ml_platform"),
    "databricks.com": ("Databricks (AI)", "ml_platform"),
    "wandb.ai": ("Weights & Biases", "ml_platform"),
    "comet.com": ("Comet ML", "ml_platform"),
    "runpod.io": ("RunPod", "ml_platform"),
    "vast.ai": ("Vast.ai", "ml_platform"),
    "lambdalabs.com": ("Lambda", "ml_platform"),
    "coreweave.com": ("CoreWeave", "ml_platform"),
    "paperspace.com": ("Paperspace", "ml_platform"),
    "nebius.com": ("Nebius", "ml_platform"),
    "pinecone.io": ("Pinecone", "ml_platform"),
    "weaviate.io": ("Weaviate", "ml_platform"),
    "qdrant.tech": ("Qdrant", "ml_platform"),
    "trychroma.com": ("Chroma", "ml_platform"),
    "zilliz.com": ("Zilliz", "ml_platform"),
    "unstructured.io": ("Unstructured", "ml_platform"),
    "langfuse.com": ("Langfuse", "ml_platform"),
    "helicone.ai": ("Helicone", "ml_platform"),
    "braintrust.dev": ("Braintrust", "ml_platform"),
    "humanloop.com": ("Humanloop", "ml_platform"),
    "promptlayer.com": ("PromptLayer", "ml_platform"),
    "arize.com": ("Arize", "ml_platform"),
    "fiddler.ai": ("Fiddler", "ml_platform"),
    "scale.com": ("Scale AI", "ml_platform"),
    "labelbox.com": ("Labelbox", "ml_platform"),
    "snorkel.ai": ("Snorkel", "ml_platform"),
    "predibase.com": ("Predibase", "ml_platform"),
    "openai.azure.com": ("Azure OpenAI", "api"),
    "aiplatform.googleapis.com": ("Vertex AI API", "api"),
    "build.nvidia.com": ("NVIDIA NIM", "api"),
    "cerebras.ai": ("Cerebras", "api"),
    "sambanova.ai": ("SambaNova", "api"),
    "deepinfra.com": ("DeepInfra", "api"),
    "hyperbolic.xyz": ("Hyperbolic", "api"),
    "novita.ai": ("Novita", "api"),
    "siliconflow.cn": ("SiliconFlow", "api"),
    "open.bigmodel.cn": ("Zhipu API", "api"),
    "fal.ai": ("fal", "api"),
    "e2b.dev": ("E2B", "api"),
    "deepgram.com": ("Deepgram", "api"),
    "assemblyai.com": ("AssemblyAI", "api"),
    "cartesia.ai": ("Cartesia", "api"),
    "tavily.com": ("Tavily", "api"),
    "beam.cloud": ("Beam", "ml_platform"),
    "lightning.ai": ("Lightning AI", "ml_platform"),
    "neptune.ai": ("Neptune", "ml_platform"),
    "clear.ml": ("ClearML", "ml_platform"),
    "dominodatalab.com": ("Domino", "ml_platform"),
    "dataiku.com": ("Dataiku", "ml_platform"),
    "h2o.ai": ("H2O.ai", "ml_platform"),
    "datarobot.com": ("DataRobot", "ml_platform"),
    "nomic.ai": ("Nomic", "ml_platform"),
    "deepnote.com": ("Deepnote", "ml_platform"),
    "hex.tech": ("Hex", "ml_platform"),
    "aws.amazon.com/sagemaker": ("Amazon SageMaker", "ml_platform"),
    "dashscope.aliyun.com": ("Qwen API (DashScope)", "api"),
    "volcengine.com": ("Volcano Engine (Doubao)", "api"),
    "upstage.ai": ("Upstage", "api"),
    "aleph-alpha.com": ("Aleph Alpha", "api"),
    "lighton.ai": ("LightOn", "api"),
    "sarvam.ai": ("Sarvam", "api"),
    "ai.azure.com": ("Azure AI Foundry", "api"),
    "featherless.ai": ("Featherless", "api"),
    "lepton.ai": ("Lepton", "api"),
    "voyageai.com": ("Voyage AI", "api"),
    "jina.ai": ("Jina AI", "api"),
    "firecrawl.dev": ("Firecrawl", "api"),
    "speechmatics.com": ("Speechmatics", "api"),
    "gladia.io": ("Gladia", "api"),
    "hume.ai": ("Hume", "api"),
    "rime.ai": ("Rime", "api"),
    "serper.dev": ("Serper", "api"),
    "llama.com": ("Meta Llama", "ml_platform"),
    "unsloth.ai": ("Unsloth", "ml_platform"),
    "cleanlab.ai": ("Cleanlab", "ml_platform"),
    "haystack.deepset.ai": ("deepset Haystack", "ml_platform"),
    "portkey.ai": ("Portkey", "api"),
}

# Rows recorded from vendor marketing/site rather than a verified traffic capture: the
# tool is real, but the hostnames its client actually talks to are UNVERIFIED. Discovery
# still names them (a hit is a hit), but classify()/classify_name() mark the hit
# `provisional: True` so console/report copy can caveat it — and the egress proxy must
# NOT add these to its intercept/parse list until a real capture confirms the API hosts.
# Dia: macOS-only (Apple Silicon); its AI sidebar talks to Dia's hosted backend, whose
# real API hostnames need a mitmproxy capture — runbook in
# docs/agentic-browser-verification.md ("Dia").
PROVISIONAL: frozenset[str] = frozenset({"diabrowser.com"})

CATEGORY_LABEL = {
    "assistant": "AI assistant", "coding": "Coding assistant", "image_video": "Image / video / audio",
    "writing": "Writing / docs", "search": "AI search", "meeting": "Meeting notetaker",
    "agent": "Agent / automation", "ml_platform": "ML platform", "api": "Model API",
}

# Local capture planes → the AI tool/platform they govern. MCP-surface captures (Cursor
# shell/tool calls, Claude Code / Gemini / Codex hooks, agent MCP) carry no destination
# domain, so the *plane's identity* (its User-Agent) is what names the tool for discovery.
CLIENT_TOOLS: dict[str, tuple[str, str]] = {
    "palivane-cursor-hook": ("Cursor", "coding"),
    "palivane-hook": ("Claude Code", "coding"),
    "palivane-gemini-hook": ("Gemini CLI", "coding"),
    "palivane-codex-hook": ("Codex CLI", "coding"),
    "palivane-copilot-hook": ("GitHub Copilot", "coding"),
    "palivane-mcp": ("MCP client", "agent"),
}


def classify_client(user_agent: str) -> dict | None:
    """Map a capture-plane User-Agent (e.g. 'palivane-cursor-hook/1.0') to the AI tool it
    governs — for discovery of MCP-surface usage that has no destination domain. None if the
    UA isn't a recognized local plane (e.g. the egress proxy, which fronts many tools)."""
    ua = (user_agent or "").strip().lower()
    if not ua:
        return None
    for key, (name, cat) in CLIENT_TOOLS.items():
        if key in ua:
            return {"tool": name, "category": cat, "domain": key}
    return None


def _key_matches(key: str, low: str) -> bool:
    """Substring match anchored at label boundaries: the char before/after the hit must not
    be part of a hostname label ([a-z0-9-]). Without this, short domain keys swallow longer
    unrelated ones — 'x.ai' (Grok) would claim 11x.ai, hix.ai, and llamaindex.ai, and
    'pi.ai' (Pi) would claim vapi.ai. '/'-delimited hits (URLs, path keys) still match."""
    i = low.find(key)
    while i != -1:
        before = low[i - 1] if i > 0 else ""
        after_i = i + len(key)
        after = low[after_i] if after_i < len(low) else ""
        if (not (before.isalnum() or before == "-")
                and not (after.isalnum() or after == "-")):
            return True
        i = low.find(key, i + 1)
    return False


def classify(text: str) -> dict | None:
    """Resolve a destination (URL / domain / tool name) to {tool, category, domain}.
    Longest key first so 'github.com/copilot' wins over a bare 'github.com'. None if unknown."""
    if not text:
        return None
    low = text.strip().lower()
    for key in sorted(CATALOG, key=len, reverse=True):
        if _key_matches(key, low):
            name, cat = CATALOG[key]
            hit = {"tool": name, "category": cat, "domain": key}
            if key in PROVISIONAL:
                hit["provisional"] = True
            return hit
    return None


# Canonical tool name (lowercased) -> (name, category), longest first — for matching a
# display NAME ("ChatGPT", "Claude for Sheets") rather than a domain. Built once.
_NAME_INDEX = sorted(
    {v[0].lower(): v for v in CATALOG.values()}.items(),
    key=lambda kv: len(kv[0]), reverse=True)

# Canonical names of PROVISIONAL rows, so name-based hits carry the same caveat.
_PROVISIONAL_NAMES = frozenset(CATALOG[d][0].lower() for d in PROVISIONAL)


def classify_name(text: str) -> dict | None:
    """Resolve an app DISPLAY NAME to a catalog tool. Tries the domain matcher first (a name
    may embed a domain), then matches against canonical tool names — 'ChatGPT for Slack'
    resolves to ChatGPT. None if unknown."""
    hit = classify(text)
    if hit:
        return hit
    low = (text or "").strip().lower()
    if not low:
        return None
    for nm, (name, cat) in _NAME_INDEX:
        if len(nm) >= 3 and _key_matches(nm, low):
            hit = {"tool": name, "category": cat, "domain": ""}
            if nm in _PROVISIONAL_NAMES:
                hit["provisional"] = True
            return hit
    return None
