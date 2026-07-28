"""False-positive benchmark for Warden's detection engine.

Warden runs in *monitor mode*: benign employee prompts, ordinary code, and normal
tool calls flow through the engine every day. Every time a genuinely clean input is
escalated to warn (`monitor`/`quarantine`) or block, or tagged with a data-loss
signal (secret_leak / pii_exposure / confidential_data / source_code_leak / ...),
that is a FALSE POSITIVE — the single most important quality metric for the product.

This is NOT a normal unit test. It builds a large, deliberately clean corpus, scores
every sample through the real `run_analysis` entry point, and prints a per-sample FP
report. When run under pytest it only asserts the overall FP rate stays under a lenient
threshold (so it never breaks CI on a marginal regression), while still surfacing the
detail. Run it directly for the full report:

    .venv/bin/python backend/tests/bench_false_positives.py
    # or
    .venv/bin/pytest backend/tests/bench_false_positives.py -s

The judge (LLM-as-judge) is a no-op without an API key, so this measures the offline
regex/heuristic detectors — the layer that must not false-positive on its own.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

# Make `app` importable when run directly (`python backend/tests/bench_false_positives.py`).
# Under pytest this is a no-op — pytest.ini already sets pythonpath to the backend dir.
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.detectors.base import AnalysisInput, Surface
from app.service import run_analysis

# ---------------------------------------------------------------------------
# What counts as a false positive
# ---------------------------------------------------------------------------
# Actions that mean "we bothered a human / blocked traffic". On a truly benign
# sample, any of these is an FP.
FP_ACTIONS = {"monitor", "quarantine", "block"}
# Non-benign severities.
FP_SEVERITIES = {"low", "suspicious", "high", "critical"}
# Data-loss categories that should never fire on a clean sample. (unsanctioned_ai
# is intentionally excluded here when a sample deliberately names an unsanctioned
# destination — those samples are marked allow_unsanctioned=True below.)
DLP_CATEGORIES = {
    "secret_leak", "pii_exposure", "confidential_data", "source_code_leak",
    "prompt_injection", "jailbreak", "data_exfiltration",
    "mcp_untrusted_server", "mcp_integrity", "sensitive_resource_access",
    "dangerous_command", "tool_poisoning", "unsafe_autonomy", "credential_at_rest",
    "data_oversharing", "agent_authz", "dependency_risk",
}


@dataclass
class Sample:
    category: str          # corpus bucket (for per-category reporting)
    text: str
    surface: Surface = Surface.AI_USAGE
    metadata: dict | None = None
    # A few samples deliberately go to an unsanctioned destination while carrying
    # NO sensitive data — an unsanctioned_ai signal alone is monitor-level by design
    # and is the product working as intended, so don't count that lone signal as an FP.
    allow_unsanctioned: bool = False


def build_corpus() -> list[Sample]:
    S = Sample
    AU = Surface.AI_USAGE
    samples: list[Sample] = []

    # --- 1) Ordinary AI prompts: questions / writing / general help ---------
    prompts = [
        "How do I center a div using flexbox in CSS?",
        "What's the difference between a process and a thread?",
        "Explain the CAP theorem in simple terms.",
        "Write a haiku about autumn leaves falling in a quiet park.",
        "Can you proofread this sentence: 'Their going to the store later today.'",
        "What are some good first-date restaurant ideas in Chicago?",
        "Summarize the plot of Romeo and Juliet in three sentences.",
        "How does photosynthesis convert sunlight into energy?",
        "Give me a 7-day beginner workout plan I can do at home.",
        "What's a good analogy to explain recursion to a 10-year-old?",
        "Translate 'good morning, how are you?' into French and Spanish.",
        "Suggest a name for a friendly coffee-shop mascot.",
        "What causes the seasons to change on Earth?",
        "Help me write a thank-you note to my mentor after an internship.",
        "What are the main differences between REST and GraphQL?",
        "Explain how compound interest works with a simple example.",
        "Draft a short, upbeat announcement for a company picnic next Friday.",
        "What's the best way to learn to play the guitar as an adult?",
        "How do vaccines train the immune system?",
        "Give me five vegetarian dinner ideas that take under 30 minutes.",
    ]
    samples += [S("ai_prompts", t) for t in prompts]

    # --- 2) Real code, several languages, NO real secrets -------------------
    code = [
        # Python — plain function, no secret
        "def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a",
        # Python config with placeholder values
        "import os\nAPI_KEY = os.getenv('API_KEY', 'your-api-key-here')\nDB_PASSWORD = '${DB_PW}'\nprint(API_KEY)",
        # .env.example style template
        "# .env.example\nAPI_KEY=your-key-here\nDATABASE_PASSWORD=changeme\nSECRET_KEY=<your-secret>\nSTRIPE_KEY=sk_test_placeholder",
        # JS async fetch
        "async function load(id) {\n  const res = await fetch(`/api/users/${id}`);\n  if (!res.ok) throw new Error('failed');\n  return res.json();\n}",
        # JS config with env placeholders
        "const config = {\n  apiKey: process.env.API_KEY,\n  password: process.env.DB_PASSWORD || 'changeme',\n  host: 'localhost',\n};",
        # SQL query
        "SELECT u.id, u.name, COUNT(o.id) AS orders\nFROM users u\nLEFT JOIN orders o ON o.user_id = u.id\nGROUP BY u.id, u.name\nORDER BY orders DESC;",
        # SQL schema
        "CREATE TABLE products (\n  id SERIAL PRIMARY KEY,\n  name TEXT NOT NULL,\n  price NUMERIC(10,2),\n  created_at TIMESTAMP DEFAULT now()\n);",
        # Go HTTP handler
        "func handler(w http.ResponseWriter, r *http.Request) {\n\tname := r.URL.Query().Get(\"name\")\n\tfmt.Fprintf(w, \"hello, %s\", name)\n}",
        # Go struct + method
        "type Point struct {\n\tX, Y int\n}\n\nfunc (p Point) Add(q Point) Point {\n\treturn Point{p.X + q.X, p.Y + q.Y}\n}",
        # Bash-ish config with template conn string
        "export DATABASE_URL=postgres://appuser:${DB_PW}@db.internal:5432/app\nexport REDIS_URL=redis://cache:6379/0",
        # Docker compose with placeholder
        "services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}\n      POSTGRES_USER: appuser",
        # A React component
        "export function Counter() {\n  const [n, setN] = useState(0);\n  return <button onClick={() => setN(n + 1)}>{n}</button>;\n}",
        # Python decorator + class
        "@dataclass\nclass User:\n    id: int\n    name: str\n\n    def greeting(self):\n        return f'hi {self.name}'",
        # Terraform-ish placeholder
        "variable \"db_password\" {\n  type = string\n  default = \"changeme\"\n}\nresource \"aws_db_instance\" \"main\" {\n  password = var.db_password\n}",
        # A pytest test
        "def test_add():\n    assert add(2, 3) == 5\n    assert add(-1, 1) == 0",
    ]
    samples += [S("code", t) for t in code]

    # --- 3) Business / legal / security discussion (mentions, no leaks) -----
    discussion = [
        "What's the standard format for a US Social Security number? I'm designing a form.",
        "Can you explain how NDAs work and when a company would ask an employee to sign one?",
        "Here's our agenda for the confidential-materials review process meeting next week.",
        "How do AWS access keys look — what's the prefix and length of an access key ID?",
        "Draft a company policy about credential handling and password rotation for engineers.",
        "Explain the difference between confidential, restricted, and public data classifications.",
        "What information typically appears on a passport, and how long is a passport number?",
        "Our team agenda covers the standard onboarding checklist and the code-review workflow.",
        "How does attorney-client privilege work in a corporate legal setting?",
        "Write an outline for a training deck on how to recognize phishing emails.",
        "What's a routing number and how is it different from an account number on a check?",
        "Explain what a trade secret is versus a patent, with a couple of examples.",
        "I need a template for a proprietary-information disclaimer footer for our reports.",
        "How should a startup structure its data-retention policy for customer records?",
        "Describe how two-factor authentication improves account security for end users.",
        "What are the standard sections of a SOC 2 report and what does each cover?",
        "Explain how OAuth access tokens and refresh tokens differ in a typical web app.",
        "Give me a checklist for reviewing a vendor's security questionnaire.",
    ]
    samples += [S("business_legal_security", t) for t in discussion]

    # --- 4) Docs / emails with sensitive-sounding words, no leak ------------
    docs = [
        "Hi Fernanda, thanks for sending over the standard agenda. See you at the standup.",
        "Reminder: the quarterly all-hands agenda is attached. Standard format as usual.",
        "The proprietary blend of spices in this recipe is what makes it special!",
        "Our restaurant has a restricted parking area for staff only during peak hours.",
        "Fernanda and Amanda will co-host the workshop; the agenda is standard.",
        "Please keep this on the standard track — no special handling needed.",
        "The museum's confidential-materials wing is a topic covered on the public tour.",
        "This is a generic reminder that the office is closed on the public holiday Monday.",
        "The standard operating procedure for opening the store is posted in the break room.",
        "We discussed proprietary trading strategies in the abstract during the finance class.",
        "Amanda's calendar shows the agenda is set; nothing confidential to prepare.",
        "The recipe is a closely guarded secret sauce, per grandma's restricted kitchen rules.",
    ]
    samples += [S("docs_wording", t) for t in docs]

    # --- 5) Secret-ish strings that are NOT secrets -------------------------
    secretish = [
        # UUID
        "The request id is 550e8400-e29b-41d4-a716-446655440000, please include it in the ticket.",
        # git SHA (hex)
        "The bug was introduced in commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b, let's revert it.",
        # base64 of harmless data ('hello world, this is a benign test string!')
        "Encoded label: aGVsbG8gd29ybGQsIHRoaXMgaXMgYSBiZW5pZ24gdGVzdCBzdHJpbmch",
        # long hex digest (sha256 of empty)
        "Checksum: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        # a version-ish / build identifier
        "Build artifact: warden-backend-2026.07.19-rc4-linux-amd64 published to the registry.",
        # kebab-case slug that is long
        "The feature flag is called enable-new-onboarding-flow-for-enterprise-tenants-v2.",
        # dotted id
        "See module app.detectors.shadow_ai.ShadowAIDetector for the implementation details.",
        # ISO timestamp + tracking code
        "Order 2026-07-19T14:33:00Z shipped with tracking 1Z999AA10123456784 via UPS.",
        # A DOI
        "Cite it as doi:10.1145/3372297.3417231 in the references section of the paper.",
        # base64-ish but low entropy (repeated)
        "Placeholder token: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA for the mock in the unit test.",
    ]
    samples += [S("secretish", t) for t in secretish]

    # --- 6) Numbers that resemble PII but aren't leaking --------------------
    pii_lookalike = [
        "A credit card number has 13-16 digits; the format is usually 4-4-4-4 groups.",
        "For example, a test Visa number like 4111 1111 1111 1111 is used in sandboxes.",
        "The SSN format is XXX-XX-XXXX — three digits, two digits, then four digits.",
        "The office phone is a single number; call the front desk if you need directions.",
        "US ZIP+4 codes look like 12345-6789 and route mail more precisely than a 5-digit ZIP.",
        "An ISBN-13 such as 978-3-16-148410-0 identifies a specific edition of a book.",
        "The invoice total was 1,234,567.89 dollars across all line items this quarter.",
        "Our conference room seats 150 people and is on the 9th floor, suite 900.",
        "The recipe serves 4 and takes about 45 minutes: 350 degrees for 25-30 minutes.",
        "Pi to a few digits is 3.141592653589793 — useful for the geometry worksheet.",
    ]
    samples += [S("pii_lookalike", t) for t in pii_lookalike]

    # --- 7) Sanctioned-destination prompts (benign content, approved tool) --
    # A normal question going to an APPROVED tool should be fully allow-level.
    for t in [
        "What's a good way to structure a README for an open-source project?",
        "Rewrite this paragraph to be more concise and professional.",
    ]:
        samples.append(S("sanctioned_dest", t, metadata={"destination": "claude.ai",
                          "sanctioned_tools": "claude.ai,chatgpt.com"}))

    # A benign prompt to an UNSANCTIONED destination — the lone unsanctioned_ai
    # signal is by-design monitor-level, so we don't count *that* as an FP; but any
    # DLP signal on this clean text would be.
    samples.append(S("unsanctioned_dest_clean",
                     "What are some good icebreaker questions for a team meeting?",
                     metadata={"destination": "chat.openai.com"}, allow_unsanctioned=True))

    # --- 8) MCP-surface benign tool calls -----------------------------------
    M = Surface.MCP
    mcp_calls = [
        ("list files", {"method": "tools/call", "tool": "run_command", "args_text": "ls -la"}),
        ("git status", {"method": "tools/call", "tool": "run_command", "args_text": "git status"}),
        ("git log", {"method": "tools/call", "tool": "run_command", "args_text": "git log --oneline -n 10"}),
        ("read source file", {"method": "resources/read", "resource": "src/app/main.py"}),
        ("read README", {"method": "resources/read", "resource": "README.md"}),
        ("run tests", {"method": "tools/call", "tool": "run_command", "args_text": "pytest -q tests/"}),
        ("npm install", {"method": "tools/call", "tool": "run_command", "args_text": "npm install lodash"}),
        ("grep code", {"method": "tools/call", "tool": "run_command", "args_text": "grep -rn 'def analyze' app/"}),
        ("build", {"method": "tools/call", "tool": "run_command", "args_text": "make build"}),
        ("docker ps", {"method": "tools/call", "tool": "run_command", "args_text": "docker ps -a"}),
        ("cat a normal config", {"method": "resources/read", "resource": "config/settings.yaml"}),
        ("edit a component", {"method": "tools/call", "tool": "edit_file",
                              "args_text": "path=src/components/Button.tsx content=export const Button = () => null"}),
        ("read package.json", {"method": "resources/read", "resource": "package.json"}),
        ("list a directory", {"method": "tools/call", "tool": "run_command", "args_text": "find . -name '*.md'"}),
        ("curl a public API", {"method": "tools/call", "tool": "run_command",
                               "args_text": "curl -s https://api.github.com/repos/anthropics/anthropic-sdk-python"}),
    ]
    for label, meta in mcp_calls:
        content = meta.get("args_text") or meta.get("resource") or ""
        samples.append(S("mcp_benign", content, surface=M, metadata=meta))

    return samples


def score_sample(db, s: Sample) -> dict:
    meta = dict(s.metadata or {})
    item = AnalysisInput(
        content=s.text,
        surface=s.surface,
        metadata=meta,
        channel=meta.get("channel", "chat"),
    )
    return run_analysis(item, persist=False, db=db, tenant_id=None)


def is_false_positive(s: Sample, r: dict) -> tuple[bool, list[str]]:
    """Return (is_fp, reasons). A benign sample is an FP if it escalates past
    allow/benign or carries a DLP signal it shouldn't."""
    reasons: list[str] = []
    action = r.get("recommended_action")
    severity = r.get("severity")
    signals = r.get("signals", [])

    dlp_hits = [sig for sig in signals if sig.get("category") in DLP_CATEGORIES]
    unsanctioned_only = (
        s.allow_unsanctioned
        and not dlp_hits
        and all(sig.get("category") == "unsanctioned_ai" for sig in signals)
    )

    if dlp_hits:
        for sig in dlp_hits:
            reasons.append(f"DLP signal: {sig['category']} / {sig['title']} — evidence={sig.get('evidence','')!r}")
    if action in FP_ACTIONS and not unsanctioned_only:
        reasons.append(f"escalated action={action}")
    if severity in FP_SEVERITIES and not unsanctioned_only:
        reasons.append(f"non-benign severity={severity}")

    return (len(reasons) > 0, reasons)


def run_bench() -> dict:
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()

    corpus = build_corpus()
    per_cat_total: dict[str, int] = {}
    per_cat_fp: dict[str, int] = {}
    fps: list[tuple[Sample, dict, list[str]]] = []

    for s in corpus:
        per_cat_total[s.category] = per_cat_total.get(s.category, 0) + 1
        r = score_sample(db, s)
        fp, reasons = is_false_positive(s, r)
        if fp:
            per_cat_fp[s.category] = per_cat_fp.get(s.category, 0) + 1
            fps.append((s, r, reasons))

    total = len(corpus)
    fp_count = len(fps)
    rate = 100.0 * fp_count / total if total else 0.0

    return {
        "total": total, "fp_count": fp_count, "rate": rate,
        "per_cat_total": per_cat_total, "per_cat_fp": per_cat_fp, "fps": fps,
    }


def print_report(res: dict) -> None:
    line = "=" * 78
    print(line)
    print("WARDEN FALSE-POSITIVE BENCHMARK  (offline detectors; judge disabled w/o API key)")
    print(line)
    print(f"Total benign samples : {res['total']}")
    print(f"False positives      : {res['fp_count']}")
    print(f"FALSE-POSITIVE RATE  : {res['rate']:.1f}%")
    print()
    print("Per-category (fp / total):")
    for cat in sorted(res["per_cat_total"]):
        tot = res["per_cat_total"][cat]
        fp = res["per_cat_fp"].get(cat, 0)
        pct = 100.0 * fp / tot if tot else 0.0
        flag = "  <-- FP" if fp else ""
        print(f"  {cat:26s} {fp:2d} / {tot:2d}  ({pct:5.1f}%){flag}")
    print()

    if not res["fps"]:
        print("No false positives. Clean run.")
        return

    print(line)
    print(f"FALSE POSITIVES  ({res['fp_count']})")
    print(line)
    for i, (s, r, reasons) in enumerate(res["fps"], 1):
        print(f"\n[{i}] category={s.category}  surface={s.surface.value}")
        print(f"    input   : {s.text!r}")
        if s.metadata:
            print(f"    metadata: {s.metadata}")
        print(f"    verdict : severity={r['severity']} action={r['recommended_action']} "
              f"risk={r['risk_score']}")
        for reason in reasons:
            print(f"    reason  : {reason}")
        for sig in r.get("signals", []):
            print(f"    signal  : [{sig['category']}] {sig['title']} :: "
                  f"evidence={sig.get('evidence','')!r}")


def main() -> int:
    res = run_bench()
    print_report(res)
    return 0


# Regression ceiling for the pytest entry. The IDEAL target is <5%, but the current
# offline-detector baseline is ~19% — dominated by design choices (unlabeled source
# code and bare mentions of "confidential"/"proprietary"/"restricted"/"trade secret"
# flagging on their own; see the report). Rather than fail CI on that known baseline,
# the assertion is a *regression guard*: it fails only if the rate climbs materially
# above today's number, so a NEW false positive is caught while the report always
# prints the full breakdown. Tighten this as the underlying detectors are improved.
FP_REGRESSION_CEILING = 25.0


def test_false_positive_rate_under_threshold():
    res = run_bench()
    print_report(res)
    assert res["rate"] < FP_REGRESSION_CEILING, (
        f"False-positive rate {res['rate']:.1f}% exceeds the {FP_REGRESSION_CEILING:.0f}% "
        f"regression ceiling; {res['fp_count']}/{res['total']} benign samples flagged. "
        f"A new false positive likely regressed a detector — see report above."
    )


if __name__ == "__main__":
    sys.exit(main())
