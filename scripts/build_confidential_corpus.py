#!/usr/bin/env python3
"""Synthetic training corpus for the CONFIDENTIAL-CONTENT classifier.

The shipped `confidential_data` signal fires on explicit markers only: the word
"confidential", or an applied sensitivity label (Purview/MIP/TLP). An unlabelled M&A term
sheet, a pipeline export or a comp spreadsheet is invisible to it — and unlabelled is how
this material actually travels. That is the gap a classifier closes, and it is the same gap
Harmonic's small language models are sold on.

Two design choices, both borrowed from what Harmonic published about how they built theirs:

1. **Synthetic data for TRAINING is legitimate.** They generated theirs with an LLM and
   multiplied their training set 10-15x. What is NOT legitimate is a synthetic holdout, and
   the gate in scripts/train_classifier.py already refuses one (`source: "synthetic"` rows
   disqualify the evaluation). So this file is allowed to be the training half and can never
   be the half that decides.

2. **Near-misses are the point.** A classifier that separates "M&A term sheet" from "cat
   photo" is worthless; every real false positive lives in text that shares the vocabulary —
   a published earnings release, a public pricing page, a job ad quoting a salary band, a
   sample contract from a template site. Those are generated deliberately and labelled
   benign, in volume, because a shipped classifier lives or dies on that tail.

Each row carries a `category` alongside the binary label. The model trained here is binary
(confidential / not), which is the signal the engine needs; keeping the category means a
later multi-label upgrade is a training question, not a re-labelling project.

    python scripts/build_confidential_corpus.py --out corpus.jsonl
"""
from __future__ import annotations

import argparse
import itertools
import json
import random
import sys

# --- confidential material, by category ---------------------------------------------------
# Phrasings avoid the words the regex path already catches ("confidential", "internal only",
# TLP/Purview labels): this model exists to catch what carries no marker at all. A template
# that leans on the marker would teach it to duplicate the regex.
_CONFIDENTIAL = {
    "m_and_a": [
        "Draft terms for the {target} acquisition: {mult}x forward revenue, {pct}% cash at close, "
        "the rest in {acq} stock vesting over {yrs} years.",
        "Diligence flagged a {issue} at {target}; we are proposing an escrow of {money} against it "
        "before we sign.",
        "The board approved moving to exclusivity with {target} at a headline number of {money}. "
        "Do not discuss outside the deal team.",
        "{acq} and {target} signed the LOI last night. Announcement is scheduled for {when}, so "
        "keep this off email threads with the wider org until then.",
    ],
    "financials": [
        "Unreleased {quarter} numbers: revenue {money}, gross margin {pct}%, net burn {money2} — "
        "we are {delta} against the plan we gave the board.",
        "Cap table after the {round}: founders {pct}%, employee pool {pct2}%, {acq} takes the rest "
        "at a {money} post-money.",
        "The forecast we are actually running to has {quarter} landing at {money}, not the {money2} "
        "in the deck we showed the bank.",
        "Runway model says {yrs} years at current burn; if the {target} renewal slips we drop under "
        "18 months and need to talk about the bridge.",
    ],
    "sales_pipeline": [
        "Q{q} commit list: {company} {money} (verbal), {company2} {money2} (legal review), "
        "{company3} slipping to next quarter after their reorg.",
        "{company} is at risk — their champion left and the new {role} is evaluating {competitor}. "
        "ARR exposure is {money}.",
        "Discount approval needed: {company} wants {pct}% off list to sign a {yrs}-year deal worth "
        "{money}. Our floor on this segment is {pct2}%.",
        "Churn forecast has {company} and {company2} both non-renewing in {quarter}, which is "
        "{money} out of the number.",
    ],
    "legal": [
        "Settlement terms with {company}: {money} paid over {yrs} years, no admission, mutual "
        "non-disparagement. Counsel wants this held to the smallest possible group.",
        "The {company} MSA has an uncapped indemnity in section 9 that our own counsel flagged; "
        "we signed it anyway to close {quarter}.",
        "We received a preservation notice related to the {target} matter. Stop deleting anything "
        "in the {store} until legal says otherwise.",
        "Draft response to the regulator on the {issue}: we acknowledge the gap and commit to "
        "remediation by {when}.",
    ],
    "strategy": [
        "Reorg plan for {quarter}: {role} function folds into platform, {n} roles are eliminated, "
        "announcement {when}.",
        "We are sunsetting the {product} line in {quarter} and migrating the {n} remaining accounts "
        "onto {product2} without announcing an EOL publicly.",
        "Pricing change under consideration: move {product} to consumption billing, which models to "
        "{pct}% expansion but risks {company} renegotiating.",
        "The plan if the {round} does not close is a {pct}% reduction in force in {quarter} and a "
        "pivot to the {product2} segment.",
    ],
    "personnel": [
        "Comp review outcomes: {person} to {money} base plus {pct}% target, {person2} held flat "
        "pending the performance conversation.",
        "{person} is on a performance plan closing {when}; if it does not turn around we separate "
        "in {quarter}.",
        "Offer approved for the {role} req at {money} base, {pct}% bonus, {n}k options — above band, "
        "justified by the counteroffer from {competitor}.",
        "Investigation notes on the {issue} complaint involving {person}: HR recommends "
        "{outcome} and legal has reviewed.",
    ],
}

# --- near-misses: the same vocabulary, none of the sensitivity -----------------------------
# Every one of these SHOULD be allowed. They are the reason the model cannot simply learn
# "mentions revenue -> confidential", which is how a DLP tool becomes an alert nobody reads.
_NEAR_MISS = [
    "Our published Q{q} results are on the investor relations page — revenue was {money}, up "
    "{pct}% year over year.",
    "Per the pricing page, {product} starts at {money2} per seat per month with volume discounts "
    "above {n} seats.",
    "The job ad for the {role} role lists a band of {money2} to {money}, which is public on our "
    "careers site.",
    "Here is a sample mutual NDA template from a legal-forms site — can you compare it to the one "
    "{company} sent?",
    "{competitor} announced their acquisition of {target} this morning; the press release says "
    "{money}. Worth a competitive brief?",
    "Analyst note on {company} estimates {quarter} revenue at {money} — that is their model, not "
    "ours, but it is a useful benchmark.",
    "Can you explain how an escrow works in an acquisition? I am reading a public S-1 and want to "
    "understand the mechanics.",
    "Draft a blog post about our {product} roadmap using only what we already announced at the "
    "user conference.",
    "The textbook example of a cap table has founders at {pct}% and a {pct2}% option pool — is that "
    "still typical?",
    "Summarize this public 10-K section on revenue recognition for the finance onboarding deck.",
    "What is a reasonable severance package to offer, generally? Asking so I can brief the {role} "
    "team on policy, not about anyone specific.",
    "Our customer {company} gave us a public case-study quote about ARR growth — can you tighten "
    "the wording for the website?",
]

# Ordinary work with no financial or legal vocabulary at all, so the benign class is not made
# entirely of hard cases (which would skew the decision boundary the other way).
_ORDINARY = [
    "Can you review this pull request and suggest a cleaner way to structure the retry logic?",
    "Draft an agenda for Thursday's engineering sync — three topics, thirty minutes.",
    "What is the difference between a p95 and a p99 latency measurement?",
    "Rewrite this paragraph so it is shorter and less jargon-heavy.",
    "Our staging deploy is failing on a migration. Here is the stack trace — any ideas?",
    "Summarize these meeting notes into action items with owners.",
    "Write a friendly reminder email asking the team to complete security training.",
    "Explain OAuth device flow to someone who has only used API keys.",
]

_SLOTS = {
    "target": ["Northwind", "Helios Systems", "Brightline", "Cortex Labs", "Meridian"],
    "acq": ["Acme", "Vertex", "Lumen Group", "our parent", "Ridgeway"],
    "company": ["Globex", "Initech", "Umbrella Retail", "Stark Industries", "Wayne Logistics"],
    "company2": ["Soylent", "Tyrell", "Pied Piper", "Hooli", "Massive Dynamic"],
    "company3": ["Cyberdyne", "Aperture", "Bluth Company", "Prestige Worldwide"],
    "competitor": ["a competitor", "the incumbent", "Vandelay", "Zenith"],
    "product": ["Atlas", "Beacon", "the legacy connector", "the analytics add-on"],
    "product2": ["Horizon", "the platform tier", "the managed offering"],
    "person": ["J. Alvarez", "the VP of Sales", "our lead architect", "M. Osei"],
    "person2": ["R. Fitzgerald", "the platform lead", "the regional director"],
    "role": ["Sales", "Engineering", "Support", "Finance", "Marketing"],
    "issue": ["revenue-recognition gap", "data-retention finding", "misclassification claim",
              "unlicensed dependency", "customer-data incident"],
    "outcome": ["a written warning", "termination", "mediation", "no further action"],
    "store": ["shared drive", "ticketing system", "email archive", "Slack export"],
    "money": ["$4.2M", "$18M", "$310K", "$1.05B", "$76M"],
    "money2": ["$2.8M", "$95K", "$640K", "$12M"],
    "quarter": ["Q1", "Q2", "Q3", "Q4", "FY26", "next quarter"],
    "round": ["Series C", "bridge round", "extension", "Series B"],
    "when": ["the 14th", "Monday", "after the close", "the earnings call"],
    "pct": ["12", "23", "40", "8", "65"],
    "pct2": ["9", "15", "31", "4"],
    "mult": ["6", "8.5", "11", "4"],
    "yrs": ["two", "three", "four"],
    "n": ["12", "40", "7", "150"],
    "q": ["1", "2", "3", "4"],
    "delta": ["ahead", "behind", "flat"],
}


def _fill(template: str, rng: random.Random) -> str:
    out = template
    for key, options in _SLOTS.items():
        token = "{" + key + "}"
        while token in out:
            out = out.replace(token, rng.choice(options), 1)
    return out


def build(per_template: int = 14, seed: int = 7) -> list[dict]:
    rng = random.Random(seed)
    rows: list[dict] = []
    for category, templates in _CONFIDENTIAL.items():
        for tpl in templates:
            seen: set[str] = set()
            for _ in range(per_template * 3):          # oversample, dedupe, then cap
                text = _fill(tpl, rng)
                if text in seen:
                    continue
                seen.add(text)
                rows.append({"content": text, "label": "confidential",
                             "category": category, "source": "synthetic"})
                if len(seen) >= per_template:
                    break
    # Near-misses get the same volume as the positives they shadow: this is where the model
    # learns that vocabulary alone is not sensitivity.
    per_near = max(1, (len(rows) // max(1, len(_NEAR_MISS))))
    for tpl in _NEAR_MISS:
        seen = set()
        for _ in range(per_near * 3):
            text = _fill(tpl, rng)
            if text in seen:
                continue
            seen.add(text)
            rows.append({"content": text, "label": "benign",
                         "category": "near_miss", "source": "synthetic"})
            if len(seen) >= per_near:
                break
    for text, suffix in itertools.product(_ORDINARY, ["", " Thanks!", " No rush.", " (see attached)"]):
        rows.append({"content": text + suffix, "label": "benign",
                     "category": "ordinary", "source": "synthetic"})
    rng.shuffle(rows)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="")
    ap.add_argument("--per-template", type=int, default=14)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    rows = build(per_template=args.per_template, seed=args.seed)
    text = "\n".join(json.dumps(r) for r in rows)
    pos = sum(1 for r in rows if r["label"] == "confidential")
    near = sum(1 for r in rows if r["category"] == "near_miss")
    msg = (f"{len(rows)} examples: {pos} confidential, {len(rows) - pos} benign "
           f"(of which {near} near-miss)")
    if args.out:
        open(args.out, "w").write(text + "\n")
        print(f"wrote {msg} to {args.out}", file=sys.stderr)
    else:
        print(text)
        print(msg, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
