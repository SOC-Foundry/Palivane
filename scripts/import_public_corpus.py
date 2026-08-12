"""Import a PUBLIC labeled prompt-injection dataset into the corpus JSONL format.

Public datasets (deepset/prompt-injections and friends) are an interim REAL-distribution
eval set: they contain human-written injections and benign prompts we didn't author, so
they measure something the synthetic builder can't. They are still not YOUR traffic —
the go/no-go gate in docs/ml-classifier-baseline.md ultimately wants consented captures.

Deliberately no network access and no vendored data: the operator downloads the file
themselves (e.g. from Hugging Face, as CSV or JSONL) and points this at it. Candidate
sources are documented in docs/ml-classifier-baseline.md.

Input: CSV (header row) or JSONL, one example per record. Field names auto-detect
(text/content/prompt/input and label/is_injection/category) or set --text-field /
--label-field. Malicious label values default to 1/true/injection/jailbreak/malicious.

Output: the repo corpus JSONL — {"content", "label": "malicious"|"benign",
"source": <name>} (+ "ts" if --ts-field is given), consumable by
scripts/train_classifier.py and mixable with the capture export.

    python scripts/import_public_corpus.py ~/Downloads/deepset_prompt_injections.csv \
        --source deepset/prompt-injections --out /tmp/eval_public.jsonl
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys

_TEXT_FIELDS = ("text", "content", "prompt", "input", "message")
_LABEL_FIELDS = ("label", "is_injection", "injection", "category", "class")
_DEFAULT_MALICIOUS = "1,true,yes,injection,prompt_injection,jailbreak,malicious,unsafe,attack"
_DEFAULT_BENIGN = "0,false,no,benign,legitimate,safe,clean"


def _records(path: str):
    """Yield dict records from a CSV (header row) or JSONL file, sniffed by content."""
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
        fh.seek(0)
        if first.lstrip().startswith("{"):
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)
        else:
            yield from csv.DictReader(fh)


def _pick_field(record: dict, explicit: str, candidates: tuple[str, ...], kind: str) -> str:
    if explicit:
        if explicit not in record:
            raise SystemExit(f"error: --{kind}-field {explicit!r} not in record fields "
                             f"{sorted(record)}")
        return explicit
    for c in candidates:
        if c in record:
            return c
    raise SystemExit(f"error: no {kind} field found (looked for {', '.join(candidates)}; "
                     f"record has {sorted(record)}) — pass --{kind}-field")


def convert(path: str, *, text_field: str = "", label_field: str = "", ts_field: str = "",
            malicious_values: str = _DEFAULT_MALICIOUS, source: str = "") -> tuple[list[dict], int]:
    """Convert one file to corpus rows. Returns (rows, skipped). A record whose label is
    neither a known-malicious nor known-benign value is SKIPPED and counted, never guessed."""
    mal = {v.strip().lower() for v in malicious_values.split(",") if v.strip()}
    ben = {v.strip().lower() for v in _DEFAULT_BENIGN.split(",")} - mal
    rows, skipped = [], 0
    tf = lf = tsf = None
    for rec in _records(path):
        if tf is None:
            tf = _pick_field(rec, text_field, _TEXT_FIELDS, "text")
            lf = _pick_field(rec, label_field, _LABEL_FIELDS, "label")
            tsf = ts_field or None
        content = (rec.get(tf) or "").strip() if isinstance(rec.get(tf), str) else str(rec.get(tf) or "")
        raw = rec.get(lf)
        val = str(raw).strip().lower() if raw is not None else ""
        if not content or not val or (val not in mal and val not in ben):
            skipped += 1
            continue
        row = {"content": content,
               "label": "malicious" if val in mal else "benign",
               "source": source or os.path.basename(path)}
        if tsf and rec.get(tsf):
            row["ts"] = str(rec[tsf])
        rows.append(row)
    return rows, skipped


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("inputs", nargs="+", help="downloaded dataset file(s), CSV or JSONL")
    ap.add_argument("--out", default="", help="output JSONL (default: stdout)")
    ap.add_argument("--text-field", default="", help="record field holding the prompt text")
    ap.add_argument("--label-field", default="", help="record field holding the label")
    ap.add_argument("--ts-field", default="",
                    help="optional timestamp field, kept as 'ts' for time-window holdout")
    ap.add_argument("--malicious-values", default=_DEFAULT_MALICIOUS,
                    help="comma-separated label values meaning malicious/injection")
    ap.add_argument("--source", default="", help="source tag (default: input basename)")
    args = ap.parse_args()

    rows: list[dict] = []
    skipped = 0
    for path in args.inputs:
        r, s = convert(path, text_field=args.text_field, label_field=args.label_field,
                       ts_field=args.ts_field, malicious_values=args.malicious_values,
                       source=args.source)
        rows += r
        skipped += s
    text = "\n".join(json.dumps(r) for r in rows)
    n_mal = sum(1 for r in rows if r["label"] == "malicious")
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(text + ("\n" if text else ""))
    else:
        print(text)
    print(f"imported {len(rows)} examples ({n_mal} malicious, {len(rows) - n_mal} benign), "
          f"skipped {skipped} (empty text or unrecognized label)"
          + (f" -> {args.out}" if args.out else ""), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
