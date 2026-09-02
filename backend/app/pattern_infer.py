"""Build a custom PII/identifier regex from examples, so nobody has to write one.

Per-tenant custom patterns already exist (`Tenant.custom_pii_patterns`, consumed by
detectors.patterns.custom_pii_patterns) and they work well. The barrier is the format:
`label=regex`. The person who knows what a customer ID looks like is very often not the
person who writes regular expressions, and that gap sits exactly where a buyer is trying
to prove value on their own data.

So: give two or three examples, get a pattern. Deliberately DETERMINISTIC rather than
model-generated. "Detection is Palivane's own engine, it calls no outside AI service to do
its job" is a promise the marketing pages make, and quietly routing detector authoring
through an LLM would undercut it while also making the result unexplainable, unreproducible
and unavailable offline. Inference from examples is none of those things: the same inputs
always give the same pattern, the reasoning is a shape, and it runs self-hosted with no key.

The output is an ordinary regex stored in the ordinary column and matched by the ordinary
engine, so nothing about the detection path changes. This only writes the string a human
would otherwise have had to write, and shows its work so they can check it.
"""
from __future__ import annotations

import re

# A run of one character class. `other` covers separators and is matched literally.
_CLASSES = (("digit", re.compile(r"\d")), ("upper", re.compile(r"[A-Z]")),
            ("lower", re.compile(r"[a-z]")))
_CLASS_RX = {"digit": r"\d", "upper": r"[A-Z]", "lower": r"[a-z]"}

MAX_EXAMPLES = 20
MAX_LEN = 200


def _classify(ch: str) -> str:
    for name, rx in _CLASSES:
        if rx.fullmatch(ch):
            return name
    return "other"


def _runs(s: str) -> list[tuple[str, str]]:
    """['ACME-1234'] -> [('upper','ACME'), ('other','-'), ('digit','1234')]"""
    out: list[tuple[str, str]] = []
    for ch in s:
        k = _classify(ch)
        if out and out[-1][0] == k:
            out[-1] = (k, out[-1][1] + ch)
        else:
            out.append((k, ch))
    return out


def _quantify(kind: str, texts: list[str]) -> str:
    """One run across every example: a literal if they all agree, else class + length."""
    if kind == "other" or len(set(texts)) == 1:
        # Identical across every example, so it is part of the format, not the value.
        return re.escape(texts[0])
    lo, hi = min(len(t) for t in texts), max(len(t) for t in texts)
    body = _CLASS_RX[kind]
    if lo == hi:
        return body if lo == 1 else f"{body}{{{lo}}}"
    return f"{body}{{{lo},{hi}}}"


def infer(examples: list[str], counter_examples: list[str] | None = None) -> dict:
    """Infer a regex matching every example and none of the counter-examples.

    Returns {ok, regex, explain, matched, missed, false_hits, error}. `ok` is False with a
    plain-language `error` rather than a partial pattern: a detector that half works is
    worse than none, because it reads as coverage.
    """
    counter_examples = [c for c in (counter_examples or []) if c.strip()]
    examples = [e.strip() for e in examples if e.strip()]
    fail = lambda msg: {"ok": False, "error": msg, "regex": "", "explain": "",
                        "matched": [], "missed": [], "false_hits": []}

    if len(examples) < 2:
        return fail("Give at least two examples, so the varying part can be told from the "
                    "fixed part. One example only describes itself.")
    if len(examples) > MAX_EXAMPLES:
        return fail(f"At most {MAX_EXAMPLES} examples.")
    if any(len(e) > MAX_LEN for e in examples + counter_examples):
        return fail(f"Examples must be under {MAX_LEN} characters.")

    shapes = [_runs(e) for e in examples]
    kinds = [tuple(k for k, _ in s) for s in shapes]
    if len(set(kinds)) != 1:
        return fail("These examples do not share a shape (the same run of letters, digits "
                    "and separators in the same order). Add the differing ones as their own "
                    "pattern instead of forcing one to cover both.")
    # Separators must be identical, or the "shape" is a coincidence of classes.
    for i, (kind, _) in enumerate(shapes[0]):
        texts = [s[i][1] for s in shapes]
        if kind == "other" and len(set(texts)) != 1:
            return fail("The separators differ between examples. Add them as separate "
                        "patterns so each one stays exact.")

    parts = [_quantify(kind, [s[i][1] for s in shapes])
             for i, (kind, _) in enumerate(shapes[0])]
    core = "".join(parts)
    # Anchor on word boundaries where the edge is alphanumeric, so the pattern does not
    # fire on a fragment of a longer token.
    pre = r"\b" if examples[0][:1].isalnum() else ""
    post = r"\b" if examples[0][-1:].isalnum() else ""
    regex = f"{pre}{core}{post}"

    try:
        rx = re.compile(regex)
    except re.error as e:                                  # defensive: parts are escaped
        return fail(f"Could not build a valid pattern ({e}).")

    matched = [e for e in examples if rx.search(e)]
    missed = [e for e in examples if not rx.search(e)]
    false_hits = [c for c in counter_examples if rx.search(c)]
    if missed:
        return fail("The inferred pattern did not match every example, which is a bug "
                    "rather than your input. Please report these examples.")
    if false_hits:
        return {"ok": False, "regex": regex, "explain": _explain(shapes[0], parts),
                "matched": matched, "missed": [], "false_hits": false_hits,
                "error": "This pattern also matches something you said it should not. Add "
                         "a more distinctive example, or narrow the format."}
    return {"ok": True, "regex": regex, "explain": _explain(shapes[0], parts),
            "matched": matched, "missed": [], "false_hits": [], "error": ""}


_HUMAN = {"digit": ("digit", "digits"), "upper": ("capital", "capitals"),
          "lower": ("lowercase letter", "lowercase letters")}


def _explain(shape: list[tuple[str, str]], parts: list[str]) -> str:
    """Say what the pattern means in words, so it can be checked without reading regex."""
    bits = []
    for (kind, text), part in zip(shape, parts):
        if kind == "other" or part == re.escape(text):
            bits.append(f'the literal "{text}"')
        elif "{" in part:
            n = part.split("{")[1].rstrip("}")
            one, many = _HUMAN[kind]
            bits.append(f"{n.replace(',', ' to ')} {one if n == '1' else many}")
        else:                                    # single character, quantifier omitted
            bits.append(f"1 {_HUMAN[kind][0]}")
    return ", then ".join(bits)
