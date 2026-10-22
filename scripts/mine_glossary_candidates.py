#!/usr/bin/env python3
"""
Mine glossary candidates from upstream ATT&CK / CAPEC STIX bundles.

Finds the most frequent multi-word technical phrases (and frequent single
words) in English human-readable fields, so a human/LLM only has to translate
a few hundred terms instead of whole descriptions. Every term added to
data/glossary_fa.json then fixes thousands of occurrences at once.

Output: TSV with columns  term, doc_freq, total_freq, in_glossary, example
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

DEFAULT_BUNDLES = [
    "enterprise-attack/enterprise-attack.json",
    "mobile-attack/mobile-attack.json",
    "ics-attack/ics-attack.json",
    "capec/2.0/stix-capec.json",
]
TEXT_FIELDS = ("name", "description", "x_mitre_detection")

STOPWORDS = set(
    """
    a an the and or of to in on for with by from as at into via over under than then
    that this these those such other others which who whom whose what when where while
    is are was were be been being has have had do does did may might can could would
    should will shall must also not no nor but if so it its their them they he she his her
    we our you your one two any all some each many more most much several various
    used use uses using including include includes e.g ex etc i.e within without
    between across about after before during through against upon both either
    """.split()
)

CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
CODE_RE = re.compile(r"<code>.*?</code>", re.DOTALL | re.IGNORECASE)
URL_RE = re.compile(r"https?://\S+")
MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")
WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9'\-]*")
SENT_SPLIT_RE = re.compile(r"[.;:!?()\[\],\"\n]+")


def clean(text: str) -> str:
    text = CITATION_RE.sub(" ", text)
    text = CODE_RE.sub(" , ", text)
    text = MD_LINK_RE.sub(r"\1", text)
    text = URL_RE.sub(" , ", text)
    return text


def iter_texts(bundle: Path):
    data = json.loads(bundle.read_text(encoding="utf-8"))
    for obj in data.get("objects", []):
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if obj.get("type") == "marking-definition":
            continue
        for field in TEXT_FIELDS:
            value = obj.get(field)
            if isinstance(value, str) and value.strip():
                yield obj.get("id", ""), value


def load_glossary_sources(path: Path) -> set[str]:
    if not path.exists():
        return set()
    payload = json.loads(path.read_text(encoding="utf-8"))
    out = {t["source"].lower() for t in payload.get("terms", []) if isinstance(t, dict) and t.get("source")}
    out |= {t.lower() for t in payload.get("protected_terms", []) if isinstance(t, str)}
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source-root", default=".")
    parser.add_argument("--bundles", nargs="+", default=DEFAULT_BUNDLES)
    parser.add_argument("--glossary", default="data/glossary_fa.json")
    parser.add_argument("--min-n", type=int, default=1)
    parser.add_argument("--max-n", type=int, default=4)
    parser.add_argument("--min-doc-freq", type=int, default=15)
    parser.add_argument("--top", type=int, default=2000)
    parser.add_argument("--output", default="data/glossary_candidates.tsv")
    args = parser.parse_args()

    root = Path(args.source_root)
    doc_freq: collections.Counter[str] = collections.Counter()
    total_freq: collections.Counter[str] = collections.Counter()
    example: dict[str, str] = {}

    for rel in args.bundles:
        bundle = root / rel
        if not bundle.exists():
            print(f"[warn] missing bundle {bundle}", file=sys.stderr)
            continue
        for obj_id, text in iter_texts(bundle):
            seen_here: set[str] = set()
            for chunk in SENT_SPLIT_RE.split(clean(text)):
                words = WORD_RE.findall(chunk)
                lowered = [w.lower() for w in words]
                for n in range(args.min_n, args.max_n + 1):
                    for i in range(len(words) - n + 1):
                        gram = lowered[i : i + n]
                        if gram[0] in STOPWORDS or gram[-1] in STOPWORDS:
                            continue
                        if n == 1 and (len(gram[0]) < 4 or gram[0] in STOPWORDS):
                            continue
                        key = " ".join(gram)
                        total_freq[key] += 1
                        seen_here.add(key)
                        if key not in example:
                            example[key] = " ".join(words[max(0, i - 4) : i + n + 4])
            doc_freq.update(seen_here)

    known = load_glossary_sources(root / args.glossary)
    candidates = [k for k, v in doc_freq.items() if v >= args.min_doc_freq]

    # Drop an n-gram when a longer n-gram containing it has nearly the same
    # document frequency (it is just a fragment of the longer phrase).
    by_len = sorted(candidates, key=lambda k: -len(k.split()))
    keep: set[str] = set()
    for term in by_len:
        n = len(term.split())
        absorbed = False
        if n < args.max_n:
            for longer in keep:
                if len(longer.split()) > n and f" {term} " in f" {longer} " and doc_freq[longer] >= 0.85 * doc_freq[term]:
                    absorbed = True
                    break
        if not absorbed:
            keep.add(term)

    ranked = sorted(keep, key=lambda k: (-doc_freq[k] * (1 + 0.6 * (len(k.split()) - 1)), k))[: args.top]
    out = root / args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        fh.write("term\tdoc_freq\ttotal_freq\tin_glossary\texample\n")
        for term in ranked:
            fh.write(
                f"{term}\t{doc_freq[term]}\t{total_freq[term]}\t{'yes' if term in known else ''}\t"
                f"{example.get(term, '').replace(chr(9), ' ')}\n"
            )
    print(f"[info] wrote {len(ranked)} candidates to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
