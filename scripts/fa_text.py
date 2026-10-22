#!/usr/bin/env python3
"""
Persian-side post-editing and quality checks for CTI translations.

Two jobs, both deterministic and free (no MT / LLM calls):

1. ``postprocess(source, fa, rules)``
   - generic Persian normalization (Arabic ي/ك, ZWNJ for می/ها, compound words)
   - source-conditional term fixes from data/glossary_fa.json (``fa_fixes``):
     e.g. when the English source contains "persistence", replace the
     machine-translation rendering "پایداری" with the glossary target "ماندگاری".
   Protected spans (code, citations, URLs, markdown links, IDs) are never edited.

2. ``quality_issues(source, fa, rules)``
   Detects typical MT failure modes: hallucinated out-of-domain text,
   degenerate repetition, broken wiki-style placeholders, abnormal length
   ratio, mostly-untranslated output and glossary misses.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

# Letters only: excludes Arabic-script punctuation such as «،» «؛» «؟» and digits,
# so word boundaries also work next to Persian punctuation.
L = "\u0621-\u065F\u0670-\u06D3\u06FA-\u06FF"
ZWNJ = "\u200c"  # zero-width non-joiner (نیم‌فاصله)
PERSIAN_LETTER_RE = re.compile(f"[{L}]")
ARABIC_SCRIPT_RE = re.compile("[\u0600-\u06FF]")
LATIN_LETTER_RE = re.compile(r"[A-Za-z]")

# Spans that must never be edited (same families the translator protects).
PROTECTED_SPAN_RE = re.compile(
    r"<code>.*?</code>"
    r"|\(Citation:[^)]+\)"
    r"|\[[^\]\n]+\]\([^)\s]+\)"
    r"|https?://[^\s)]+"
    r"|\b[a-z0-9_-]+--[0-9a-f-]{36}\b"
    r"|\b(?:TA|T|S|G|M|DS|D|C)\d{3,5}(?:\.\d{3})?\b",
    re.IGNORECASE | re.DOTALL,
)

# ---------------------------------------------------------------------------
# Generic normalization
# ---------------------------------------------------------------------------

_CHAR_MAP = str.maketrans({"ي": "ی", "ك": "ک", "ى": "ی", "ۀ": "هٔ"})

_MI_PREFIX_RE = re.compile(rf"(?<![{L}{ZWNJ}])(ن?می) +(?=[{L}])")
_HA_SUFFIX_RE = re.compile(
    rf"(?<=[{L}]) +(ها|های|هایی|هایم|هایت|هایش|هایمان|هایتان|هایشان)(?![{L}])"
)
_MULTI_SPACE_RE = re.compile(r"[ \t]{2,}")
_ZWNJ_SPACE_RE = re.compile(rf"[ \t]*{ZWNJ}+[ \t]*")

# Compound words that MT frequently writes with a plain space.
COMPOUND_FIXES: list[tuple[str, str]] = [
    ("سوء استفاده", "سوءاستفاده"),
    ("بد افزار", "بدافزار"),
    ("باج افزار", "باج‌افزار"),
    ("جاسوس افزار", "جاسوس‌افزار"),
    ("نرم افزار", "نرم‌افزار"),
    ("سخت افزار", "سخت‌افزار"),
    ("میان افزار", "میان‌افزار"),
    ("آسیب پذیری", "آسیب‌پذیری"),
    ("آسیب پذیر", "آسیب‌پذیر"),
    ("بهره برداری", "بهره‌برداری"),
    ("جمع آوری", "جمع‌آوری"),
    ("راه اندازی", "راه‌اندازی"),
    ("رمز گذاری", "رمزگذاری"),
    ("رمز گشایی", "رمزگشایی"),
    ("زمان بندی", "زمان‌بندی"),
    ("مرحله بندی", "مرحله‌بندی"),
    ("ذخیره سازی", "ذخیره‌سازی"),
    ("مبهم سازی", "مبهم‌سازی"),
    ("پیاده سازی", "پیاده‌سازی"),
    ("کنترل کننده", "کنترل‌کننده"),
    ("اسکرین شات", "اسکرین‌شات"),
    ("کی لاگر", "کی‌لاگر"),
    ("روت کیت", "روت‌کیت"),
    ("بوت کیت", "بوت‌کیت"),
    ("بات نت", "بات‌نت"),
    ("تله متری", "تله‌متری"),
    ("غیر مجاز", "غیرمجاز"),
    ("غیر فعال", "غیرفعال"),
    ("غیر عادی", "غیرعادی"),
    ("پس زمینه", "پس‌زمینه"),
    ("پشتیبان گیری", "پشتیبان‌گیری"),
    ("به روز رسانی", "به‌روزرسانی"),
    ("به روزرسانی", "به‌روزرسانی"),
    ("وب سایت", "وب‌سایت"),
    ("خط مشی", "خط‌مشی"),
    ("قطره چکان", "قطره‌چکان"),
    ("خوش خیم", "خوش‌خیم"),
]


def _word_pattern(fa: str) -> re.Pattern[str]:
    # Left: not glued to a preceding Persian letter/ZWNJ.
    # Right: not followed by a Persian letter (a ZWNJ + suffix is allowed).
    return re.compile(rf"(?<![{L}{ZWNJ}]){re.escape(fa)}(?![{L}])")


# Compounds: left boundary only, so suffixed forms are fixed too
# ("نرم افزارهای" -> "نرم‌افزارهای").
_COMPOUND_PATTERNS = [
    (re.compile(rf"(?<![{L}{ZWNJ}]){re.escape(a)}"), b) for a, b in COMPOUND_FIXES
]


def normalize_persian(text: str) -> str:
    """Normalization for a chunk that contains no protected spans."""
    if not PERSIAN_LETTER_RE.search(text):
        return text
    text = text.translate(_CHAR_MAP)
    text = _ZWNJ_SPACE_RE.sub(lambda m: " " if " " in m.group(0) or "\t" in m.group(0) else ZWNJ, text)
    text = _MI_PREFIX_RE.sub(lambda m: m.group(1) + ZWNJ, text)
    text = _HA_SUFFIX_RE.sub(lambda m: ZWNJ + m.group(1), text)
    for pattern, repl in _COMPOUND_PATTERNS:
        text = pattern.sub(repl, text)
    text = re.sub(r"[ \t]+،", "،", text)
    text = _MULTI_SPACE_RE.sub(" ", text)
    return text


# ---------------------------------------------------------------------------
# Glossary-driven, source-conditional fixes
# ---------------------------------------------------------------------------


@dataclass
class TermRule:
    source: str
    target: str
    match: re.Pattern[str]
    unless: re.Pattern[str] | None
    fixes: list[tuple[re.Pattern[str], str]] = field(default_factory=list)
    check: bool = False
    accept: list[str] = field(default_factory=list)
    note: str = ""


def _compile_source_match(term: dict[str, Any]) -> re.Pattern[str]:
    if term.get("match"):
        return re.compile(term["match"], re.IGNORECASE)
    source = term["source"]
    flags = 0 if term.get("case_sensitive", False) else re.IGNORECASE
    if term.get("whole_word", True):
        return re.compile(rf"(?<![A-Za-z0-9_]){re.escape(source)}(?![A-Za-z0-9_])", flags)
    return re.compile(re.escape(source), flags)


def load_term_rules(glossary_payload: dict[str, Any] | None) -> list[TermRule]:
    rules: list[TermRule] = []
    if not glossary_payload:
        return rules
    for term in glossary_payload.get("terms", []):
        if not isinstance(term, dict) or not term.get("source") or not term.get("target"):
            continue
        fixes: list[tuple[re.Pattern[str], str]] = []
        raw_fixes = term.get("fa_fixes", {})
        items: Iterable[tuple[str, str]]
        if isinstance(raw_fixes, dict):
            items = raw_fixes.items()
        else:
            items = [tuple(pair) for pair in raw_fixes if isinstance(pair, (list, tuple)) and len(pair) == 2]
        # Longest wrong-form first so "افزایش امتیازات" wins over "امتیازات".
        for wrong, right in sorted(items, key=lambda kv: -len(kv[0])):
            wrong_n = normalize_persian(wrong)
            fixes.append((_word_pattern(wrong_n), right))
        rules.append(
            TermRule(
                source=term["source"],
                target=term["target"],
                match=_compile_source_match(term),
                unless=re.compile(term["unless_source"], re.IGNORECASE) if term.get("unless_source") else None,
                fixes=fixes,
                check=bool(term.get("check", False)),
                accept=[a for a in term.get("accept", []) if isinstance(a, str)],
                note=term.get("note", ""),
            )
        )
    return rules


def load_glossary_payload(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _source_text(source: str) -> str:
    """Source without protected spans (link text, code, citations), for rule matching."""
    return PROTECTED_SPAN_RE.sub(" ", source)


def _rule_applies(rule: TermRule, source: str, cleaned: bool = False) -> bool:
    if not cleaned:
        source = _source_text(source)
    if not rule.match.search(source):
        return False
    if rule.unless is not None and rule.unless.search(source):
        return False
    return True


def split_protected(text: str) -> list[tuple[bool, str]]:
    parts: list[tuple[bool, str]] = []
    pos = 0
    for m in PROTECTED_SPAN_RE.finditer(text):
        if m.start() > pos:
            parts.append((False, text[pos : m.start()]))
        parts.append((True, m.group(0)))
        pos = m.end()
    if pos < len(text):
        parts.append((False, text[pos:]))
    return parts


ENTITY_LINK_RE = re.compile(
    r"\[([^\]]+)\]\((https?://attack\.mitre\.org/(?:groups|software|campaigns)/[^)\s]+)\)"
)


def _plain_link_text(text: str) -> bool:
    """False for 'link text' that is really a broken span swallowing other text."""
    return len(text) <= 80 and not re.search(r"[\[\]()\n]|https?://", text)


def postprocess(
    source: str,
    fa: str,
    rules: Sequence[TermRule] = (),
    link_text_map: dict[str, str] | None = None,
) -> str:
    """Normalize Persian output and apply source-conditional glossary fixes."""
    if not fa or not PERSIAN_LETTER_RE.search(fa):
        return fa
    source_clean = _source_text(source)
    active = [rule for rule in rules if rule.fixes and _rule_applies(rule, source_clean, cleaned=True)]
    # Group/software/campaign names stay English by policy, even inside link
    # text that MT (or an older cached translation) localized.
    entity_text = {m.group(2): m.group(1) for m in ENTITY_LINK_RE.finditer(source)}
    out: list[str] = []
    for is_protected, chunk in split_protected(fa):
        if is_protected:
            if chunk.startswith("["):
                m = re.match(r"\[([^\]]+)\](\((.*)\))$", chunk, re.DOTALL)
                if m and m.group(3) in entity_text and _plain_link_text(m.group(1)):
                    chunk = f"[{entity_text[m.group(3)]}]{m.group(2)}"
                elif m and link_text_map and m.group(1) in link_text_map:
                    chunk = f"[{link_text_map[m.group(1)]}]{m.group(2)}"
            out.append(chunk)
            continue
        chunk = normalize_persian(chunk)
        for rule in active:
            for pattern, repl in rule.fixes:
                chunk = pattern.sub(repl, chunk)
        out.append(chunk)
    return "".join(out)


# ---------------------------------------------------------------------------
# Quality checks
# ---------------------------------------------------------------------------

# Out-of-domain vocabulary that only shows up when MT hallucinates
# (wiki markup, religious formulas, encyclopedia boilerplate).
# Whole-word matches only: "رده:" must not fire inside "پژمرده:" (Wilted Tulip).
HALLUCINATION_RE = re.compile(
    rf"(?<![{L}])(?:آیات|روایات|علیه[\s‌]?السلام|صلی[\s‌]?الله|سلّم|رحمه[\s‌]?الله|ویکی‌?پدیا)(?![{L}])"
    r"|\[\[\s*(?:رده|ویرایش|پرونده|الگو)"
    rf"|(?<![{L}])رده:"
)
WIKI_BRACKETS_RE = re.compile(r"\[\[|\]\]")
CLEAN_FOR_RATIO_RE = re.compile(
    r"\(Citation:[^)]*\)|<code>.*?</code>|https?://\S+|\[\[\[[^\]]*\]\]\]",
    re.DOTALL | re.IGNORECASE,
)
SEVERE_ISSUES = {"hallucination", "repetition", "wiki_markup", "length_ratio"}


def _has_degenerate_repetition(text: str, min_repeats: int = 3) -> bool:
    tokens = re.findall(rf"[{L}{ZWNJ}]+|[A-Za-z0-9]+", text)
    n_tokens = len(tokens)
    for n in range(1, 5):
        for i in range(0, n_tokens - n * min_repeats + 1):
            unit = tokens[i : i + n]
            if n == 1 and len(unit[0]) <= 1:
                continue
            if n == 1 and unit[0] in {"و", "یا", "از", "به", "در"}:
                continue
            repeats = 1
            j = i + n
            while j + n <= n_tokens and tokens[j : j + n] == unit:
                repeats += 1
                j += n
            if repeats >= min_repeats + (1 if n == 1 else 0):
                return True
    return False


def _letters(text: str) -> int:
    return len(re.findall(rf"[A-Za-z{L}]", text))


def quality_issues(source: str, fa: str, rules: Sequence[TermRule] = ()) -> list[str]:
    """Return a list of issue codes for one translated string."""
    issues: list[str] = []
    if not fa or not fa.strip():
        return ["empty"]
    if HALLUCINATION_RE.search(fa) and not HALLUCINATION_RE.search(source):
        issues.append("hallucination")
    if WIKI_BRACKETS_RE.search(fa) and not WIKI_BRACKETS_RE.search(source):
        issues.append("wiki_markup")
    if _has_degenerate_repetition(fa) and not _has_degenerate_repetition(source):
        issues.append("repetition")

    src_clean = CLEAN_FOR_RATIO_RE.sub(" ", source)
    fa_clean = CLEAN_FOR_RATIO_RE.sub(" ", fa)
    src_len = _letters(src_clean)
    fa_len = _letters(fa_clean)
    if src_len >= 80:
        ratio = fa_len / max(src_len, 1)
        if ratio < 0.45 or ratio > 2.2:
            issues.append("length_ratio")
        # Ordinary lowercase English words left untranslated (identifiers such as
        # WNetOpenEnumW, file names and product names do not count).
        unprotected = "".join(chunk for prot, chunk in split_protected(fa) if not prot)
        english_words = len(re.findall(r"(?<![A-Za-z0-9_.\\/-])[a-z]{3,}(?![A-Za-z0-9_(])", unprotected))
        persian_words = len(re.findall(rf"[{L}]+", unprotected))
        if english_words > persian_words:
            issues.append("mostly_english")

    source_clean = _source_text(source)
    for rule in rules:
        if (
            rule.check
            and _rule_applies(rule, source_clean, cleaned=True)
            and not any(form in fa for form in [rule.target, *rule.accept])
        ):
            issues.append(f"glossary_miss:{rule.source}")
    return issues


def is_severe(issues: Iterable[str]) -> bool:
    return any(issue in SEVERE_ISSUES for issue in issues)
