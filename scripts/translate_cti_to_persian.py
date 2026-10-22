#!/usr/bin/env python3
"""
Translate MITRE CTI STIX JSON files to Persian.

This script is designed for large CTI repositories:
- translates only selected human-readable fields
- keeps a persistent SQLite cache to avoid retranslating duplicate text
- retries failed requests with exponential backoff
- writes to a separate output tree (safe by default)
"""

from __future__ import annotations

import argparse
import concurrent.futures
import html
import json
import os
import random
import re
import sqlite3
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from fa_text import (  # noqa: E402
    is_severe,
    load_glossary_payload,
    load_term_rules,
    postprocess,
    quality_issues,
)


DEFAULT_DATASETS = [
    "enterprise-attack",
    "mobile-attack",
    "ics-attack",
    "pre-attack",
    "capec",
]

# JSON-path-like patterns for text fields that should be translated.
DEFAULT_TRANSLATABLE_PATHS = [
    "objects[].name",
    "objects[].description",
    # external_references[].source_name is a citation key matched by
    # "(Citation: <source_name>)" in descriptions; it must stay English.
    "objects[].external_references[].description",
    "objects[].x_mitre_detection",
    "objects[].x_mitre_mutable_elements[].description",
    "objects[].x_mitre_difficulty_for_adversary_explanation",
    "objects[].x_mitre_detectable_by_common_defenses_explanation",
    "objects[].x_mitre_first_seen_citation",
    "objects[].x_mitre_last_seen_citation",
    "objects[].x_capec_prerequisites[]",
    "objects[].x_capec_example_instances[]",
    "objects[].x_capec_resources_required[]",
    "objects[].x_capec_extended_description",
    "objects[].x_capec_execution_flow",
    "objects[].x_capec_consequences.*[]",
    "objects[].x_capec_skills_required.*",
]

SOURCE_LETTER_RE = re.compile(r"[A-Za-z]")
STIX_ID_RE = re.compile(
    r"^[a-z0-9_-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
URL_ONLY_RE = re.compile(r"^https?://\S+$", re.IGNORECASE)
ATTACK_ID_ONLY_RE = re.compile(r"^(?:TA|T|S|G|M|DS|D|C)\d{3,5}(?:\.\d{3})?$")

# Preserve tokens that should remain verbatim after translation.
PROTECT_PATTERNS = [
    re.compile(r"<code>.*?</code>", re.IGNORECASE | re.DOTALL),
    re.compile(r"\(Citation:[^)]+\)"),
    re.compile(r"https?://[^\s)]+", re.IGNORECASE),
    re.compile(r"\b[a-z0-9_-]+--[0-9a-f-]{36}\b", re.IGNORECASE),
    re.compile(r"\b(?:TA|T|S|G|M|DS|D|C)\d{3,5}(?:\.\d{3})?\b"),
]

# Extra spans that are masked before MT but are NOT part of the fragment-count
# validation above (so existing cache entries are not mass-rejected). MT engines
# routinely mangle these: markdown links (link text + URL), registry keys,
# file-system paths and file names.
MARKDOWN_LINK_RE = re.compile(r"\[[^\]\n]+\]\([^)\s]+\)")
EXTRA_MASK_PATTERNS = [
    re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^\s,;)\"'<]*"),
    re.compile(r"(?:\b[A-Za-z]:|%[A-Za-z_]+%)\\[^\s,;)\"'<]*"),
    re.compile(r"(?<![\w/~])(?:~|/(?:etc|usr|var|tmp|bin|sbin|Library|System|Users|home|dev|proc|opt|private|Applications))/[^\s,;)\"'<]*"),
    re.compile(
        r"(?<![\w.-])[\w-]+(?:\.[\w-]+)*\.(?:exe|dll|sys|ps1|psm1|bat|cmd|vbs|vbe|js|jse|hta|lnk|msi|scr|cpl|ocx|"
        r"plist|sh|py|so|dylib|apk|ipa|jar|docm|xlsm|dotm|iso|img|vhdx?|chm|wsf|reg|inf)\b",
        re.IGNORECASE,
    ),
]

CORRUPTED_PLACEHOLDER_RE = re.compile(
    r"CTI[_\s-]*PRESERVE|\[\[\s*ویرایش|\[\[\s*رده|\[\[\[|ZQX[A-J]+|<\s*x\s+id\s*="
)

GLOSSARY_STRATEGIES = ("post", "placeholder", "inline")


class PlaceholderStyle:
    """How protected spans are represented in the text sent to MT.

    legacy: [[[CTI_PRESERVE_3]]]  - looks like wiki markup; Google often rewrites
            it as [[رده:...]] and then hallucinates encyclopedia/religious text.
    caps:   ZQXD                  - an acronym-like Latin token (digits as A-J),
            no brackets and no digits for MT to localize.
    tag:    <x id="3"/>           - XML-ish tag; best with Cloud API format=html.
    """

    DIGITS = "ABCDEFGHIJ"

    def __init__(self, name: str) -> None:
        if name not in ("legacy", "caps", "tag"):
            raise ValueError(f"unknown placeholder style: {name}")
        self.name = name
        if name == "legacy":
            self.regex = re.compile(r"\[\[\[\s*CTI_PRESERVE_(\d+)\s*]]]")
        elif name == "caps":
            self.regex = re.compile(r"ZQX([A-J]+)", re.IGNORECASE)
        else:
            self.regex = re.compile(r"<\s*x\s+id\s*=\s*[\"'«»]?\s*([0-9۰-۹٠-٩]+)\s*[\"'«»]?\s*/?\s*>")

    def token(self, idx: int) -> str:
        if self.name == "legacy":
            return f"[[[CTI_PRESERVE_{idx}]]]"
        if self.name == "caps":
            return "ZQX" + "".join(self.DIGITS[int(ch)] for ch in str(idx))
        return f'<x id="{idx}"/>'

    def parse_index(self, match: re.Match[str]) -> int:
        raw = match.group(1)
        if self.name == "caps":
            return int("".join(str(self.DIGITS.index(ch)) for ch in raw.upper()))
        raw = raw.translate(str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩", "01234567890123456789"))
        return int(raw)

    def canonicalize(self, text: str) -> str:
        """Rewrite slightly mangled tokens (spaces, Persian digits) to canonical form."""
        return self.regex.sub(lambda m: self.token(self.parse_index(m)), text)


LEGACY_STYLE = PlaceholderStyle("legacy")
PROTECTED_TOKEN_RE = LEGACY_STYLE.regex  # backward compatible name


class TranslationError(RuntimeError):
    """Raised when translation fails after retries."""


class ProtectedTokenError(TranslationError):
    """Raised when a translation drops or changes protected placeholders."""


class QualityError(TranslationError):
    """Raised when a translation shows hallucination / repetition / broken markup."""


class SegmentMismatch(TranslationError):
    """Raised when MT does not return the same number of lines that were sent."""


def _word_alternation(words: Sequence[str], flags: int = 0) -> re.Pattern[str] | None:
    words = sorted({w for w in words if w}, key=len, reverse=True)
    if not words:
        return None
    body = "|".join(re.escape(w) for w in words)
    return re.compile(rf"(?<![A-Za-z0-9_])(?:{body})(?![A-Za-z0-9_])", flags)


class Glossary:
    def __init__(
        self,
        terms: Sequence[dict[str, Any]],
        protected_terms: Sequence[str],
        payload: dict[str, Any] | None = None,
    ) -> None:
        self.terms = list(terms)
        self.protected_terms = list(protected_terms)
        self.payload = payload or {"terms": self.terms, "protected_terms": self.protected_terms}
        self.rules = load_term_rules(self.payload)
        self._compile()

    _TOKEN_RE = re.compile(r"[\w.+#-]+")

    def _compile(self) -> None:
        # Index protected terms by their first token so each text only runs the
        # handful of patterns whose first word actually occurs in it.
        self._protected_index: dict[str, list[str]] = {}
        for term in self.protected_terms:
            tokens = self._TOKEN_RE.findall(term)
            if tokens:
                self._protected_index.setdefault(tokens[0].rstrip("."), []).append(term)
        self._pattern_cache: dict[tuple[str, ...], re.Pattern[str] | None] = {}
        # Only plain glossary entries (no fa_fixes) are used for pre-MT
        # substitution; fa_fixes entries are post-edit rules.
        self._term_patterns: list[tuple[re.Pattern[str], str]] = []
        for term in self.terms:
            source = term.get("source")
            target = term.get("target")
            if not isinstance(source, str) or not isinstance(target, str) or not source or not target:
                continue
            if "fa_fixes" in term and not term.get("inline", False):
                continue
            whole_word = bool(term.get("whole_word", True))
            flags = 0 if term.get("case_sensitive", False) else re.IGNORECASE
            if whole_word:
                pattern_text = rf"(?<![A-Za-z0-9_]){re.escape(source)}(?![A-Za-z0-9_])"
            else:
                pattern_text = re.escape(source)
            self._term_patterns.append((re.compile(pattern_text, flags), target))
        # Longest source first so "Intrusion Set" wins over "Set".
        self._term_patterns.sort(key=lambda item: -len(item[0].pattern))

    def _protected_pattern_for(self, text: str) -> re.Pattern[str] | None:
        present: set[str] = set()
        for token in self._TOKEN_RE.findall(text):
            present.add(token)
            present.add(token.rstrip("."))
        candidates = tuple(
            sorted({term for tok in present for term in self._protected_index.get(tok, ())}, key=len, reverse=True)
        )
        if not candidates:
            return None
        if candidates not in self._pattern_cache:
            if len(self._pattern_cache) > 50_000:
                self._pattern_cache.clear()
            self._pattern_cache[candidates] = _word_alternation(candidates)
        return self._pattern_cache[candidates]

    def add_protected_terms(self, extra: Sequence[str]) -> int:
        before = len(self.protected_terms)
        known = set(self.protected_terms)
        self.protected_terms.extend(term for term in extra if term not in known)
        self._compile()
        return len(self.protected_terms) - before

    @classmethod
    def from_path(cls, path: Path) -> "Glossary":
        if not path.exists():
            return cls([], [])
        payload = json.loads(path.read_text(encoding="utf-8"))
        terms = payload.get("terms", [])
        protected_terms = payload.get("protected_terms", [])
        if not isinstance(terms, list) or not isinstance(protected_terms, list):
            raise TranslationError(f"Invalid glossary structure: {path}")
        return cls(
            terms=[term for term in terms if isinstance(term, dict)],
            protected_terms=[term for term in protected_terms if isinstance(term, str)],
            payload=payload,
        )

    def apply(
        self,
        text: str,
        protected: dict[str, str],
        token_prefix: str = "CTI_PRESERVE",
        strategy: str = "placeholder",
        style: PlaceholderStyle | None = None,
    ) -> str:
        style = style or LEGACY_STYLE
        updated = text

        def next_token(value: str) -> str:
            if style is LEGACY_STYLE and token_prefix != "CTI_PRESERVE":
                token = f"[[[{token_prefix}_{len(protected)}]]]"
            else:
                token = style.token(len(protected))
            protected[token] = value
            return token

        protected_re = self._protected_pattern_for(updated)
        if protected_re is not None:
            updated = protected_re.sub(lambda match: next_token(match.group(0)), updated)

        if strategy == "post":
            return updated
        for pattern, target in self._term_patterns:
            if strategy == "inline":
                updated = pattern.sub(lambda _match, value=target: value, updated)
            else:
                updated = pattern.sub(lambda _match, value=target: next_token(value), updated)
        return updated


class NameOverrides:
    """Human/LLM-reviewed translations of object names (data/overrides_fa.json).

    - names[type][English] = Persian: exact name translations, highest priority
      (above the MT cache), never post-edited.
    - templates: regex patterns for generated names, e.g.
      "Detection of <technique name>"; a template applies only when every
      captured group named t* can itself be translated from the names table
      (so no half-English results).
    - "Parent: Sub" combinations are resolved part by part.
    The flattened table is also used to localize the visible text of ATT&CK
    markdown links inside descriptions.
    """

    def __init__(self, payload: dict[str, Any] | None = None) -> None:
        payload = payload or {}
        self.by_type: dict[str, dict[str, str]] = {
            t: {k: v for k, v in names.items() if isinstance(v, str) and v.strip()}
            for t, names in (payload.get("names") or {}).items()
            if isinstance(names, dict)
        }
        self.flat: dict[str, str] = {}
        for names in self.by_type.values():
            for en, fa in names.items():
                self.flat.setdefault(en, fa)
        self.templates: list[tuple[set[str], re.Pattern[str], str]] = []
        for tpl in payload.get("templates") or []:
            if isinstance(tpl, dict) and tpl.get("pattern") and tpl.get("target"):
                self.templates.append((set(tpl.get("types") or []), re.compile(tpl["pattern"]), tpl["target"]))
        self.localize_links = bool(payload.get("localize_link_text", True))
        # paragraphs[English paragraph] = Persian paragraph (descriptions are
        # split on blank lines; only matching paragraphs are replaced).
        self.paragraphs: dict[str, str] = {
            k: v for k, v in (payload.get("paragraphs") or {}).items() if isinstance(v, str) and v.strip()
        }

    @classmethod
    def from_path(cls, path: Path) -> "NameOverrides":
        if not path.exists():
            return cls()
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def __bool__(self) -> bool:
        return bool(self.flat or self.templates or self.paragraphs)

    _PARA_SPLIT = re.compile(r"(\n\s*\n)")

    def apply_paragraphs(self, source: str, translated: str | None) -> str | None:
        """Replace MT paragraphs with reviewed ones where available.

        Works when MT kept the paragraph structure (same number of blank-line
        separated blocks) or when every source paragraph has an override.
        Returns None when nothing can be produced.
        """
        if not self.paragraphs:
            return translated
        src_parts = self._PARA_SPLIT.split(source)
        src_paras = src_parts[0::2]
        if not any(p.strip() in self.paragraphs for p in src_paras):
            return translated
        if all(p.strip() in self.paragraphs or not p.strip() for p in src_paras):
            return "".join(self.paragraphs.get(part.strip(), part) if i % 2 == 0 else part for i, part in enumerate(src_parts))
        if translated is None:
            return None
        fa_parts = self._PARA_SPLIT.split(translated)
        if len(fa_parts) != len(src_parts):
            return translated
        replaced = False
        for i in range(0, len(src_parts), 2):
            key = src_parts[i].strip()
            if key in self.paragraphs:
                lead = fa_parts[i][: len(fa_parts[i]) - len(fa_parts[i].lstrip())]
                fa_parts[i] = lead + self.paragraphs[key]
                replaced = True
        if replaced:
            # MT output sometimes moves citations/URLs/code it lost mid-text to the very
            # end. Once the paragraphs they came from are replaced by reviewed
            # text, that tail duplicates them; keep only what is still missing
            # relative to the whole source text.
            for i in range(0, len(src_parts), 2):
                if src_parts[i].strip() not in self.paragraphs:
                    self._trim_marker_tail(fa_parts, i, source)
        return "".join(fa_parts)

    _TOKEN_PATTERN = r"\(Citation:[^)]*\)|https?://[^\s)\]]+|<code>.*?</code>|`[^`\n]+`"
    _TAIL_RE = re.compile(r"(?:\s*(?:" + _TOKEN_PATTERN + r"))+\s*$")
    _TOKEN_RE = re.compile(_TOKEN_PATTERN)

    @classmethod
    def _trim_marker_tail(cls, fa_parts: list[str], i: int, source: str) -> None:
        m = cls._TAIL_RE.search(fa_parts[i])
        if not m:
            return
        head = fa_parts[i][: m.start()]
        tail = m.group(0)
        first_sep = tail[: len(tail) - len(tail.lstrip())]
        trailing_ws = tail[len(tail.rstrip()):]
        before = "".join(fa_parts[:i])
        after = "".join(fa_parts[i + 1 :])
        kept: list[str] = []
        for token in cls._TOKEN_RE.findall(tail):
            current = before + head + " ".join(kept) + after
            if current.count(token) < source.count(token):
                kept.append(token)
        fa_parts[i] = head + (first_sep + " ".join(kept) if kept else "") + trailing_ws

    def lookup_name(self, name: str) -> str | None:
        name = name.strip()
        if name in self.flat:
            return self.flat[name]
        if ": " in name:
            parts = [part.strip() for part in name.split(": ")]
            translated = [self.flat.get(part) for part in parts]
            if all(translated):
                return ": ".join(translated)  # type: ignore[arg-type]
        return None

    def for_object(self, obj_type: str, name: str) -> str | None:
        exact = self.by_type.get(obj_type, {}).get(name)
        if exact:
            return exact
        for types, pattern, target in self.templates:
            if types and obj_type not in types:
                continue
            m = pattern.match(name)
            if not m:
                continue
            values: dict[str, str] = {}
            ok = True
            for group, value in m.groupdict().items():
                if group.startswith("t"):
                    fa = self.lookup_name(value)
                    if fa is None:
                        ok = False
                        break
                    values[group] = fa
                else:
                    values[group] = value
            if ok:
                return target.format(**values)
        return None

    def link_map(self) -> "_LinkMap":
        return _LinkMap(self)


class _LinkMap(dict):
    """dict-like view used by fa_text.postprocess for markdown link text."""

    def __init__(self, overrides: NameOverrides) -> None:
        super().__init__()
        self._o = overrides

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and self._o.lookup_name(key) is not None

    def __getitem__(self, key: str) -> str:
        value = self._o.lookup_name(key)
        if value is None:
            raise KeyError(key)
        return value

    def __bool__(self) -> bool:
        return bool(self._o.flat)


def build_stix_name_terms(
    source_root: Path,
    datasets: Sequence[str],
    types: Sequence[str] = ("intrusion-set", "malware", "tool", "campaign"),
    common_word_threshold: int = 15,
    exclude: Sequence[str] = (),
) -> list[str]:
    """Names and aliases of groups/software/campaigns, to keep them in English.

    Single-word names that also occur as ordinary lowercase words in the corpus
    (e.g. the tools "at", "ping", "net") are skipped, because masking them would
    also mask the ordinary word.
    """
    bundles: list[Path] = []
    for dataset in datasets:
        root = source_root / dataset
        if (root / f"{dataset}.json").exists():
            bundles.append(root / f"{dataset}.json")
        bundles.extend(sorted(root.glob("*/stix-capec.json")))
    names: set[str] = set()
    lowercase_counts: dict[str, int] = {}
    word_re = re.compile(r"[a-z][a-z0-9-]+")
    for bundle in bundles:
        try:
            objects = json.loads(bundle.read_text(encoding="utf-8")).get("objects", [])
        except Exception:  # noqa: BLE001
            continue
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            desc = obj.get("description")
            if isinstance(desc, str):
                for word in word_re.findall(desc):
                    lowercase_counts[word] = lowercase_counts.get(word, 0) + 1
            if obj.get("type") not in types:
                continue
            for value in [obj.get("name"), *(obj.get("aliases") or []), *(obj.get("x_mitre_aliases") or [])]:
                if isinstance(value, str) and len(value.strip()) >= 3:
                    names.add(value.strip())
    excluded = set(exclude)
    result = []
    for name in names:
        if name in excluded:
            continue
        if " " not in name and lowercase_counts.get(name.lower(), 0) >= common_word_threshold:
            continue
        if not re.search(r"[A-Za-z]", name):
            continue
        result.append(name)
    return sorted(result, key=len, reverse=True)


class SQLiteTranslationCache:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS translations (
                provider TEXT NOT NULL,
                source_lang TEXT NOT NULL,
                target_lang TEXT NOT NULL,
                source_text TEXT NOT NULL,
                translated_text TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (provider, source_lang, target_lang, source_text)
            )
            """
        )
        self.conn.commit()

    def get(
        self,
        provider: str,
        source_lang: str,
        target_lang: str,
        source_text: str,
    ) -> str | None:
        cur = self.conn.execute(
            """
            SELECT translated_text
            FROM translations
            WHERE provider = ? AND source_lang = ? AND target_lang = ? AND source_text = ?
            """,
            (provider, source_lang, target_lang, source_text),
        )
        row = cur.fetchone()
        return row[0] if row else None

    def put_many(
        self,
        provider: str,
        source_lang: str,
        target_lang: str,
        pairs: Sequence[tuple[str, str]],
    ) -> None:
        if not pairs:
            return
        self.conn.executemany(
            """
            INSERT INTO translations (provider, source_lang, target_lang, source_text, translated_text)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(provider, source_lang, target_lang, source_text)
            DO UPDATE SET translated_text = excluded.translated_text, updated_at = CURRENT_TIMESTAMP
            """,
            [
                (provider, source_lang, target_lang, source, translated)
                for source, translated in pairs
            ],
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


class GooglePublicTranslator:
    """Uses the undocumented web endpoint. No API key required."""

    name = "google_public"
    endpoint = "https://translate.googleapis.com/translate_a/single"

    def __init__(
        self,
        source_lang: str,
        target_lang: str,
        timeout: float = 30.0,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.source_lang = source_lang
        self.target_lang = target_lang
        self.timeout = timeout
        self.ssl_context = ssl_context

    def translate_text(self, text: str) -> str:
        params = {
            "client": "gtx",
            "sl": self.source_lang,
            "tl": self.target_lang,
            "dt": "t",
            "q": text,
        }
        url = f"{self.endpoint}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "cti-persian-translator/1.0"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        if not payload or not isinstance(payload, list) or not payload[0]:
            raise TranslationError("Unexpected response shape from Google public endpoint")
        segments = payload[0]
        return "".join(part[0] for part in segments if isinstance(part, list) and part)


class GoogleCloudTranslator:
    """Uses official Google Cloud Translation API v2."""

    name = "google_cloud"
    endpoint = "https://translation.googleapis.com/language/translate/v2"

    def __init__(
        self,
        source_lang: str,
        target_lang: str,
        api_key: str,
        timeout: float = 30.0,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.source_lang = source_lang
        self.target_lang = target_lang
        self.api_key = api_key
        self.timeout = timeout
        self.ssl_context = ssl_context

    def translate_batch(self, texts: Sequence[str]) -> list[str]:
        url = f"{self.endpoint}?key={urllib.parse.quote(self.api_key)}"
        body = json.dumps(
            {
                "q": list(texts),
                "source": self.source_lang,
                "target": self.target_lang,
                "format": "text",
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": "cti-persian-translator/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
            payload = json.loads(resp.read().decode("utf-8"))

        items = payload.get("data", {}).get("translations", [])
        if len(items) != len(texts):
            raise TranslationError(
                f"Expected {len(texts)} translations but got {len(items)} from Google Cloud API"
            )
        return [html.unescape(item.get("translatedText", "")) for item in items]

    def translate_text(self, text: str) -> str:
        return self.translate_batch([text])[0]


class GoogleTransTranslator:
    """Uses googletrans package (unofficial web API)."""

    name = "googletrans"

    def __init__(self, source_lang: str, target_lang: str) -> None:
        self.source_lang = source_lang
        self.target_lang = target_lang
        self._local = threading.local()

        try:
            from googletrans import Translator  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise TranslationError(
                "googletrans is not installed. Install it with: pip install 'googletrans==4.0.2'"
            ) from exc
        self._translator_cls = Translator

    def _get_translator(self) -> Any:
        tr = getattr(self._local, "translator", None)
        if tr is None:
            tr = self._translator_cls()
            # googletrans variants use inconsistent attribute names.
            if not hasattr(tr, "raise_Exception"):
                try:
                    setattr(tr, "raise_Exception", False)
                except Exception:  # noqa: BLE001
                    pass
            if not hasattr(tr, "raise_exception"):
                try:
                    setattr(tr, "raise_exception", False)
                except Exception:  # noqa: BLE001
                    pass
            self._local.translator = tr
        return tr

    def _reset_translator(self) -> None:
        tr = self._translator_cls()
        if not hasattr(tr, "raise_Exception"):
            try:
                setattr(tr, "raise_Exception", False)
            except Exception:  # noqa: BLE001
                pass
        if not hasattr(tr, "raise_exception"):
            try:
                setattr(tr, "raise_exception", False)
            except Exception:  # noqa: BLE001
                pass
        self._local.translator = tr

    def translate_text(self, text: str) -> str:
        tr = self._get_translator()
        result = tr.translate(text, src=self.source_lang, dest=self.target_lang)
        return str(result.text)


class ArgosOfflineTranslator:
    """Uses Argos Translate local models for fully offline translation."""

    name = "argos_offline"

    def __init__(
        self,
        source_lang: str,
        target_lang: str,
        auto_install: bool = True,
        package_path: str = "",
        package_index: str = "",
    ) -> None:
        self.source_lang = source_lang
        self.target_lang = target_lang
        self.auto_install = auto_install
        self.package_path = package_path
        self.package_index = package_index

        try:
            import argostranslate.package as argos_package  # type: ignore
            import argostranslate.translate as argos_translate  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise TranslationError(
                "Argos Translate is not installed. Install it with: pip install argostranslate "
                "(for Python 3.9 use: pip install 'argostranslate==1.9.6')."
            ) from exc

        self.argos_package = argos_package
        self.argos_translate = argos_translate

        if self.package_index:
            os.environ["ARGOS_PACKAGE_INDEX"] = self.package_index

        if self.package_path:
            pkg_path = Path(self.package_path).expanduser().resolve()
            if not pkg_path.exists():
                raise TranslationError(f"Argos model package not found: {pkg_path}")
            self.argos_package.install_from_path(pkg_path)

        if not self._is_ready():
            if not self.auto_install:
                raise TranslationError(
                    "Argos translation package for "
                    f"{self.source_lang}->{self.target_lang} is not installed. "
                    "Use --argos-auto-install or pass --argos-package-path."
                )
            self._auto_install_pair()

        if not self._is_ready():
            raise TranslationError(
                "Argos could not provide translation for "
                f"{self.source_lang}->{self.target_lang}. "
                "Try importing a matching .argosmodel with --argos-package-path."
            )

    def _is_ready(self) -> bool:
        try:
            self.argos_translate.translate(
                "hello",
                self.source_lang,
                self.target_lang,
            )
            return True
        except Exception:  # noqa: BLE001
            return False

    def _auto_install_pair(self) -> None:
        install_ok = False
        try:
            install_ok = bool(
                self.argos_package.install_package_for_language_pair(
                    self.source_lang,
                    self.target_lang,
                )
            )
        except Exception:  # noqa: BLE001
            install_ok = False

        if install_ok:
            return

        self.argos_package.update_package_index()
        available_packages = self.argos_package.get_available_packages()
        pair_pkg = next(
            (
                pkg
                for pkg in available_packages
                if getattr(pkg, "from_code", None) == self.source_lang
                and getattr(pkg, "to_code", None) == self.target_lang
            ),
            None,
        )
        if pair_pkg is None:
            raise TranslationError(
                "No Argos package found for "
                f"{self.source_lang}->{self.target_lang} in current index."
            )

        downloaded = pair_pkg.download()
        self.argos_package.install_from_path(downloaded)

    def translate_text(self, text: str) -> str:
        return self.argos_translate.translate(text, self.source_lang, self.target_lang)


class PathMatcher:
    def __init__(self, patterns: Sequence[str]) -> None:
        self.patterns = [self._compile(p) for p in patterns]

    @staticmethod
    def _compile(pattern: str) -> re.Pattern[str]:
        # Support '*' as one path-token wildcard.
        regex = re.escape(pattern).replace(r"\*", r"[^.]+")
        return re.compile(rf"^{regex}$")

    def matches(self, path: str) -> bool:
        return any(p.match(path) for p in self.patterns)


def iter_string_targets(
    node: Any,
    matcher: PathMatcher,
    path: str = "",
    parent: Any | None = None,
    parent_key: str | int | None = None,
) -> Iterator[tuple[Any, str | int, str, str, Any | None, str | int | None]]:
    if isinstance(node, dict):
        for key, value in node.items():
            child_path = f"{path}.{key}" if path else key
            if isinstance(value, str):
                if matcher.matches(child_path):
                    yield node, key, child_path, value, parent, parent_key
            elif isinstance(value, list):
                list_path = f"{child_path}[]"
                for idx, item in enumerate(value):
                    if isinstance(item, str):
                        if matcher.matches(list_path):
                            yield value, idx, list_path, item, node, key
                    else:
                        yield from iter_string_targets(
                            item,
                            matcher,
                            list_path,
                            parent=value,
                            parent_key=idx,
                        )
            else:
                yield from iter_string_targets(
                    value,
                    matcher,
                    child_path,
                    parent=node,
                    parent_key=key,
                )
    elif isinstance(node, list):
        list_path = f"{path}[]"
        for idx, item in enumerate(node):
            if isinstance(item, str):
                if matcher.matches(list_path):
                    yield node, idx, list_path, item, parent, parent_key
            else:
                yield from iter_string_targets(
                    item,
                    matcher,
                    list_path,
                    parent=node,
                    parent_key=idx,
                )


def should_translate_text(text: str) -> bool:
    candidate = text.strip()
    if not candidate:
        return False
    if URL_ONLY_RE.match(candidate):
        return False
    if STIX_ID_RE.match(candidate):
        return False
    if ATTACK_ID_ONLY_RE.match(candidate):
        return False
    if not SOURCE_LETTER_RE.search(candidate):
        return False
    return True


CAPS_STYLE = PlaceholderStyle("caps")
TAG_STYLE = PlaceholderStyle("tag")
STYLES = {"legacy": LEGACY_STYLE, "caps": CAPS_STYLE, "tag": TAG_STYLE}


def _detect_style(protected: dict[str, str]) -> PlaceholderStyle:
    first = next(iter(protected), "")
    if first.startswith("ZQX"):
        return CAPS_STYLE
    if first.startswith("<x"):
        return TAG_STYLE
    return LEGACY_STYLE


def protect_text(
    text: str,
    glossary: Glossary | None = None,
    strategy: str = "placeholder",
    style: PlaceholderStyle | None = None,
    mask_extras: bool = False,
) -> tuple[str, dict[str, str]]:
    style = style or LEGACY_STYLE
    protected: dict[str, str] = {}
    updated = text

    def replacer(match: re.Match[str]) -> str:
        token = style.token(len(protected))
        protected[token] = match.group(0)
        return token

    patterns: list[re.Pattern[str]] = list(PROTECT_PATTERNS[:2])  # code, citations
    if mask_extras:
        patterns.append(MARKDOWN_LINK_RE)  # whole link before its URL
    patterns.extend(PROTECT_PATTERNS[2:])
    if mask_extras:
        patterns.extend(EXTRA_MASK_PATTERNS)
    for pattern in patterns:
        updated = pattern.sub(replacer, updated)
    if glossary is not None:
        updated = glossary.apply(updated, protected, strategy=strategy, style=style)
    return updated, protected


def validate_protected_tokens(
    text: str,
    protected: dict[str, str],
    style: PlaceholderStyle | None = None,
) -> None:
    style = style or _detect_style(protected)
    canonical = style.canonicalize(text)
    seen = {m.group(0) for m in style.regex.finditer(canonical)}
    missing = [token for token in protected if token not in seen]
    if missing:
        raise ProtectedTokenError(f"translation dropped protected token(s): {', '.join(missing[:10])}")


def count_protected_fragments(text: str) -> list[int]:
    return [len(pattern.findall(text)) for pattern in PROTECT_PATTERNS]


def validate_protected_fragment_counts(source: str, translated: str) -> None:
    if CORRUPTED_PLACEHOLDER_RE.search(translated):
        raise ProtectedTokenError("translated text contains corrupted protected placeholder text")
    source_counts = count_protected_fragments(source)
    translated_counts = count_protected_fragments(translated)
    if source_counts != translated_counts:
        details = ", ".join(
            f"{pattern.pattern}: {src}!={dst}"
            for pattern, src, dst in zip(PROTECT_PATTERNS, source_counts, translated_counts)
            if src != dst
        )
        raise ProtectedTokenError(f"protected fragment count mismatch after restore: {details}")


def restore_text(
    text: str,
    protected: dict[str, str],
    source_text: str | None = None,
    style: PlaceholderStyle | None = None,
) -> str:
    style = style or _detect_style(protected)
    canonical = style.canonicalize(text)
    validate_protected_tokens(canonical, protected, style=style)
    # Regex-based replacement: plain str.replace would corrupt ZQXBA (10) when
    # replacing ZQXB (1) first.
    restored = style.regex.sub(
        lambda m: protected.get(style.token(style.parse_index(m)), m.group(0)),
        canonical,
    )
    if source_text is not None:
        validate_protected_fragment_counts(source_text, restored)
    return restored


# ---------------------------------------------------------------------------
# Segmented translation: peel citation runs off sentence ends
# ---------------------------------------------------------------------------
#
# ATT&CK text looks like "Sentence one.(Citation: A)(Citation: B) Sentence two."
# Sending those placeholders through MT is what corrupts them. Instead, every
# run of placeholders that follows sentence-final punctuation is removed, the
# remaining sentence "cores" are sent as one request (one core per line), and
# the placeholders are put back in their original positions afterwards.

_SENTENCE_END = r"[.!?:;؟؛]"


def plan_segments(
    masked: str,
    style: PlaceholderStyle,
) -> tuple[str, Callable[[str], str]] | None:
    token_body = style.regex.pattern
    edge_re = re.compile(rf"(?<={_SENTENCE_END})(?:[ \t]*(?:{token_body}))+")
    pieces: list[tuple[bool, str]] = []  # (send_to_mt, text)
    peeled = False
    for para_idx, para in enumerate(re.split(r"(\n+)", masked)):
        if para_idx % 2 == 1:  # newline separator
            pieces.append((False, para))
            continue
        pos = 0
        chunks: list[tuple[bool, str]] = []
        for m in edge_re.finditer(para):
            chunks.append((True, para[pos : m.start()]))
            chunks.append((False, m.group(0)))
            pos = m.end()
            peeled = True
        chunks.append((True, para[pos:]))
        for send, chunk in chunks:
            if not send:
                pieces.append((False, chunk))
                continue
            lead = chunk[: len(chunk) - len(chunk.lstrip())]
            trail = chunk[len(chunk.rstrip()) :]
            core = chunk.strip()
            if lead:
                pieces.append((False, lead))
            if core:
                has_words = bool(re.search(r"[A-Za-z]", style.regex.sub(" ", core)))
                pieces.append((has_words, core))
            if trail and core:
                pieces.append((False, trail))
    cores = [text for send, text in pieces if send]
    if not peeled and len(cores) <= 1:
        return None
    if not cores:
        return None
    payload = "\n".join(cores)

    def rebuild(translated: str) -> str:
        lines = translated.replace("\r\n", "\n").split("\n")
        if len(lines) != len(cores):
            lines = [line for line in lines if line.strip()]
        if len(lines) != len(cores):
            raise SegmentMismatch(f"expected {len(cores)} lines, got {len(lines)}")
        it = iter(lines)
        return "".join(next(it).strip() if send else text for send, text in pieces)

    return payload, rebuild


def translate_masked(
    call: Callable[[str], str],
    masked: str,
    style: PlaceholderStyle,
    enabled: bool = True,
) -> str:
    plan = plan_segments(masked, style) if enabled else None
    if plan is None:
        return call(masked)
    payload, rebuild = plan
    try:
        return rebuild(call(payload))
    except SegmentMismatch:
        return call(masked)


def translate_masked_batch(
    batch_call: Callable[[Sequence[str]], list[str]],
    masked_list: Sequence[str],
    style: PlaceholderStyle,
    enabled: bool = True,
) -> list[str]:
    plans = [plan_segments(m, style) if enabled else None for m in masked_list]
    payloads = [plan[0] if plan else masked for plan, masked in zip(plans, masked_list)]
    outputs = batch_call(payloads)
    results: list[str] = [""] * len(masked_list)
    retry: list[int] = []
    for idx, (plan, out) in enumerate(zip(plans, outputs)):
        if plan is None:
            results[idx] = out
            continue
        try:
            results[idx] = plan[1](out)
        except SegmentMismatch:
            retry.append(idx)
    if retry:
        for idx, out in zip(retry, batch_call([masked_list[i] for i in retry])):
            results[idx] = out
    return results


class SegmentingTranslator:
    """Wraps a provider so every call goes through translate_masked()."""

    def __init__(self, inner: Any, style: PlaceholderStyle, enabled: bool = True) -> None:
        self.inner = inner
        self.style = style
        self.enabled = enabled
        self.name = inner.name

    def translate_text(self, text: str) -> str:
        return translate_masked(self.inner.translate_text, text, self.style, self.enabled)

    def translate_batch(self, texts: Sequence[str]) -> list[str]:
        return translate_masked_batch(self.inner.translate_batch, texts, self.style, self.enabled)

    def _reset_translator(self) -> None:
        if hasattr(self.inner, "_reset_translator"):
            self.inner._reset_translator()


def chunked(items: Sequence[str], size: int) -> Iterator[Sequence[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def translate_with_retries(
    translator: Any,
    text: str,
    max_retries: int,
    initial_backoff: float,
    jitter_seconds: float = 0.0,
) -> str:
    backoff = initial_backoff
    last_error: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            if jitter_seconds > 0:
                time.sleep(random.uniform(0.0, jitter_seconds))
            return translator.translate_text(text)
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if hasattr(translator, "_reset_translator"):
                try:
                    translator._reset_translator()
                except Exception:  # noqa: BLE001
                    pass
            if attempt == max_retries:
                break
            time.sleep(backoff)
            backoff *= 2
    raise TranslationError(f"Failed to translate after {max_retries} attempts: {last_error}") from last_error


def has_existing_suffix_translation(
    container: Any,
    key: str | int,
    parent: Any | None,
    parent_key: str | int | None,
    suffix: str,
    source_value: str,
) -> bool:
    if isinstance(container, dict) and isinstance(key, str):
        translated_key = f"{key}{suffix}"
        if translated_key not in container or not isinstance(container[translated_key], str):
            return False
        translated = container[translated_key].strip()
        source = source_value.strip()
        return bool(translated) and translated != source

    if (
        isinstance(container, list)
        and isinstance(key, int)
        and isinstance(parent, dict)
        and isinstance(parent_key, str)
    ):
        translated_key = f"{parent_key}{suffix}"
        translated_list = parent.get(translated_key)
        if not (
            isinstance(translated_list, list)
            and key < len(translated_list)
            and isinstance(translated_list[key], str)
        ):
            return False
        translated = translated_list[key].strip()
        source = source_value.strip()
        return bool(translated) and translated != source

    return False


def strip_suffix_fields(node: Any, suffix: str) -> None:
    if isinstance(node, dict):
        for key in list(node):
            if isinstance(key, str) and key.endswith(suffix):
                del node[key]
            else:
                strip_suffix_fields(node[key], suffix)
    elif isinstance(node, list):
        for item in node:
            strip_suffix_fields(item, suffix)


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def collect_files(source_root: Path, datasets: Sequence[str]) -> list[Path]:
    files: list[Path] = []
    for dataset in datasets:
        dataset_path = source_root / dataset
        if not dataset_path.exists():
            print(f"[warn] dataset not found and will be skipped: {dataset_path}", file=sys.stderr)
            continue
        files.extend(sorted(dataset_path.rglob("*.json")))
    return files


def build_ssl_context(ca_bundle: str) -> ssl.SSLContext | None:
    if ca_bundle:
        return ssl.create_default_context(cafile=ca_bundle)
    try:
        import certifi  # type: ignore

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Translate selected MITRE CTI STIX JSON fields to Persian."
    )
    parser.add_argument(
        "--source-root",
        default=".",
        help="Path to repository root (default: current directory).",
    )
    parser.add_argument(
        "--output-root",
        default="translated/fa",
        help="Destination root for translated JSON files (default: translated/fa).",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Write translated output into source JSON files directly.",
    )
    parser.add_argument(
        "--datasets",
        nargs="+",
        default=DEFAULT_DATASETS,
        help="Top-level dataset directories to process.",
    )
    parser.add_argument(
        "--source-lang",
        default="en",
        help="Source language code (default: en).",
    )
    parser.add_argument(
        "--target-lang",
        default="fa",
        help="Target language code (default: fa).",
    )
    parser.add_argument(
        "--provider",
        choices=["google_public", "google_cloud", "googletrans", "argos_offline"],
        default="google_public",
        help="Translation backend.",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("GOOGLE_TRANSLATE_API_KEY", ""),
        help="Google Cloud API key (required only for --provider google_cloud).",
    )
    parser.add_argument(
        "--cache-db",
        default=".translation-cache/cti_fa.sqlite3",
        help="SQLite translation cache file.",
    )
    parser.add_argument(
        "--cache-provider-fallbacks",
        nargs="*",
        default=[],
        help=(
            "Optional provider names to reuse cached translations from "
            "(e.g. google_public google_cloud)."
        ),
    )
    parser.add_argument(
        "--glossary",
        default="data/glossary_fa.json",
        help=(
            "Editable Persian glossary JSON. Existing path is applied before "
            "machine translation through protected placeholders (default: data/glossary_fa.json)."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=["replace", "overlay", "suffix"],
        default="replace",
        help=(
            "replace: overwrite selected source fields with Persian text in output. "
            "overlay: keep source text and write Persian values under x_cti_persian_translations. "
            "suffix: keep source fields and add sibling *_fa fields."
        ),
    )
    parser.add_argument(
        "--fa-suffix",
        default="_fa",
        help="Suffix used by --mode suffix (default: _fa).",
    )
    parser.add_argument(
        "--overlay-key",
        default="x_cti_persian_translations",
        help="Object key used in overlay mode (default: x_cti_persian_translations).",
    )
    parser.add_argument(
        "--paths",
        nargs="+",
        default=DEFAULT_TRANSLATABLE_PATHS,
        help="Path patterns to translate.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=48,
        help="Batch size for cloud API mode (default: 48, max API is 128).",
    )
    parser.add_argument(
        "--ca-bundle",
        default=os.getenv("SSL_CERT_FILE", ""),
        help="Path to CA bundle PEM file (default: auto-detect via certifi).",
    )
    parser.add_argument(
        "--argos-auto-install",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "For --provider argos_offline: auto-download and install source-target model "
            "if not already installed (default: true)."
        ),
    )
    parser.add_argument(
        "--argos-package-path",
        default="",
        help=(
            "For --provider argos_offline: path to a local .argosmodel file "
            "(for example translate-en_fa.argosmodel)."
        ),
    )
    parser.add_argument(
        "--argos-package-index",
        default="",
        help=(
            "For --provider argos_offline: custom Argos package index URL. "
            "Default index is used when omitted."
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of worker threads for translation calls (default: 4).",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=5,
        help="Max retries per translation call (default: 5).",
    )
    parser.add_argument(
        "--backoff",
        type=float,
        default=1.0,
        help="Initial retry backoff in seconds (default: 1.0).",
    )
    parser.add_argument(
        "--jitter",
        type=float,
        default=0.2,
        help="Random sleep jitter (seconds) before each network translation call.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=100,
        help="Print progress every N files (default: 100).",
    )
    parser.add_argument(
        "--progress-seconds",
        type=float,
        default=30.0,
        help="Print heartbeat progress at least every N seconds (default: 30).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Process only first N files (0 means all files).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan and report what would be translated without writing files.",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help=(
            "When writing output, skip files that already exist under --output-root. "
            "Useful for resuming interrupted runs. In --in-place --mode suffix, "
            "skip files that already contain *_fa values."
        ),
    )
    parser.add_argument(
        "--cache-only",
        action="store_true",
        help="Use only cached translations and do not call a machine translation provider.",
    )
    parser.add_argument(
        "--strip-existing-suffixes",
        action="store_true",
        help="Remove existing *_fa fields from source JSON before applying suffix translations.",
    )
    quality = parser.add_argument_group("translation quality")
    quality.add_argument(
        "--glossary-strategy",
        choices=GLOSSARY_STRATEGIES,
        default="post",
        help=(
            "post (default): send plain English to MT and enforce the glossary afterwards "
            "with source-conditional fa_fixes (no extra placeholders). "
            "placeholder: legacy behaviour, glossary terms become placeholders carrying the "
            "Persian target. inline: glossary targets are written into the English text "
            "before MT. Protected terms are masked in every strategy."
        ),
    )
    quality.add_argument(
        "--placeholder-style",
        choices=sorted(STYLES),
        default="tag",
        help=(
            "Token format for protected spans (default: tag). A/B test on 120 ATT&CK "
            "descriptions with google_public (2026-10-21): legacy 56.7%% restored intact, "
            "caps 99.2%%, tag 100%%. Re-run scripts/ab_test_placeholders.py when switching provider."
        ),
    )
    quality.add_argument(
        "--segment",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Peel citation placeholders off sentence ends and send one sentence per line (default: on).",
    )
    quality.add_argument(
        "--mask-extras",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Also mask markdown links, registry keys, paths and file names (default: on).",
    )
    quality.add_argument(
        "--auto-protect-names",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Keep names/aliases of groups, software and campaigns in English "
            "(default: glossary auto_protect_stix_names.enabled)."
        ),
    )
    quality.add_argument(
        "--postprocess",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Apply Persian normalization and glossary fa_fixes to every output value (default: on).",
    )
    quality.add_argument(
        "--quality-gate",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Reject cached and fresh translations with hallucination, degenerate repetition, "
            "wiki markup or abnormal length ratio (default: on)."
        ),
    )
    quality.add_argument(
        "--overrides",
        default="data/overrides_fa.json",
        help=(
            "Reviewed name translations and name templates; they take priority over MT and "
            "the cache, and also localize ATT&CK link text (default: data/overrides_fa.json)."
        ),
    )
    quality.add_argument(
        "--link-names",
        default="",
        help=(
            "Optional JSON object {English name: Persian name} used to localize the visible "
            "text of ATT&CK markdown links in the output."
        ),
    )
    quality.add_argument(
        "--quality-report",
        default="",
        help="Optional JSONL path; one line per rejected translation with its issue codes.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source_root = Path(args.source_root).resolve()
    output_root = Path(args.output_root).resolve()
    in_place = bool(args.in_place)
    ssl_context = build_ssl_context(args.ca_bundle)

    if args.provider == "google_cloud":
        if not args.api_key:
            print(
                "[error] --provider google_cloud requires --api-key or GOOGLE_TRANSLATE_API_KEY.",
                file=sys.stderr,
            )
            return 2
        translator: (
            GooglePublicTranslator | GoogleCloudTranslator | GoogleTransTranslator | ArgosOfflineTranslator
        ) = GoogleCloudTranslator(
            source_lang=args.source_lang,
            target_lang=args.target_lang,
            api_key=args.api_key,
            ssl_context=ssl_context,
        )
    elif args.provider == "googletrans":
        translator = GoogleTransTranslator(
            source_lang=args.source_lang,
            target_lang=args.target_lang,
        )
    elif args.provider == "argos_offline":
        translator = ArgosOfflineTranslator(
            source_lang=args.source_lang,
            target_lang=args.target_lang,
            auto_install=args.argos_auto_install,
            package_path=args.argos_package_path,
            package_index=args.argos_package_index,
        )
    else:
        translator = GooglePublicTranslator(
            source_lang=args.source_lang,
            target_lang=args.target_lang,
            ssl_context=ssl_context,
        )

    matcher = PathMatcher(args.paths)
    cache = SQLiteTranslationCache(Path(args.cache_db).resolve())
    glossary = Glossary.from_path((source_root / args.glossary).resolve())
    style = STYLES[args.placeholder_style]
    mt = SegmentingTranslator(translator, style, enabled=args.segment)

    auto_cfg = glossary.payload.get("auto_protect_stix_names", {}) if isinstance(glossary.payload, dict) else {}
    auto_cfg = auto_cfg if isinstance(auto_cfg, dict) else {}
    auto_protect = args.auto_protect_names if args.auto_protect_names is not None else bool(auto_cfg.get("enabled", False))
    name_types = set(auto_cfg.get("types", ["intrusion-set", "malware", "tool", "campaign"]))
    if auto_protect:
        added = glossary.add_protected_terms(
            build_stix_name_terms(
                source_root,
                args.datasets,
                sorted(name_types),
                exclude=auto_cfg.get("exclude", []),
            )
        )
        print(f"[info] auto-protected STIX names: {added}")

    overrides = NameOverrides.from_path((source_root / args.overrides).resolve())
    if overrides:
        print(f"[info] name overrides: {len(overrides.flat)} names, {len(overrides.templates)} templates")
    link_text_map: dict[str, str] = {}
    if args.link_names:
        link_text_map = json.loads(Path(args.link_names).read_text(encoding="utf-8"))
    elif overrides and overrides.localize_links:
        link_text_map = overrides.link_map()
    quality_report = open(args.quality_report, "a", encoding="utf-8") if args.quality_report else None

    finalize_memo: dict[tuple[str, str], str] = {}
    quality_memo: dict[tuple[str, str], list[str]] = {}

    def finalize(source_value: str, translated_value: str) -> str:
        if not args.postprocess:
            return translated_value
        key = (source_value, translated_value)
        if key not in finalize_memo:
            finalize_memo[key] = postprocess(source_value, translated_value, glossary.rules, link_text_map or None)
        return finalize_memo[key]

    def check_quality(source_value: str, translated_value: str, origin: str) -> None:
        if not args.quality_gate:
            return
        key = (source_value, translated_value)
        if key not in quality_memo:
            quality_memo[key] = quality_issues(source_value, finalize(source_value, translated_value), glossary.rules)
        issues = quality_memo[key]
        if is_severe(issues):
            if quality_report is not None:
                quality_report.write(
                    json.dumps(
                        {"origin": origin, "issues": issues, "source": source_value[:300], "fa": translated_value[:300]},
                        ensure_ascii=False,
                    )
                    + "\n"
                )
            raise QualityError(f"low-quality translation rejected ({', '.join(issues)})")

    try:
        files = collect_files(source_root, args.datasets)
        if args.limit and args.limit > 0:
            files = files[: args.limit]
        if not files:
            print("[error] No JSON files found for the selected datasets.", file=sys.stderr)
            return 1

        print(f"[info] source root: {source_root}")
        if in_place:
            print("[info] output: in-place")
        else:
            print(f"[info] output root: {output_root}")
        print(f"[info] files to process: {len(files)}")
        print(f"[info] provider: {translator.name}")
        if args.cache_only:
            print("[info] cache-only: enabled")
        if args.cache_provider_fallbacks:
            print(f"[info] cache fallbacks: {', '.join(args.cache_provider_fallbacks)}")
        print(f"[info] mode: {args.mode}")
        if glossary.terms or glossary.protected_terms:
            print(
                f"[info] glossary: {args.glossary} "
                f"({len(glossary.terms)} terms, {len(glossary.protected_terms)} protected terms)"
            )
        print(
            f"[info] glossary strategy: {args.glossary_strategy} | placeholder style: {style.name} | "
            f"segment: {args.segment} | mask extras: {args.mask_extras} | postprocess: {args.postprocess} | "
            f"quality gate: {args.quality_gate}"
        )

        translated_text_count = 0
        cache_hit_count = 0
        changed_file_count = 0
        failed_file_count = 0
        skipped_file_count = 0
        failed_translation_count = 0
        rejected_cache_count = 0
        memory_cache: dict[str, str] = {}
        start_time = time.time()
        last_progress_print = start_time

        def maybe_print_progress(idx_value: int, current_file: str = "", force: bool = False) -> None:
            nonlocal last_progress_print
            now = time.time()
            should_print = force
            if not should_print and args.progress_every > 0 and idx_value % args.progress_every == 0:
                should_print = True
            if not should_print and args.progress_seconds > 0 and now - last_progress_print >= args.progress_seconds:
                should_print = True
            if not should_print:
                return

            rate = idx_value / max(now - start_time, 1e-6)
            parts = [
                f"[progress] {idx_value}/{len(files)} files",
                f"changed: {changed_file_count}",
                f"skipped existing: {skipped_file_count}",
                f"cache hits: {cache_hit_count}",
                f"translated strings: {translated_text_count}",
                f"translation errors: {failed_translation_count}",
                f"rejected cache: {rejected_cache_count}",
                f"rate: {rate:.2f} files/s",
            ]
            if current_file:
                parts.append(f"current: {current_file}")
            print(" | ".join(parts))
            last_progress_print = now

        for idx, src_path in enumerate(files, start=1):
            rel_path = src_path.relative_to(source_root)
            dst_path = src_path if in_place else output_root / rel_path
            if args.progress_seconds > 0 and time.time() - last_progress_print >= args.progress_seconds:
                maybe_print_progress(idx - 1, str(rel_path), force=True)

            if args.skip_existing and not in_place and not args.dry_run and dst_path.exists():
                skipped_file_count += 1
                maybe_print_progress(idx, str(rel_path))
                continue

            try:
                raw = src_path.read_text(encoding="utf-8")
                data = json.loads(raw)
            except Exception as exc:
                failed_file_count += 1
                print(f"[warn] skip invalid JSON {rel_path}: {exc}", file=sys.stderr)
                continue
            if args.strip_existing_suffixes:
                strip_suffix_fields(data, args.fa_suffix)

            targets = [
                (container, key, target_path, value, parent, parent_key)
                for container, key, target_path, value, parent, parent_key in iter_string_targets(
                    data, matcher
                )
                if should_translate_text(value)
            ]
            # Fixed values that never go to MT:
            #  - names of groups/software/campaigns stay English by policy;
            #  - reviewed name overrides (data/overrides_fa.json).
            fixed_values: dict[int, str] = {}
            for target in targets:
                if target[2] != "objects[].name" or not isinstance(target[0], dict):
                    continue
                obj_type = str(target[0].get("type", ""))
                if auto_protect and obj_type in name_types:
                    fixed_values[id(target)] = target[3]
                elif overrides:
                    override = overrides.for_object(obj_type, target[3])
                    if override:
                        fixed_values[id(target)] = override
            mt_targets = [target for target in targets if id(target) not in fixed_values]

            if not targets:
                if not args.dry_run:
                    ensure_parent(dst_path)
                    dst_path.write_text(raw, encoding="utf-8")
                maybe_print_progress(idx, str(rel_path))
                continue

            if in_place and args.skip_existing and args.mode == "suffix":
                already_translated = all(
                    has_existing_suffix_translation(
                        container=container,
                        key=key,
                        parent=parent,
                        parent_key=parent_key,
                        suffix=args.fa_suffix,
                        source_value=source_value,
                    )
                    for container, key, _, source_value, parent, parent_key in targets
                )
                if already_translated:
                    skipped_file_count += 1
                    maybe_print_progress(idx, str(rel_path))
                    continue

            unique_sources = list(dict.fromkeys(target[3] for target in mt_targets))
            unique_prepared: dict[str, tuple[str, dict[str, str]]] = {}

            translation_results: dict[str, str] = {}
            missing_sources: list[str] = []
            promoted_pairs: list[tuple[str, str]] = []
            for source_value in unique_sources:
                cached = memory_cache.get(source_value)
                should_promote_cached = False
                if cached is None:
                    cached = cache.get(
                        provider=translator.name,
                        source_lang=args.source_lang,
                        target_lang=args.target_lang,
                        source_text=source_value,
                    )
                if cached is None and args.cache_provider_fallbacks:
                    for fallback_provider in args.cache_provider_fallbacks:
                        if fallback_provider == translator.name:
                            continue
                        cached = cache.get(
                            provider=fallback_provider,
                            source_lang=args.source_lang,
                            target_lang=args.target_lang,
                            source_text=source_value,
                        )
                        if cached is not None:
                            should_promote_cached = True
                            break
                if cached is not None:
                    try:
                        validate_protected_fragment_counts(source_value, cached)
                        check_quality(source_value, cached, "cache")
                    except (ProtectedTokenError, QualityError):
                        rejected_cache_count += 1
                        cached = None
                if cached is not None:
                    translation_results[source_value] = cached
                    cache_hit_count += 1
                    memory_cache[source_value] = cached
                    if should_promote_cached:
                        promoted_pairs.append((source_value, cached))
                else:
                    missing_sources.append(source_value)
                    # Mask only what actually goes to MT.
                    unique_prepared[source_value] = protect_text(
                        source_value,
                        glossary=glossary,
                        strategy=args.glossary_strategy,
                        style=style,
                        mask_extras=args.mask_extras,
                    )

            if promoted_pairs:
                cache.put_many(
                    provider=translator.name,
                    source_lang=args.source_lang,
                    target_lang=args.target_lang,
                    pairs=promoted_pairs,
                )

            if missing_sources and args.cache_only:
                failed_translation_count += len(missing_sources)
            elif missing_sources and not args.dry_run:
                translated_pairs: list[tuple[str, str]] = []

                if isinstance(translator, GoogleCloudTranslator):
                    # Cloud API can batch multiple texts in one request.
                    for batch in chunked(missing_sources, max(1, min(args.batch_size, 128))):
                        masked_batch = [unique_prepared[source][0] for source in batch]
                        translated_batch = None
                        last_error: Exception | None = None
                        backoff = args.backoff
                        for attempt in range(1, args.max_retries + 1):
                            try:
                                translated_batch = mt.translate_batch(masked_batch)
                                break
                            except Exception as exc:  # noqa: BLE001
                                last_error = exc
                                if attempt == args.max_retries:
                                    break
                                time.sleep(backoff)
                                backoff *= 2
                        if translated_batch is None:
                            failed_translation_count += len(batch)
                            print(
                                f"[warn] batch translation failed for {len(batch)} strings in {rel_path}: {last_error}",
                                file=sys.stderr,
                            )
                            continue

                        for source_value, translated_masked in zip(batch, translated_batch):
                            protected = unique_prepared[source_value][1]
                            try:
                                translated = restore_text(
                                    translated_masked,
                                    protected,
                                    source_text=source_value,
                                    style=style,
                                )
                                check_quality(source_value, translated, "fresh")
                            except (ProtectedTokenError, QualityError) as exc:
                                failed_translation_count += 1
                                print(
                                    f"[warn] rejected translation with protected-token mismatch in {rel_path}: {exc}",
                                    file=sys.stderr,
                                )
                                continue
                            translation_results[source_value] = translated
                            translated_pairs.append((source_value, translated))
                        if args.progress_seconds > 0 and time.time() - last_progress_print >= args.progress_seconds:
                            maybe_print_progress(
                                idx - 1,
                                str(rel_path),
                                force=True,
                            )
                elif isinstance(translator, (GooglePublicTranslator, GoogleTransTranslator)):
                    # Public endpoints and googletrans are one-text-per-request with retries.
                    def run_one(source_value: str) -> tuple[str, str]:
                        masked = unique_prepared[source_value][0]
                        translated_masked = translate_with_retries(
                            translator=mt,
                            text=masked,
                            max_retries=args.max_retries,
                            initial_backoff=args.backoff,
                            jitter_seconds=args.jitter,
                        )
                        protected = unique_prepared[source_value][1]
                        restored = restore_text(
                            translated_masked,
                            protected,
                            source_text=source_value,
                            style=style,
                        )
                        check_quality(source_value, restored, "fresh")
                        return source_value, restored

                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=max(1, args.workers)
                    ) as executor:
                        future_to_source = {
                            executor.submit(run_one, text): text for text in missing_sources
                        }
                        for future in concurrent.futures.as_completed(future_to_source):
                            source_value = future_to_source[future]
                            try:
                                source_value, translated = future.result()
                            except Exception as exc:  # noqa: BLE001
                                failed_translation_count += 1
                                print(
                                    f"[warn] translation failed for one string in {rel_path}: {exc}",
                                    file=sys.stderr,
                                )
                                continue
                            translation_results[source_value] = translated
                            translated_pairs.append((source_value, translated))
                            if (
                                args.progress_seconds > 0
                                and time.time() - last_progress_print >= args.progress_seconds
                            ):
                                maybe_print_progress(
                                    idx - 1,
                                    str(rel_path),
                                    force=True,
                                )
                else:
                    # Offline translation can also benefit from thread-level parallelism.
                    def run_offline(source_value: str) -> tuple[str, str]:
                        masked = unique_prepared[source_value][0]
                        translated_masked = mt.translate_text(masked)
                        protected = unique_prepared[source_value][1]
                        restored = restore_text(
                            translated_masked,
                            protected,
                            source_text=source_value,
                            style=style,
                        )
                        check_quality(source_value, restored, "fresh")
                        return source_value, restored

                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=max(1, args.workers)
                    ) as executor:
                        future_to_source = {
                            executor.submit(run_offline, text): text for text in missing_sources
                        }
                        for future in concurrent.futures.as_completed(future_to_source):
                            source_value = future_to_source[future]
                            try:
                                source_value, translated = future.result()
                            except Exception as exc:  # noqa: BLE001
                                failed_translation_count += 1
                                print(
                                    f"[warn] offline translation failed for one string in {rel_path}: {exc}",
                                    file=sys.stderr,
                                )
                                continue
                            translation_results[source_value] = translated
                            translated_pairs.append((source_value, translated))
                            if (
                                args.progress_seconds > 0
                                and time.time() - last_progress_print >= args.progress_seconds
                            ):
                                maybe_print_progress(
                                    idx - 1,
                                    str(rel_path),
                                    force=True,
                                )

                cache.put_many(
                    provider=translator.name,
                    source_lang=args.source_lang,
                    target_lang=args.target_lang,
                    pairs=translated_pairs,
                )
                for source, translated in translated_pairs:
                    memory_cache[source] = translated

            if args.dry_run:
                translated_text_count += len(targets)
                maybe_print_progress(idx, str(rel_path))
                continue

            file_changed = False
            overlay_entries: list[dict[str, str]] = []
            for target in targets:
                container, key, target_path, source_value, parent, parent_key = target
                if id(target) in fixed_values:
                    translated_value = fixed_values[id(target)]
                else:
                    translated_value = translation_results.get(source_value)
                    if translated_value:
                        translated_value = finalize(source_value, translated_value)
                    if overrides and overrides.paragraphs:
                        translated_value = overrides.apply_paragraphs(source_value, translated_value or None)
                    if not translated_value:
                        continue

                translated_text_count += 1
                if args.mode == "replace":
                    if container[key] != translated_value:
                        container[key] = translated_value
                        file_changed = True
                elif args.mode == "suffix":
                    if isinstance(container, dict) and isinstance(key, str):
                        fa_key = f"{key}{args.fa_suffix}"
                        if container.get(fa_key) != translated_value:
                            container[fa_key] = translated_value
                            file_changed = True
                    elif (
                        isinstance(container, list)
                        and isinstance(key, int)
                        and isinstance(parent, dict)
                        and isinstance(parent_key, str)
                    ):
                        fa_key = f"{parent_key}{args.fa_suffix}"
                        existing_list = parent.get(fa_key)
                        if not isinstance(existing_list, list):
                            existing_list = [None] * len(container)
                            parent[fa_key] = existing_list
                        if len(existing_list) < len(container):
                            existing_list.extend([None] * (len(container) - len(existing_list)))
                        if existing_list[key] != translated_value:
                            existing_list[key] = translated_value
                            file_changed = True
                else:
                    overlay_entries.append(
                        {
                            "path": target_path,
                            "source": source_value,
                            "translated": translated_value,
                        }
                    )
                    file_changed = True

            if args.mode == "overlay" and overlay_entries:
                existing = data.get(args.overlay_key)
                if not isinstance(existing, list):
                    existing = []
                    data[args.overlay_key] = existing
                existing.extend(overlay_entries)

            if file_changed:
                changed_file_count += 1

            ensure_parent(dst_path)
            dst_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=4) + "\n",
                encoding="utf-8",
            )

            maybe_print_progress(idx, str(rel_path))

        print("")
        print("[done]")
        print(f"processed files: {len(files)}")
        print(f"changed files: {changed_file_count}")
        print(f"translated strings: {translated_text_count}")
        print(f"cache hits: {cache_hit_count}")
        print(f"skipped existing files: {skipped_file_count}")
        print(f"failed translations: {failed_translation_count}")
        print(f"rejected cache hits: {rejected_cache_count}")
        print(f"failed files: {failed_file_count}")
        return 0
    finally:
        cache.close()
        if quality_report is not None:
            quality_report.close()


if __name__ == "__main__":
    raise SystemExit(main())
