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
import re
import sqlite3
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterator, Sequence


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
    "objects[].external_references[].source_name",
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


class TranslationError(RuntimeError):
    """Raised when translation fails after retries."""


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


def protect_text(text: str) -> tuple[str, dict[str, str]]:
    protected: dict[str, str] = {}
    updated = text

    def replacer(match: re.Match[str]) -> str:
        token = f"[[[CTI_PRESERVE_{len(protected)}]]]"
        protected[token] = match.group(0)
        return token

    for pattern in PROTECT_PATTERNS:
        updated = pattern.sub(replacer, updated)
    return updated, protected


def restore_text(text: str, protected: dict[str, str]) -> str:
    restored = text
    missing: list[str] = []
    for token, original in protected.items():
        if token in restored:
            restored = restored.replace(token, original)
            continue
        if original not in restored:
            missing.append(original)
    if missing:
        restored = restored.rstrip() + " " + " ".join(missing)
    return restored


def chunked(items: Sequence[str], size: int) -> Iterator[Sequence[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def translate_with_retries(
    translator: GooglePublicTranslator | GoogleCloudTranslator,
    text: str,
    max_retries: int,
    initial_backoff: float,
) -> str:
    backoff = initial_backoff
    last_error: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            return translator.translate_text(text)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, TranslationError) as exc:
            last_error = exc
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
) -> bool:
    if isinstance(container, dict) and isinstance(key, str):
        translated_key = f"{key}{suffix}"
        return translated_key in container and isinstance(container[translated_key], str)

    if (
        isinstance(container, list)
        and isinstance(key, int)
        and isinstance(parent, dict)
        and isinstance(parent_key, str)
    ):
        translated_key = f"{parent_key}{suffix}"
        translated_list = parent.get(translated_key)
        return (
            isinstance(translated_list, list)
            and key < len(translated_list)
            and isinstance(translated_list[key], str)
        )

    return False


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
        choices=["google_public", "google_cloud", "argos_offline"],
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
        translator: GooglePublicTranslator | GoogleCloudTranslator | ArgosOfflineTranslator = GoogleCloudTranslator(
            source_lang=args.source_lang,
            target_lang=args.target_lang,
            api_key=args.api_key,
            ssl_context=ssl_context,
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
        if args.cache_provider_fallbacks:
            print(f"[info] cache fallbacks: {', '.join(args.cache_provider_fallbacks)}")
        print(f"[info] mode: {args.mode}")

        translated_text_count = 0
        cache_hit_count = 0
        changed_file_count = 0
        failed_file_count = 0
        skipped_file_count = 0
        memory_cache: dict[str, str] = {}

        for idx, src_path in enumerate(files, start=1):
            rel_path = src_path.relative_to(source_root)
            dst_path = src_path if in_place else output_root / rel_path

            if args.skip_existing and not in_place and not args.dry_run and dst_path.exists():
                skipped_file_count += 1
                if idx % 100 == 0 or idx == len(files):
                    print(
                        f"[progress] {idx}/{len(files)} files | skipped existing: {skipped_file_count}"
                    )
                continue

            try:
                raw = src_path.read_text(encoding="utf-8")
                data = json.loads(raw)
            except Exception as exc:
                failed_file_count += 1
                print(f"[warn] skip invalid JSON {rel_path}: {exc}", file=sys.stderr)
                continue

            targets = [
                (container, key, target_path, value, parent, parent_key)
                for container, key, target_path, value, parent, parent_key in iter_string_targets(
                    data, matcher
                )
                if should_translate_text(value)
            ]
            if not targets:
                if not args.dry_run:
                    ensure_parent(dst_path)
                    dst_path.write_text(raw, encoding="utf-8")
                if idx % 100 == 0 or idx == len(files):
                    print(f"[progress] {idx}/{len(files)} files")
                continue

            if in_place and args.skip_existing and args.mode == "suffix":
                already_translated = all(
                    has_existing_suffix_translation(
                        container=container,
                        key=key,
                        parent=parent,
                        parent_key=parent_key,
                        suffix=args.fa_suffix,
                    )
                    for container, key, _, _, parent, parent_key in targets
                )
                if already_translated:
                    skipped_file_count += 1
                    if idx % 100 == 0 or idx == len(files):
                        print(
                            f"[progress] {idx}/{len(files)} files | skipped existing: {skipped_file_count}"
                        )
                    continue

            unique_prepared: dict[str, tuple[str, dict[str, str]]] = {}
            for _, _, _, source_value, _, _ in targets:
                if source_value in unique_prepared:
                    continue
                masked, protected = protect_text(source_value)
                unique_prepared[source_value] = (masked, protected)

            translation_results: dict[str, str] = {}
            missing_sources: list[str] = []
            promoted_pairs: list[tuple[str, str]] = []
            for source_value, (_, _) in unique_prepared.items():
                cached = memory_cache.get(source_value)
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
                            promoted_pairs.append((source_value, cached))
                            break
                if cached is not None:
                    translation_results[source_value] = cached
                    cache_hit_count += 1
                    memory_cache[source_value] = cached
                else:
                    missing_sources.append(source_value)

            if promoted_pairs:
                cache.put_many(
                    provider=translator.name,
                    source_lang=args.source_lang,
                    target_lang=args.target_lang,
                    pairs=promoted_pairs,
                )

            if missing_sources and not args.dry_run:
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
                                translated_batch = translator.translate_batch(masked_batch)
                                break
                            except Exception as exc:  # noqa: BLE001
                                last_error = exc
                                if attempt == args.max_retries:
                                    break
                                time.sleep(backoff)
                                backoff *= 2
                        if translated_batch is None:
                            raise TranslationError(
                                f"Batch translation failed after retries: {last_error}"
                            )

                        for source_value, translated_masked in zip(batch, translated_batch):
                            protected = unique_prepared[source_value][1]
                            translated = restore_text(translated_masked, protected)
                            translation_results[source_value] = translated
                            translated_pairs.append((source_value, translated))
                elif isinstance(translator, GooglePublicTranslator):
                    # Public endpoint is safer as one-text-per-request with retries.
                    def run_one(source_value: str) -> tuple[str, str]:
                        masked = unique_prepared[source_value][0]
                        translated_masked = translate_with_retries(
                            translator=translator,
                            text=masked,
                            max_retries=args.max_retries,
                            initial_backoff=args.backoff,
                        )
                        protected = unique_prepared[source_value][1]
                        return source_value, restore_text(translated_masked, protected)

                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=max(1, args.workers)
                    ) as executor:
                        futures = [executor.submit(run_one, text) for text in missing_sources]
                        for future in concurrent.futures.as_completed(futures):
                            source_value, translated = future.result()
                            translation_results[source_value] = translated
                            translated_pairs.append((source_value, translated))
                else:
                    # Offline translation can also benefit from thread-level parallelism.
                    def run_offline(source_value: str) -> tuple[str, str]:
                        masked = unique_prepared[source_value][0]
                        translated_masked = translator.translate_text(masked)
                        protected = unique_prepared[source_value][1]
                        return source_value, restore_text(translated_masked, protected)

                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=max(1, args.workers)
                    ) as executor:
                        futures = [executor.submit(run_offline, text) for text in missing_sources]
                        for future in concurrent.futures.as_completed(futures):
                            source_value, translated = future.result()
                            translation_results[source_value] = translated
                            translated_pairs.append((source_value, translated))

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
                if idx % 100 == 0 or idx == len(files):
                    print(f"[progress] {idx}/{len(files)} files")
                continue

            file_changed = False
            overlay_entries: list[dict[str, str]] = []
            for container, key, target_path, source_value, parent, parent_key in targets:
                translated_value = translation_results.get(source_value)
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

            if idx % 100 == 0 or idx == len(files):
                print(
                    f"[progress] {idx}/{len(files)} files | changed: {changed_file_count} | translated strings: {translated_text_count}"
                )

        print("")
        print("[done]")
        print(f"processed files: {len(files)}")
        print(f"changed files: {changed_file_count}")
        print(f"translated strings: {translated_text_count}")
        print(f"cache hits: {cache_hit_count}")
        print(f"skipped existing files: {skipped_file_count}")
        print(f"failed files: {failed_file_count}")
        return 0
    finally:
        cache.close()


if __name__ == "__main__":
    raise SystemExit(main())
