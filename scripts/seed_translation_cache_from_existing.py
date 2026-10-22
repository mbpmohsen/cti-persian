#!/usr/bin/env python3
"""Seed the translation cache from existing Persian CTI output."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterator, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from translate_cti_to_persian import (  # noqa: E402
    DEFAULT_DATASETS,
    DEFAULT_TRANSLATABLE_PATHS,
    PathMatcher,
    SQLiteTranslationCache,
    ProtectedTokenError,
    should_translate_text,
    validate_protected_fragment_counts,
)
from fa_text import is_severe, quality_issues  # noqa: E402


PERSIAN_RE = re.compile(r"[\u0600-\u06FF]")


def has_persian(text: str) -> bool:
    return bool(PERSIAN_RE.search(text))


def get_objects(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict) and isinstance(data.get("objects"), list):
        return [obj for obj in data["objects"] if isinstance(obj, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def object_by_id(data: Any) -> dict[str, dict[str, Any]]:
    return {
        obj["id"]: obj
        for obj in get_objects(data)
        if isinstance(obj.get("id"), str)
    }


def iter_string_locations(
    node: Any,
    matcher: PathMatcher,
    path: str = "",
    loc: tuple[str | int, ...] = (),
) -> Iterator[tuple[tuple[str | int, ...], str]]:
    if isinstance(node, dict):
        for key, value in node.items():
            child_path = f"{path}.{key}" if path else key
            child_loc = (*loc, key)
            if isinstance(value, str):
                if matcher.matches(child_path):
                    yield child_loc, value
            elif isinstance(value, list):
                list_path = f"{child_path}[]"
                for idx, item in enumerate(value):
                    item_loc = (*child_loc, idx)
                    if isinstance(item, str):
                        if matcher.matches(list_path):
                            yield item_loc, item
                    else:
                        yield from iter_string_locations(item, matcher, list_path, item_loc)
            else:
                yield from iter_string_locations(value, matcher, child_path, child_loc)


def get_at(root: Any, loc: Sequence[str | int]) -> Any:
    node = root
    for part in loc:
        if isinstance(part, int):
            if not isinstance(node, list) or part >= len(node):
                return None
            node = node[part]
        else:
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
    return node


def get_suffix_value(root: Any, loc: Sequence[str | int], suffix: str) -> Any:
    if not loc:
        return None
    leaf = loc[-1]
    if isinstance(leaf, str):
        parent = get_at(root, loc[:-1])
        if isinstance(parent, dict):
            return parent.get(f"{leaf}{suffix}")
        return None
    if isinstance(leaf, int) and len(loc) >= 2 and isinstance(loc[-2], str):
        grandparent = get_at(root, loc[:-2])
        translated_list = grandparent.get(f"{loc[-2]}{suffix}") if isinstance(grandparent, dict) else None
        if isinstance(translated_list, list) and leaf < len(translated_list):
            return translated_list[leaf]
    return None


def collect_files(source_root: Path, datasets: Sequence[str]) -> list[Path]:
    files: list[Path] = []
    for dataset in datasets:
        dataset_root = source_root / dataset
        if dataset_root.exists():
            files.extend(
                path
                for path in sorted(dataset_root.rglob("*.json"))
                if path != dataset_root / f"{dataset}.json"
            )
    return files


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", default=".")
    parser.add_argument("--translated-root", default="translated/fa")
    parser.add_argument("--datasets", nargs="+", default=DEFAULT_DATASETS)
    parser.add_argument("--paths", nargs="+", default=DEFAULT_TRANSLATABLE_PATHS)
    parser.add_argument("--cache-db", default=".translation-cache/cti_fa.sqlite3")
    parser.add_argument("--provider", default="google_public")
    parser.add_argument("--source-lang", default="en")
    parser.add_argument("--target-lang", default="fa")
    parser.add_argument("--fa-suffix", default="_fa")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--quality-gate",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Skip candidates with hallucination/repetition/wiki markup/length-ratio issues (default: on).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source_root = Path(args.source_root).resolve()
    translated_root = Path(args.translated_root).resolve()
    matcher = PathMatcher(args.paths)
    pairs: dict[str, str] = {}
    skipped = 0
    skipped_quality = 0

    for src_path in collect_files(source_root, args.datasets):
        rel_path = src_path.relative_to(source_root)
        translated_path = translated_root / rel_path
        if not translated_path.exists():
            continue

        source_data = json.loads(src_path.read_text(encoding="utf-8"))
        translated_data = json.loads(translated_path.read_text(encoding="utf-8"))
        translated_objects = object_by_id(translated_data)

        for source_obj in get_objects(source_data):
            obj_id = source_obj.get("id")
            if not isinstance(obj_id, str):
                continue
            translated_obj = translated_objects.get(obj_id)
            if translated_obj is None:
                continue
            wrapped_source = {"objects": [source_obj]}
            wrapped_translated = {"objects": [translated_obj]}
            for loc, source_value in iter_string_locations(wrapped_source, matcher):
                if not should_translate_text(source_value):
                    continue
                candidate = get_suffix_value(wrapped_translated, loc, args.fa_suffix)
                if not isinstance(candidate, str):
                    translated_value = get_at(wrapped_translated, loc)
                    if isinstance(translated_value, str) and translated_value != source_value:
                        candidate = translated_value
                if (
                    isinstance(candidate, str)
                    and candidate.strip()
                    and candidate.strip() != source_value.strip()
                    and has_persian(candidate)
                ):
                    try:
                        validate_protected_fragment_counts(source_value, candidate)
                    except ProtectedTokenError:
                        skipped += 1
                        continue
                    if args.quality_gate and is_severe(quality_issues(source_value, candidate)):
                        skipped_quality += 1
                        continue
                    pairs[source_value] = candidate
                else:
                    skipped += 1

    print(f"candidate cache pairs: {len(pairs)}")
    print(f"skipped non-Persian/identical/marker-mismatch candidates: {skipped}")
    print(f"skipped low-quality candidates (hallucination/repetition/...): {skipped_quality}")
    if not args.dry_run:
        cache = SQLiteTranslationCache(Path(args.cache_db).resolve())
        try:
            cache.put_many(
                provider=args.provider,
                source_lang=args.source_lang,
                target_lang=args.target_lang,
                pairs=sorted(pairs.items()),
            )
        finally:
            cache.close()
        print(f"seeded cache: {args.cache_db}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
