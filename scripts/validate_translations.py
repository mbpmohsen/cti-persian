#!/usr/bin/env python3
"""Validate Persian suffix translations against upstream CTI STIX JSON."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterator, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from translate_cti_to_persian import (  # noqa: E402
    CORRUPTED_PLACEHOLDER_RE,
    DEFAULT_DATASETS,
    DEFAULT_TRANSLATABLE_PATHS,
    PROTECT_PATTERNS,
    ATTACK_ID_ONLY_RE,
    PathMatcher,
    should_translate_text,
)
from fa_text import is_severe, load_glossary_payload, load_term_rules, quality_issues  # noqa: E402


PERSIAN_RE = re.compile(r"[\u0600-\u06FF]")
DEFAULT_KEEP_ENGLISH_NAME_TYPES = ["intrusion-set", "malware", "tool", "campaign"]
URL_RE = re.compile(r"https?://[^\s)]+", re.IGNORECASE)
ATTACK_ID_RE = re.compile(r"\b(?:TA|T|S|G|M|DS|D|C)\d{3,5}(?:\.\d{3})?\b")
MARKERS = {
    "citation": PROTECT_PATTERNS[1],
    "code": PROTECT_PATTERNS[0],
    "url": URL_RE,
    "attack_id": ATTACK_ID_RE,
}


def has_persian(text: str) -> bool:
    return bool(PERSIAN_RE.search(text))


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


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
) -> Iterator[tuple[tuple[str | int, ...], str, str]]:
    if isinstance(node, dict):
        for key, value in node.items():
            child_path = f"{path}.{key}" if path else key
            child_loc = (*loc, key)
            if isinstance(value, str):
                if matcher.matches(child_path):
                    yield child_loc, child_path, value
            elif isinstance(value, list):
                list_path = f"{child_path}[]"
                for idx, item in enumerate(value):
                    item_loc = (*child_loc, idx)
                    if isinstance(item, str):
                        if matcher.matches(list_path):
                            yield item_loc, list_path, item
                    else:
                        yield from iter_string_locations(item, matcher, list_path, item_loc)
            else:
                yield from iter_string_locations(value, matcher, child_path, child_loc)
    elif isinstance(node, list):
        list_path = f"{path}[]"
        for idx, item in enumerate(node):
            item_loc = (*loc, idx)
            if isinstance(item, str):
                if matcher.matches(list_path):
                    yield item_loc, list_path, item
            else:
                yield from iter_string_locations(item, matcher, list_path, item_loc)


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


def path_label(loc: Sequence[str | int]) -> str:
    label = ""
    for part in loc:
        if isinstance(part, int):
            label += f"[{part}]"
        else:
            label = f"{label}.{part}" if label else part
    return label


def marker_counts(text: str) -> dict[str, int]:
    return {name: len(pattern.findall(text)) for name, pattern in MARKERS.items()}


def collect_files(source_root: Path, datasets: Sequence[str]) -> list[tuple[str, Path]]:
    files: list[tuple[str, Path]] = []
    for dataset in datasets:
        dataset_root = source_root / dataset
        if not dataset_root.exists():
            continue
        files.extend(
            (dataset, path)
            for path in sorted(dataset_root.rglob("*.json"))
            if path != dataset_root / f"{dataset}.json"
        )
    return files


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", default=".", help="Repository root containing upstream datasets.")
    parser.add_argument("--translated-root", default="translated/fa", help="Persian output root.")
    parser.add_argument("--datasets", nargs="+", default=DEFAULT_DATASETS)
    parser.add_argument("--paths", nargs="+", default=DEFAULT_TRANSLATABLE_PATHS)
    parser.add_argument("--fa-suffix", default="_fa")
    parser.add_argument("--max-overwritten-objects", type=int, default=0)
    parser.add_argument("--max-marker-mismatches", type=int, default=0)
    parser.add_argument("--max-nonpersian-fa", type=int, default=1_000_000)
    parser.add_argument("--max-identical-fa", type=int, default=1_000_000)
    parser.add_argument("--min-coverage", type=float, default=0.0, help="Minimum overall named-object coverage percentage.")
    parser.add_argument("--glossary", default="data/glossary_fa.json", help="Glossary with fa_fixes/check rules.")
    parser.add_argument(
        "--max-severe-quality",
        type=int,
        default=1_000_000,
        help="Fail when more fields than this show hallucination/repetition/wiki markup/length-ratio issues.",
    )
    parser.add_argument(
        "--keep-english-name-types",
        nargs="*",
        default=DEFAULT_KEEP_ENGLISH_NAME_TYPES,
        help="Object types whose name_fa intentionally equals the English name (counted as healthy).",
    )
    parser.add_argument("--examples", type=int, default=20)
    parser.add_argument("--json-output", default="", help="Optional path for machine-readable report JSON.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source_root = Path(args.source_root).resolve()
    translated_root = Path(args.translated_root).resolve()
    matcher = PathMatcher(args.paths)
    rules = load_term_rules(load_glossary_payload(source_root / args.glossary))
    keep_english_types = set(args.keep_english_name_types)
    quality_counts: Counter[str] = Counter()

    named_status = Counter()
    field_counts = Counter()
    coverage: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    examples: dict[str, list[dict[str, Any]]] = defaultdict(list)

    files = collect_files(source_root, args.datasets)
    for dataset, src_path in files:
        rel_path = src_path.relative_to(source_root)
        translated_path = translated_root / rel_path
        source_data = load_json(src_path)
        translated_data = load_json(translated_path) if translated_path.exists() else {"objects": []}
        translated_objects = object_by_id(translated_data)

        for source_obj in get_objects(source_data):
            obj_id = source_obj.get("id")
            obj_type = str(source_obj.get("type", "unknown"))
            if not isinstance(obj_id, str):
                continue
            translated_obj = translated_objects.get(obj_id)
            wrapped_source = {"objects": [source_obj]}
            wrapped_translated = {"objects": [translated_obj]} if translated_obj is not None else {"objects": [{}]}

            source_name = source_obj.get("name")
            if isinstance(source_name, str) and should_translate_text(source_name):
                name_loc = ("objects", 0, "name")
                translated_name = get_at(wrapped_translated, name_loc)
                name_fa = get_suffix_value(wrapped_translated, name_loc, args.fa_suffix)
                coverage_key = (dataset, obj_type)
                coverage[coverage_key]["total"] += 1
                if isinstance(translated_name, str) and translated_name != source_name:
                    named_status["broken"] += 1
                    coverage[coverage_key]["broken"] += 1
                    if len(examples["overwritten_objects"]) < args.examples:
                        examples["overwritten_objects"].append(
                            {
                                "file": str(rel_path),
                                "id": obj_id,
                                "type": obj_type,
                                "source_name": source_name,
                                "translated_name": translated_name,
                            }
                        )
                elif isinstance(name_fa, str) and name_fa.strip() and name_fa.strip() != source_name.strip() and has_persian(name_fa):
                    named_status["healthy"] += 1
                    coverage[coverage_key]["translated"] += 1
                elif obj_type in keep_english_types and isinstance(name_fa, str) and name_fa.strip() == source_name.strip():
                    named_status["healthy"] += 1
                    coverage[coverage_key]["translated"] += 1
                else:
                    named_status["untranslated"] += 1
                    coverage[coverage_key]["untranslated"] += 1

            object_has_overwrite = False
            for loc, target_path, source_value in iter_string_locations(wrapped_source, matcher):
                if not should_translate_text(source_value):
                    continue
                translated_value = get_at(wrapped_translated, loc)
                fa_value = get_suffix_value(wrapped_translated, loc, args.fa_suffix)
                label = path_label(loc)

                if isinstance(translated_value, str) and translated_value != source_value:
                    field_counts["overwritten_fields"] += 1
                    object_has_overwrite = True
                    if len(examples["overwritten_fields"]) < args.examples:
                        examples["overwritten_fields"].append(
                            {
                                "file": str(rel_path),
                                "id": obj_id,
                                "path": label,
                                "source": source_value[:160],
                                "translated": translated_value[:160],
                            }
                        )

                candidate = fa_value if isinstance(fa_value, str) else None
                if candidate is None and isinstance(translated_value, str) and translated_value != source_value:
                    candidate = translated_value

                kept_english = label.endswith(".name") and label.count(".") == 2 and obj_type in keep_english_types
                if isinstance(fa_value, str) and not kept_english:
                    if fa_value.strip() == source_value.strip():
                        field_counts["identical_fa"] += 1
                        if len(examples["identical_fa"]) < args.examples:
                            examples["identical_fa"].append({"file": str(rel_path), "id": obj_id, "path": label})
                    if fa_value.strip() and not has_persian(fa_value):
                        field_counts["nonpersian_fa"] += 1
                        if len(examples["nonpersian_fa"]) < args.examples:
                            examples["nonpersian_fa"].append(
                                {"file": str(rel_path), "id": obj_id, "path": label, "value": fa_value[:160]}
                            )

                if candidate:
                    if CORRUPTED_PLACEHOLDER_RE.search(candidate):
                        field_counts["leftover_placeholders"] += 1
                        if len(examples["leftover_placeholders"]) < args.examples:
                            examples["leftover_placeholders"].append(
                                {"file": str(rel_path), "id": obj_id, "path": label, "value": candidate[:160]}
                            )
                    issues = quality_issues(source_value, candidate, rules)
                    for issue in issues:
                        quality_counts[issue] += 1
                        bucket = f"quality_{issue.split(':')[0]}"
                        if len(examples[bucket]) < args.examples:
                            examples[bucket].append(
                                {
                                    "file": str(rel_path),
                                    "id": obj_id,
                                    "path": label,
                                    "issue": issue,
                                    "source": source_value[:160],
                                    "value": candidate[:200],
                                }
                            )
                    if is_severe(issues):
                        field_counts["severe_quality"] += 1
                    source_markers = marker_counts(source_value)
                    candidate_markers = marker_counts(candidate)
                    for marker_name, source_count in source_markers.items():
                        candidate_count = candidate_markers[marker_name]
                        if source_count != candidate_count:
                            field_counts["marker_mismatches"] += 1
                            if len(examples["marker_mismatches"]) < args.examples:
                                examples["marker_mismatches"].append(
                                    {
                                        "file": str(rel_path),
                                        "id": obj_id,
                                        "path": label,
                                        "marker": marker_name,
                                        "source_count": source_count,
                                        "translated_count": candidate_count,
                                    }
                                )

            if object_has_overwrite:
                field_counts["overwritten_objects_any_field"] += 1

    total_named = sum(named_status.values())
    healthy = named_status["healthy"]
    coverage_percent = (healthy / total_named * 100.0) if total_named else 0.0

    print("Translation validation report")
    print(f"source root: {source_root}")
    print(f"translated root: {translated_root}")
    print(f"datasets: {', '.join(args.datasets)}")
    print("")
    print("Named object status")
    print(f"  healthy:      {named_status['healthy']}")
    print(f"  broken:       {named_status['broken']}")
    print(f"  untranslated: {named_status['untranslated']}")
    print(f"  coverage:     {coverage_percent:.2f}%")
    print("")
    print("Field quality checks")
    print(f"  overwritten fields:      {field_counts['overwritten_fields']}")
    print(f"  overwritten objects:     {field_counts['overwritten_objects_any_field']}")
    print(f"  *_fa without Persian:    {field_counts['nonpersian_fa']}")
    print(f"  *_fa identical to source: {field_counts['identical_fa']}")
    print(f"  marker mismatches:       {field_counts['marker_mismatches']}")
    print(f"  leftover placeholders:   {field_counts['leftover_placeholders']}")
    print(f"  severe quality issues:   {field_counts['severe_quality']}")
    print("")
    print("Translation quality (see docs/TRANSLATION_PIPELINE.md)")
    for issue, count in sorted(quality_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {issue:40} {count}")
    print("")
    print("Coverage by dataset/type")
    for (dataset, obj_type), counts in sorted(coverage.items()):
        total = counts["total"]
        translated = counts["translated"]
        pct = (translated / total * 100.0) if total else 0.0
        print(
            f"  {dataset:18} {obj_type:28} "
            f"{translated:5}/{total:<5} {pct:6.2f}% "
            f"broken={counts['broken']} untranslated={counts['untranslated']}"
        )

    for name in [
        "overwritten_objects",
        "overwritten_fields",
        "marker_mismatches",
        "leftover_placeholders",
        "nonpersian_fa",
        "identical_fa",
        "quality_hallucination",
        "quality_wiki_markup",
        "quality_repetition",
        "quality_length_ratio",
        "quality_mostly_english",
        "quality_glossary_miss",
    ]:
        if examples[name]:
            print("")
            print(f"Examples: {name}")
            for item in examples[name]:
                print(f"  - {json.dumps(item, ensure_ascii=False)}")

    report = {
        "named_status": dict(named_status),
        "coverage_percent": coverage_percent,
        "field_counts": dict(field_counts),
        "quality_counts": dict(quality_counts),
        "coverage": [
            {
                "dataset": dataset,
                "type": obj_type,
                **dict(counts),
                "coverage_percent": (counts["translated"] / counts["total"] * 100.0)
                if counts["total"]
                else 0.0,
            }
            for (dataset, obj_type), counts in sorted(coverage.items())
        ],
        "examples": examples,
    }
    if args.json_output:
        output_path = Path(args.json_output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    failed = False
    failed |= named_status["broken"] > args.max_overwritten_objects
    failed |= field_counts["marker_mismatches"] > args.max_marker_mismatches
    failed |= field_counts["leftover_placeholders"] > args.max_marker_mismatches
    failed |= field_counts["nonpersian_fa"] > args.max_nonpersian_fa
    failed |= field_counts["identical_fa"] > args.max_identical_fa
    failed |= coverage_percent < args.min_coverage
    failed |= field_counts["severe_quality"] > args.max_severe_quality
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
