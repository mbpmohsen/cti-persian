#!/usr/bin/env python3
"""
A/B test placeholder styles and glossary strategies against a real MT provider.

Takes a sample of English descriptions that contain citations / code / links,
translates the same sample with several pipeline configurations and reports,
per configuration:

  ok%          restored without losing or corrupting any protected span
  severe%      hallucination / repetition / wiki markup / abnormal length
  miss         glossary misses (target term absent although source has the term)
  fixes        how many fa_fixes the post-editor had to apply (lower = MT already right)

Writes translated/ab-test/<timestamp>/{summary.json,side_by_side.tsv} so a human
can read the variants next to each other. Needs network access to the provider,
so run it on your own machine (Google is not reachable from Claude's sandbox).

Example:
  python scripts/ab_test_placeholders.py --sample 120 --sleep 0.7
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import translate_cti_to_persian as tr  # noqa: E402
from fa_text import is_severe, postprocess, quality_issues  # noqa: E402

DEFAULT_CONFIGS = [
    # name, placeholder style, glossary strategy, segment, mask extras
    ("baseline_legacy", "legacy", "placeholder", False, False),
    ("legacy_post_seg", "legacy", "post", True, True),
    ("caps_post_seg", "caps", "post", True, True),
    ("tag_post_seg", "tag", "post", True, True),
    ("caps_inline_seg", "caps", "inline", True, True),
]


def pick_sample(bundle: Path, size: int, seed: int) -> list[str]:
    objects = json.loads(bundle.read_text(encoding="utf-8"))["objects"]
    pool = []
    for obj in objects:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        desc = obj.get("description")
        if not isinstance(desc, str) or not (120 <= len(desc) <= 1800):
            continue
        score = desc.count("(Citation:") + desc.count("<code>") + desc.count("](http")
        pool.append((score, desc))
    rng = random.Random(seed)
    rng.shuffle(pool)
    rich = [d for s, d in pool if s >= 2]
    plain = [d for s, d in pool if s < 2]
    take_rich = min(len(rich), int(size * 0.75))
    return rich[:take_rich] + plain[: size - take_rich]


def count_fixes(source: str, raw: str, rules) -> int:  # noqa: ANN001
    fixed = postprocess(source, raw, rules)
    return sum(1 for a, b in zip(raw.split(), fixed.split()) if a != b)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source-root", default=".")
    parser.add_argument("--bundle", default="enterprise-attack/enterprise-attack.json")
    parser.add_argument("--glossary", default="data/glossary_fa.json")
    parser.add_argument("--provider", choices=["google_public", "google_cloud"], default="google_public")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--sample", type=int, default=100)
    parser.add_argument("--seed", type=int, default=13)
    parser.add_argument("--sleep", type=float, default=0.7, help="Seconds between requests (avoid HTTP 429).")
    parser.add_argument("--configs", nargs="*", default=[c[0] for c in DEFAULT_CONFIGS])
    parser.add_argument("--output-dir", default="translated/ab-test")
    args = parser.parse_args()

    root = Path(args.source_root).resolve()
    glossary = tr.Glossary.from_path(root / args.glossary)
    cfg = glossary.payload.get("auto_protect_stix_names", {}) or {}
    glossary.add_protected_terms(tr.build_stix_name_terms(root, ["enterprise-attack"], exclude=cfg.get("exclude", [])))
    if args.provider == "google_cloud":
        provider = tr.GoogleCloudTranslator("en", "fa", api_key=args.api_key, ssl_context=tr.build_ssl_context(""))
    else:
        provider = tr.GooglePublicTranslator("en", "fa", ssl_context=tr.build_ssl_context(""))

    sample = pick_sample(root / args.bundle, args.sample, args.seed)
    print(f"[info] sample size: {len(sample)}")
    configs = [c for c in DEFAULT_CONFIGS if c[0] in args.configs]

    rows: list[dict[str, str]] = [{"source": s} for s in sample]
    summary = {}
    for name, style_name, strategy, segment, mask_extras in configs:
        style = tr.STYLES[style_name]
        mt = tr.SegmentingTranslator(provider, style, enabled=segment)
        ok = severe = misses = fixes = errors = 0
        started = time.time()
        for idx, source in enumerate(sample):
            masked, protected = tr.protect_text(
                source, glossary=glossary, strategy=strategy, style=style, mask_extras=mask_extras
            )
            try:
                raw_masked = tr.translate_with_retries(mt, masked, max_retries=4, initial_backoff=2.0)
            except Exception as exc:  # noqa: BLE001
                errors += 1
                rows[idx][name] = f"ERROR: {exc}"
                continue
            finally:
                time.sleep(args.sleep)
            try:
                raw = tr.restore_text(raw_masked, protected, source_text=source, style=style)
                ok += 1
            except tr.ProtectedTokenError as exc:
                rows[idx][name] = f"TOKEN_FAIL: {exc} | {raw_masked}"
                continue
            final = postprocess(source, raw, glossary.rules)
            issues = quality_issues(source, final, glossary.rules)
            severe += int(is_severe(issues))
            misses += sum(1 for i in issues if i.startswith("glossary_miss"))
            fixes += count_fixes(source, raw, glossary.rules)
            rows[idx][name] = final + (f"  ⟨{', '.join(issues)}⟩" if issues else "")
            if (idx + 1) % 20 == 0:
                print(f"[{name}] {idx + 1}/{len(sample)}")
        n = max(len(sample) - errors, 1)
        summary[name] = {
            "style": style_name,
            "strategy": strategy,
            "segment": segment,
            "ok_pct": round(100 * ok / n, 1),
            "severe_pct": round(100 * severe / max(ok, 1), 1),
            "glossary_misses": misses,
            "post_fixes": fixes,
            "errors": errors,
            "seconds": round(time.time() - started, 1),
        }
        print(f"[{name}] {json.dumps(summary[name], ensure_ascii=False)}")

    out_dir = root / args.output_dir / time.strftime("%Y%m%d-%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    cols = ["source"] + [c[0] for c in configs]
    with (out_dir / "side_by_side.tsv").open("w", encoding="utf-8") as fh:
        fh.write("\t".join(cols) + "\n")
        for row in rows:
            fh.write("\t".join(re.sub(r"[\t\n]+", " ⏎ ", row.get(c, "")) for c in cols) + "\n")

    print("")
    print(f"{'config':18} {'ok%':>6} {'severe%':>8} {'miss':>5} {'fixes':>6} {'err':>4}")
    for name, s in summary.items():
        print(f"{name:18} {s['ok_pct']:6} {s['severe_pct']:8} {s['glossary_misses']:5} {s['post_fixes']:6} {s['errors']:4}")
    best = max(summary.items(), key=lambda kv: (kv[1]["ok_pct"] - kv[1]["severe_pct"], -kv[1]["glossary_misses"]))
    print(f"\n[recommendation] {best[0]}  -> --placeholder-style {best[1]['style']} "
          f"--glossary-strategy {best[1]['strategy']} {'--segment' if best[1]['segment'] else '--no-segment'}")
    print(f"[info] side-by-side review: {out_dir / 'side_by_side.tsv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
