import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import translate_cti_to_persian as tr
from scripts.fa_text import load_term_rules, normalize_persian, postprocess, quality_issues


GLOSSARY = {
    "terms": [
        {
            "source": "adversary",
            "target": "مهاجم",
            "match": r"\badversar(?:y|ies)\b",
            "fa_fixes": {"دشمنان": "مهاجمان", "دشمن": "مهاجم"},
            "check": True,
        },
        {
            "source": "legitimate",
            "target": "مشروع",
            "match": r"\blegitimate\b",
            "unless_source": r"\blegal",
            "fa_fixes": {"قانونی": "مشروع"},
        },
    ],
    "protected_terms": ["PowerShell"],
}


class PlaceholderStyleTests(unittest.TestCase):
    def test_caps_tokens_do_not_collide(self) -> None:
        style = tr.CAPS_STYLE
        protected = {style.token(i): f"(Citation: {i})" for i in range(12)}
        text = " ".join(style.token(i) for i in reversed(range(12)))
        restored = tr.restore_text(text, protected, style=style)
        self.assertIn("(Citation: 10)", restored)
        self.assertIn("(Citation: 1)", restored)
        self.assertNotIn("ZQX", restored)

    def test_tag_style_accepts_persian_digits(self) -> None:
        style = tr.TAG_STYLE
        protected = {style.token(3): "<code>whoami</code>"}
        restored = tr.restore_text('اجرای <x id="۳"/> روی سیستم', protected, style=style)
        self.assertIn("<code>whoami</code>", restored)

    def test_legacy_corruption_is_rejected(self) -> None:
        with self.assertRaises(tr.ProtectedTokenError):
            tr.validate_protected_fragment_counts("See it.", "ببینید [[رده:رده:]]")


class SegmentationTests(unittest.TestCase):
    def test_citation_runs_are_peeled_and_restored(self) -> None:
        style = tr.CAPS_STYLE
        masked = "First sentence.ZQXA ZQXB Second one.ZQXC\n\nThird."
        plan = tr.plan_segments(masked, style)
        self.assertIsNotNone(plan)
        payload, rebuild = plan
        self.assertEqual(payload, "First sentence.\nSecond one.\nThird.")
        out = rebuild("جمله اول.\nجمله دوم.\nسوم.")
        self.assertEqual(out, "جمله اول.ZQXA ZQXB جمله دوم.ZQXC\n\nسوم.")

    def test_line_mismatch_falls_back_to_whole_text(self) -> None:
        style = tr.CAPS_STYLE
        masked = "One.ZQXA Two."
        calls = []

        def fake(text: str) -> str:
            calls.append(text)
            return "یک و دو" if "\n" in text else "یک.ZQXA دو."

        self.assertEqual(tr.translate_masked(fake, masked, style), "یک.ZQXA دو.")
        self.assertEqual(len(calls), 2)


class PostprocessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rules = load_term_rules(GLOSSARY)

    def test_source_conditional_fix(self) -> None:
        src = "Adversaries may abuse legitimate tools."
        out = postprocess(src, "دشمنان ممکن است از ابزارهای قانونی سوء استفاده کنند.", self.rules)
        self.assertEqual(out, "مهاجمان ممکن است از ابزارهای مشروع سوءاستفاده کنند.")

    def test_unless_source_blocks_fix(self) -> None:
        src = "A legitimate and legal process."
        out = postprocess(src, "یک فرآیند قانونی.", self.rules)
        self.assertIn("قانونی", out)

    def test_fix_not_applied_without_source_term(self) -> None:
        out = postprocess("The enemy of my enemy.", "دشمن دشمن من.", self.rules)
        self.assertEqual(out, "دشمن دشمن من.")

    def test_protected_spans_untouched_and_zwnj(self) -> None:
        src = "Adversaries run code."
        fa = "دشمنان کد را اجرا می کنند <code>می کند</code> (Citation: دشمنان)"
        out = postprocess(src, fa, self.rules)
        self.assertTrue(out.startswith("مهاجمان کد را اجرا می\u200cکنند"))
        self.assertIn("<code>می کند</code>", out)
        self.assertIn("(Citation: دشمنان)", out)

    def test_compound_with_suffix(self) -> None:
        self.assertEqual(normalize_persian("نرم افزارهای مخرب"), "نرم\u200cافزارهای مخرب")

    def test_identifiers_are_not_mostly_english(self) -> None:
        src = "Clop has used built-in API functions such as WNetOpenEnumW(), WNetEnumResourceW() and VirtualAlloc() for discovery."
        fa = "Clop از توابع داخلی API مانند WNetOpenEnumW()، WNetEnumResourceW() و VirtualAlloc() برای کشف استفاده کرده است."
        self.assertNotIn("mostly_english", quality_issues(src, fa))

    def test_boundary_next_to_persian_comma(self) -> None:
        self.assertEqual(normalize_persian("نرم افزار، فایل ها"), "نرم\u200cافزار، فایل\u200cها")


class QualityTests(unittest.TestCase):
    def test_detects_hallucination_and_repetition(self) -> None:
        src = "Adversaries may perform Endpoint Denial of Service attacks to degrade availability of services."
        fa = "مهاجمان ممکن است حملات انجام دهند. آیات و روایات و روایات و روایات و ائمه علیه السلام"
        issues = quality_issues(src, fa)
        self.assertIn("hallucination", issues)
        self.assertIn("repetition", issues)

    def test_no_false_hallucination_inside_words(self) -> None:
        src = "ClearSky Cyber Security and Trend Micro. (2017, July). Operation Wilted Tulip: Exposing a cyber espionage apparatus."
        fa = "ClearSky و Trend Micro. (2017، ژوئیه). عملیات لاله پژمرده: افشای یک دستگاه جاسوسی سایبری."
        self.assertNotIn("hallucination", quality_issues(src, fa))
        self.assertIn("hallucination", quality_issues("See the list.", "فهرست را ببینید [[رده:رده:]]"))

    def test_glossary_miss_ignores_link_text(self) -> None:
        rules = load_term_rules(GLOSSARY)
        src = "Uses [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557)."
        fa = "از [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) استفاده می‌کند."
        self.assertEqual(quality_issues(src, fa, rules), [])


class NameOverrideTests(unittest.TestCase):
    def test_exact_template_and_parent_sub(self) -> None:
        o = tr.NameOverrides(
            {
                "names": {"attack-pattern": {"Scheduled Task/Job": "وظیفه/کار زمان‌بندی‌شده", "Cron": "Cron"}},
                "templates": [
                    {"types": ["x-mitre-detection-strategy"], "pattern": r"^Detection of (?P<t>.+)$", "target": "تشخیص {t}"},
                    {"types": ["x-mitre-analytic"], "pattern": r"^Analytic (?P<n>\d+)$", "target": "تحلیل تشخیصی {n}"},
                ],
            }
        )
        self.assertEqual(o.for_object("attack-pattern", "Cron"), "Cron")
        self.assertEqual(
            o.for_object("x-mitre-detection-strategy", "Detection of Scheduled Task/Job: Cron"),
            "تشخیص وظیفه/کار زمان‌بندی‌شده: Cron",
        )
        # unknown technique inside a template -> no half-English result
        self.assertIsNone(o.for_object("x-mitre-detection-strategy", "Detection of Something Else"))
        self.assertEqual(o.for_object("x-mitre-analytic", "Analytic 0110"), "تحلیل تشخیصی 0110")
        links = o.link_map()
        self.assertIn("Scheduled Task/Job", links)
        out = postprocess(
            "Uses [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053).",
            "از [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) استفاده می‌کند.",
            (),
            links,
        )
        self.assertIn("[وظیفه/کار زمان‌بندی‌شده](https://attack.mitre.org/techniques/T1053)", out)

    def test_paragraph_override_drops_duplicated_marker_tail(self) -> None:
        # Real case (ICS T0873): MT appended every citation/URL at the end of the
        # last paragraph; after replacing paragraph 1 they appeared twice.
        p1 = "Adversaries may infect files.(Citation: Beckhoff) Enables [Execution](https://attack.mitre.org/tactics/TA0104).(Citation: PLCdev)"
        p2 = "Adversaries may export code.(Citation: Falliere) Once downloaded it keeps running.(Citation: PLCdev)"
        source = p1 + " \n\n" + p2
        mt = (
            "متن ماشینی اول. \n\n"
            "مهاجمان ممکن است کد صادر کنند. پس از دانلود اجرا می‌شود.(Citation: PLCdev) "
            "(Citation: Beckhoff) (Citation: Falliere) https://attack.mitre.org/tactics/TA0104"
        )
        reviewed = "مهاجمان ممکن است فایل‌ها را آلوده کنند.(Citation: Beckhoff) [اجرا](https://attack.mitre.org/tactics/TA0104) را ممکن می‌کند.(Citation: PLCdev)"
        o = tr.NameOverrides({"paragraphs": {p1: reviewed}})
        out = o.apply_paragraphs(source, mt)
        self.assertTrue(out.startswith(reviewed))
        for token in ("(Citation: Beckhoff)", "(Citation: PLCdev)", "(Citation: Falliere)", "https://attack.mitre.org/tactics/TA0104"):
            self.assertEqual(out.count(token), source.count(token), token)

    def test_paragraph_override_keeps_tail_tokens_from_other_mt_paragraphs(self) -> None:
        # Real case (mobile T1638): MT dropped citations from paragraph 2 and
        # appended them to the end of paragraph 3; they must survive trimming.
        p1 = "Adversaries may sit in the middle."
        p2 = "Adversary-in-the-disk is a variant.(Citation: kaspersky)(Citation: checkpoint) More text."
        p3 = "Encryption helps.(Citation: NSC)"
        source = p1 + "\n\n" + p2 + "\n\n" + p3
        mt = "ماشینی.\n\nنوعی حمله است. متن بیشتر.\n\nرمزگذاری کمک می‌کند.(Citation: NSC) (Citation: kaspersky) (Citation: checkpoint)"
        o = tr.NameOverrides({"paragraphs": {p1: "مهاجمان ممکن است در میانه قرار بگیرند."}})
        out = o.apply_paragraphs(source, mt)
        for token in ("(Citation: kaspersky)", "(Citation: checkpoint)", "(Citation: NSC)"):
            self.assertEqual(out.count(token), 1, token)


class EndToEndTests(unittest.TestCase):
    def test_pipeline_with_fake_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ds = root / "enterprise-attack"
            (ds / "malware").mkdir(parents=True)
            (ds / "attack-pattern").mkdir(parents=True)
            (root / "data").mkdir()
            (root / "data" / "glossary_fa.json").write_text(
                json.dumps({**GLOSSARY, "auto_protect_stix_names": {"enabled": True}}, ensure_ascii=False),
                encoding="utf-8",
            )
            malware = {
                "type": "malware",
                "id": "malware--00000000-0000-0000-0000-000000000001",
                "name": "Agent Tesla",
                "description": "Agent Tesla is a spyware.",
            }
            technique = {
                "type": "attack-pattern",
                "id": "attack-pattern--00000000-0000-0000-0000-000000000002",
                "name": "Bind Mounts",
                "description": (
                    "Adversaries may abuse legitimate tools.(Citation: A)(Citation: B) "
                    "[Agent Tesla](https://attack.mitre.org/software/S0331) runs C:\\Windows\\evil.exe."
                ),
            }
            bundle = {"type": "bundle", "objects": [malware, technique]}
            (ds / "enterprise-attack.json").write_text(json.dumps(bundle), encoding="utf-8")
            (ds / "malware" / "m.json").write_text(json.dumps({"type": "bundle", "objects": [malware]}), encoding="utf-8")
            (ds / "attack-pattern" / "t.json").write_text(
                json.dumps({"type": "bundle", "objects": [technique]}), encoding="utf-8"
            )

            sent: list[str] = []

            def fake_translate(self, text: str) -> str:  # noqa: ANN001
                sent.append(text)
                table = {
                    "Adversaries may abuse legitimate tools.": "دشمنان ممکن است از ابزارهای قانونی سوء استفاده کنند.",
                    "Agent Tesla is a spyware.": "یک جاسوس افزار است.",
                    "Bind Mounts": "اتصال پایه ها",
                }
                return "\n".join(table.get(line, "ترجمه " + line) for line in text.split("\n"))

            argv = [
                "translate_cti_to_persian.py",
                "--source-root", str(root),
                "--output-root", str(root / "out"),
                "--datasets", "enterprise-attack",
                "--mode", "suffix",
                "--cache-db", str(root / "cache.sqlite3"),
                "--placeholder-style", "caps",
                "--workers", "1",
                "--jitter", "0",
                "--progress-every", "0",
                "--progress-seconds", "0",
            ]
            with mock.patch.object(tr.GooglePublicTranslator, "translate_text", fake_translate), mock.patch.object(
                sys, "argv", argv
            ):
                self.assertEqual(tr.main(), 0)

            out_mal = json.loads((root / "out/enterprise-attack/malware/m.json").read_text(encoding="utf-8"))["objects"][0]
            out_tech = json.loads((root / "out/enterprise-attack/attack-pattern/t.json").read_text(encoding="utf-8"))[
                "objects"
            ][0]
            # Software name is kept in English, not sent to MT.
            self.assertEqual(out_mal["name_fa"], "Agent Tesla")
            self.assertNotIn("Agent Tesla", "".join(sent))
            # Citations never reached MT; they come back in place.
            self.assertFalse(any("ZQXA" in s and "ZQXB" in s and "\n" in s for s in sent))
            desc = out_tech["description_fa"]
            self.assertIn("مهاجمان ممکن است از ابزارهای مشروع سوءاستفاده کنند.(Citation: A)(Citation: B)", desc)
            self.assertIn("[Agent Tesla](https://attack.mitre.org/software/S0331)", desc)
            self.assertIn("C:\\Windows\\evil.exe", desc)
            self.assertEqual(out_tech["description"], technique["description"])

            from scripts import validate_translations as vt

            report_path = root / "report.json"
            vargv = [
                "validate_translations.py",
                "--source-root", str(root),
                "--translated-root", str(root / "out"),
                "--datasets", "enterprise-attack",
                "--max-severe-quality", "0",
                "--json-output", str(report_path),
            ]
            with mock.patch.object(sys, "argv", vargv):
                self.assertEqual(vt.main(), 0)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["named_status"].get("healthy"), 2)  # Agent Tesla kept English + Bind Mounts
            self.assertEqual(report["field_counts"].get("severe_quality", 0), 0)


class EntityLinkTextTests(unittest.TestCase):
    def test_group_software_campaign_link_text_stays_english(self) -> None:
        src = "[Sandworm Team](https://attack.mitre.org/groups/G0034) used [Fakecalls](https://attack.mitre.org/software/S1080)."
        fa = "[تیم کرم شنی](https://attack.mitre.org/groups/G0034) از [تماس‌های جعلی](https://attack.mitre.org/software/S1080) استفاده کرد."
        out = postprocess(src, fa, ())
        self.assertIn("[Sandworm Team](https://attack.mitre.org/groups/G0034)", out)
        self.assertIn("[Fakecalls](https://attack.mitre.org/software/S1080)", out)

    def test_broken_link_span_is_not_collapsed(self) -> None:
        # Real case (mobile Chameleon): MT broke a link into "[https://...)" so the
        # bracket span swallowed a whole sentence up to the next link.
        src = "[Chameleon](https://attack.mitre.org/software/S1083) is a trojan. Active in 2023, [Chameleon](https://attack.mitre.org/software/S1083) targets users."
        fa = "[Chameleon](https://attack.mitre.org/software/S1083) یک تروجان است. [https://attack.mitre.org/software/S1083) فعال در ۲۰۲۳، کاربران را هدف گرفته است. [Chameleon](https://attack.mitre.org/software/S1083) گسترش یافت."
        out = postprocess(src, fa, ())
        self.assertIn("فعال در ۲۰۲۳", out)

if __name__ == "__main__":
    unittest.main()
