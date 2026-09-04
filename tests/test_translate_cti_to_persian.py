import unittest

from scripts.translate_cti_to_persian import (
    Glossary,
    ProtectedTokenError,
    protect_text,
    restore_text,
)


class ProtectedTokenTests(unittest.TestCase):
    def test_restore_preserves_citation_and_code(self) -> None:
        source = "Run <code>Regsvr32</code> for testing. (Citation: Example 2024)"
        masked, protected = protect_text(source)

        translated = restore_text(
            f"اجرای {list(protected)[0]} برای آزمایش. {list(protected)[1]}",
            protected,
            source_text=source,
        )

        self.assertIn("<code>Regsvr32</code>", translated)
        self.assertIn("(Citation: Example 2024)", translated)

    def test_restore_rejects_dropped_token(self) -> None:
        source = "See (Citation: Example 2024)"
        _masked, protected = protect_text(source)

        with self.assertRaises(ProtectedTokenError):
            restore_text("ارجاع حذف شده است.", protected, source_text=source)

    def test_glossary_terms_are_protected_before_translation(self) -> None:
        glossary = Glossary(
            terms=[
                {
                    "source": "Adversaries",
                    "target": "مهاجمان",
                    "whole_word": True,
                    "case_sensitive": False,
                }
            ],
            protected_terms=["Regsvr32"],
        )
        source = "Adversaries may use Regsvr32."
        masked, protected = protect_text(source, glossary=glossary)

        self.assertNotIn("Adversaries", masked)
        self.assertNotIn("Regsvr32", masked)
        restored = restore_text(masked, protected, source_text=source)
        self.assertIn("مهاجمان", restored)
        self.assertIn("Regsvr32", restored)


if __name__ == "__main__":
    unittest.main()
