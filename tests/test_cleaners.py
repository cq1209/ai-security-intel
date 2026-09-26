"""Unit tests for filtering and deduplication."""
from __future__ import annotations

import unittest

from app.cleaners.dedup import make_fingerprint
from app.cleaners.filtering import is_ai_relevant


class FilterTest(unittest.TestCase):
    def test_ollama_description_is_relevant(self) -> None:
        cve = {
            "id": "CVE-2026-0001",
            "descriptions": [{"lang": "en", "value": "Ollama path traversal vulnerability"}],
            "configurations": [],
        }
        self.assertTrue(is_ai_relevant(cve))

    def test_generic_web_vulnerability_is_filtered(self) -> None:
        cve = {
            "id": "CVE-2026-0002",
            "descriptions": [{"lang": "en", "value": "SQL injection in a WordPress plugin"}],
            "configurations": [],
        }
        self.assertFalse(is_ai_relevant(cve))


class DedupTest(unittest.TestCase):
    def test_cve_id_fingerprint_is_stable(self) -> None:
        first = make_fingerprint(intel_id="CVE-2026-0001")
        second = make_fingerprint(intel_id="CVE-2026-0001")
        self.assertEqual(first, second)

    def test_fallback_uses_title_and_date(self) -> None:
        first = make_fingerprint(title="Example", publish_date="2026-09-26")
        second = make_fingerprint(title="Example", publish_date="2026-09-26")
        third = make_fingerprint(title="Example", publish_date="2026-09-27")
        self.assertEqual(first, second)
        self.assertNotEqual(first, third)


if __name__ == "__main__":
    unittest.main()
