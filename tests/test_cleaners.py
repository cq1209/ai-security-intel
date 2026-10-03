"""Unit tests for filtering, deduplication, and tag classification."""
from __future__ import annotations

import unittest

from app.cleaners.dedup import make_fingerprint
from app.cleaners.filtering import classify_tag, is_ai_relevant, matches_ai_keywords, tag_category


class FilterTest(unittest.TestCase):
    def test_ollama_description_is_relevant(self) -> None:
        cve = {
            "id": "CVE-2026-0001",
            "descriptions": [{"lang": "en", "value": "Ollama path traversal vulnerability"}],
            "configurations": [],
        }
        self.assertTrue(is_ai_relevant(cve))

    def test_new_affected_field_detects_component(self) -> None:
        cve = {
            "id": "CVE-2026-0003",
            "descriptions": [{"lang": "en", "value": "A denial of service vulnerability."}],
            "affected": [
                {
                    "affectedData": [
                        {"vendor": "vllm-project", "product": "vllm", "packageURL": "pkg:pypi/vllm"}
                    ]
                }
            ],
        }
        self.assertTrue(is_ai_relevant(cve))

    def test_generic_web_vulnerability_is_filtered(self) -> None:
        cve = {
            "id": "CVE-2026-0002",
            "descriptions": [{"lang": "en", "value": "SQL injection in a WordPress plugin"}],
            "configurations": [],
        }
        self.assertFalse(is_ai_relevant(cve))

    def test_prompt_injection_is_ai_security(self) -> None:
        self.assertTrue(matches_ai_keywords("Prompt injection leaks the system prompt"))

    def test_ai_only_without_security_is_downgraded(self) -> None:
        self.assertFalse(matches_ai_keywords("Ollama usage tutorial"))


class TagTreeTest(unittest.TestCase):
    def test_ollama_rce_maps_to_a1(self) -> None:
        self.assertEqual(classify_tag("Ollama remote code execution"), "A1")
        self.assertEqual(tag_category("Ollama remote code execution"), "A")

    def test_prompt_injection_maps_to_b1(self) -> None:
        self.assertEqual(classify_tag("Prompt injection leaks system prompt"), "B1")
        self.assertEqual(tag_category("Prompt injection"), "B")

    def test_generic_security_maps_to_f(self) -> None:
        self.assertEqual(tag_category("DrayTek router command injection"), "F")


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
