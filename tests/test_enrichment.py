"""Unit tests for paper and attack-chain enrichment."""
from __future__ import annotations

import unittest

from app.enrichment.attack import enrich_item_attack, map_attack_chain
from app.enrichment.assets import _to_fofa_query
from app.enrichment.papers import _extract_search_terms, _lexical_similarity, _reconstruct_abstract
from app.enrichment.pipeline import _jsonl_lines, _strip_mongo_id, normalize_enrichment
from app.enrichment.remediation import (
    _cpe_parts,
    _extract_mitigation,
    enrich_item_remediation,
    infer_remediation,
)


class PapersTest(unittest.TestCase):
    def test_identical_text_scores_one(self) -> None:
        self.assertAlmostEqual(_lexical_similarity("remote code execution", "remote code execution"), 1.0)

    def test_unrelated_text_scores_low(self) -> None:
        self.assertLess(_lexical_similarity("prompt injection", "differential equations"), 0.5)

    def test_search_terms_extract_cve_id(self) -> None:
        item = {
            "intel_id": "CVE-2021-44228",
            "title": "CVE-2021-44228",
            "description": "Remote code execution in Apache Log4j2.",
        }
        terms = _extract_search_terms(item)
        self.assertIn("CVE-2021-44228", terms)
        self.assertTrue(any("log4j2" in term.lower() for term in terms))

    def test_search_terms_strip_trailing_punctuation(self) -> None:
        item = {
            "intel_id": "CVE-2026-90959",
            "title": "CVE-2026-90959",
            "description": "A path traversal was found in pulpcore.",
        }
        terms = _extract_search_terms(item)
        self.assertTrue(all(not term.endswith(".") for term in terms))

    def test_reconstruct_abstract_preserves_word_order(self) -> None:
        inverted = {"security": [0], "of": [1], "pulpcore": [2]}
        self.assertEqual(_reconstruct_abstract(inverted), "security of pulpcore")


class AttackChainTest(unittest.TestCase):
    def test_rce_maps_to_public_facing_application(self) -> None:
        chain = map_attack_chain("Remote code execution via command injection")
        ids = [step["technique_id"] for step in chain]
        self.assertIn("T1190", ids)
        self.assertIn("T1059", ids)

    def test_prompt_injection_maps_to_atlas(self) -> None:
        chain = map_attack_chain("Prompt injection allows jailbreaking the model")
        ids = [step["technique_id"] for step in chain]
        self.assertIn("AML.T0051", ids)
        self.assertIn("AML.T0054", ids)

    def test_chain_is_ordered_by_tactic(self) -> None:
        chain = map_attack_chain(
            "Remote code execution leading to arbitrary file read and denial of service"
        )
        tactics = [step["tactic"] for step in chain]
        self.assertEqual(tactics, sorted(tactics, key=tactics.index))
        self.assertIn("Initial Access", tactics)
        self.assertIn("Collection", tactics)
        self.assertIn("Impact", tactics)

    def test_enrich_item_sets_chain(self) -> None:
        item = {
            "intel_id": "CVE-2026-0001",
            "title": "CVE-2026-0001",
            "description": "SQL injection allows remote code execution.",
            "enrichment": {},
        }
        enrich_item_attack(item)
        self.assertTrue(item["enrichment"]["attack_chain"])


class FofaQueryTest(unittest.TestCase):
    def test_product_query_translation(self) -> None:
        self.assertEqual(_to_fofa_query("product:ollama"), 'app="ollama"')

    def test_port_query_translation(self) -> None:
        self.assertEqual(_to_fofa_query("port:11434"), 'port="11434"')


class RemediationTest(unittest.TestCase):
    def test_cpe_parts_parse_vendor_product_version(self) -> None:
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}
                            ]
                        }
                    ]
                }
            ]
        }
        vendor, product, versions = _cpe_parts(cve)
        self.assertEqual(vendor, "apache")
        self.assertEqual(product, "log4j")
        self.assertIn("2.14.1", versions)

    def test_mitigation_extracts_fixed_version(self) -> None:
        steps = _extract_mitigation(
            "The issue has been fixed in version 5.0.0.",
            "python-social-auth",
            None,
        )
        self.assertTrue(any("5.0.0" in step for step in steps))

    def test_infer_remediation_detects_component(self) -> None:
        remediation = infer_remediation(
            {"intel_id": "GHSA-1234", "title": "Ollama", "description": "Ollama path traversal"}
        )
        self.assertEqual(remediation["vendor"], "ollama")
        self.assertTrue(remediation["mitigation_steps"])

    def test_enrich_item_remediation_sets_remediation(self) -> None:
        item = {
            "intel_id": "GHSA-1234",
            "title": "Ollama",
            "description": "Ollama path traversal",
            "enrichment": {},
        }
        enrich_item_remediation(item)
        self.assertTrue(item["enrichment"]["remediation"]["mitigation_steps"])


class PipelineTest(unittest.TestCase):
    def test_strip_mongo_id(self) -> None:
        self.assertNotIn("_id", _strip_mongo_id({"_id": 1, "intel_id": "CVE-1"}))

    def test_jsonl_lines_are_valid(self) -> None:
        output = _jsonl_lines([{"intel_id": "CVE-1"}, {"intel_id": "CVE-2"}])
        lines = [line for line in output.splitlines() if line]
        self.assertEqual(len(lines), 2)

    def test_normalize_enrichment_fills_all_dimensions(self) -> None:
        item = {"intel_id": "CVE-1", "enrichment": {"cvss": {"score": 9.8}}}
        normalize_enrichment(item)
        keys = set(item["enrichment"].keys())
        self.assertTrue(
            {"cvss", "poc", "affected_assets", "related_papers", "attack_chain", "remediation"} <= keys
        )
        self.assertEqual(item["enrichment"]["related_papers"], [])
        self.assertIsNone(item["enrichment"]["remediation"])


if __name__ == "__main__":
    unittest.main()
