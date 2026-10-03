"""Accuracy regression tests for filtering and tag classification."""
from __future__ import annotations

import unittest

from app.cleaners import filtering as f
from app.cleaners.eval_cases import EVAL_CASES


class AccuracyTest(unittest.TestCase):
    def test_filtering_accuracy_at_least_95_percent(self) -> None:
        correct = 0
        for text, expected_relevant, _expected_l1 in EVAL_CASES:
            if f.matches_ai_keywords(text) == expected_relevant:
                correct += 1
        accuracy = correct / len(EVAL_CASES)
        self.assertGreaterEqual(accuracy, 0.95, f"filtering accuracy {accuracy:.2%}")

    def test_category_accuracy_at_least_95_percent(self) -> None:
        correct = 0
        total = 0
        for text, _expected_relevant, expected_l1 in EVAL_CASES:
            if expected_l1 is None:
                continue
            total += 1
            if f.tag_category(text) == expected_l1:
                correct += 1
        accuracy = correct / total
        self.assertGreaterEqual(accuracy, 0.95, f"category accuracy {accuracy:.2%}")


if __name__ == "__main__":
    unittest.main()
