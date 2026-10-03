"""Evaluate filtering and tag-classification accuracy against a labeled set."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.cleaners import filtering as f
from app.cleaners.eval_cases import EVAL_CASES


def main() -> None:
    total = len(EVAL_CASES)
    relevance_correct = 0
    category_correct = 0
    category_total = 0
    errors: list[tuple[str, str, bool, str | None, bool, str | None]] = []

    for text, expected_relevant, expected_l1 in EVAL_CASES:
        actual_relevant = f.matches_ai_keywords(text)
        actual_l1 = f.tag_category(text)

        if actual_relevant == expected_relevant:
            relevance_correct += 1

        if expected_l1 is not None:
            category_total += 1
            if actual_l1 == expected_l1:
                category_correct += 1

        if actual_relevant != expected_relevant or (
            expected_l1 is not None and actual_l1 != expected_l1
        ):
            errors.append((text, "relevant", actual_relevant, expected_relevant, actual_l1, expected_l1))

    relevance_accuracy = relevance_correct / total * 100
    category_accuracy = category_correct / category_total * 100 if category_total else 0.0

    print(f"filtering accuracy: {relevance_correct}/{total} = {relevance_accuracy:.1f}%")
    print(f"category accuracy:  {category_correct}/{category_total} = {category_accuracy:.1f}%")
    print(f"errors: {len(errors)}")
    for text, _kind, actual_relevant, expected_relevant, actual_l1, expected_l1 in errors:
        print(
            f"  - {text!r}: relevant={actual_relevant} (exp {expected_relevant}), "
            f"cat={actual_l1} (exp {expected_l1})"
        )


if __name__ == "__main__":
    main()
