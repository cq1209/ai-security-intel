"""Recompute structured intelligence tags using the C tag tree."""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.cleaners import filtering as ai_filter
from app.db import structured_collection


def main() -> None:
    collection = structured_collection()
    l1_counts: Counter = Counter()
    l2_counts: Counter = Counter()
    unknown = 0

    for item in collection.find({}):
        text = " ".join(
            [item.get("title") or "", item.get("description") or "", " ".join(item.get("tags") or [])]
        )
        l2 = ai_filter.classify_tag(text)
        if l2:
            l1 = ai_filter._L2_TO_L1.get(l2, "F")
            tags = ai_filter.build_tags(text)
            l1_counts[l1] += 1
            l2_counts[l2] += 1
        else:
            tags = ["F", "通用安全情报"]
            l1_counts["F"] += 1
            unknown += 1
        item["tags"] = tags
        item["ai_relevant"] = l2 is not None
        collection.update_one(
            {"_id": item["_id"]},
            {"$set": {"tags": tags, "ai_relevant": item["ai_relevant"]}},
        )

    print("total:", collection.count_documents({}))
    print("L1 distribution:", dict(sorted(l1_counts.items())))
    print("L2 distribution:", dict(sorted(l2_counts.items())))
    print("unknown/fallback-F:", unknown)


if __name__ == "__main__":
    main()
