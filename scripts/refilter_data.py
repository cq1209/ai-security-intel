"""Re-evaluate existing structured intelligence with the current AI filter."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.cleaners import filtering as ai_filter
from app.db import raw_collection, structured_collection


def _recompute_relevance(item: dict) -> bool:
    source = str(item.get("source") or "")
    if source.startswith("vendor:"):
        return True

    intel_id = str(item.get("intel_id") or "")
    if source == "nvd":
        raw = raw_collection().find_one({"_id": intel_id})
        if raw and raw.get("data"):
            return ai_filter.is_ai_relevant(raw["data"])

    text = " ".join(
        [
            item.get("title") or "",
            item.get("description") or "",
            " ".join(item.get("tags") or []),
        ]
    )
    return ai_filter.matches_ai_keywords(text)


def main() -> None:
    collection = structured_collection()
    removed = 0
    kept = 0
    for item in list(collection.find({})):
        relevant = _recompute_relevance(item)
        if not relevant:
            collection.delete_one({"_id": item["_id"]})
            print("REMOVED", item.get("intel_id"), "|", (item.get("title") or "")[:40])
            removed += 1
            continue
        if "ai" not in (item.get("tags") or []):
            item["tags"] = list(item.get("tags") or []) + ["ai"]
        item["ai_relevant"] = True
        collection.update_one({"_id": item["_id"]}, {"$set": item})
        kept += 1
    print(f"done: removed={removed} kept={kept} total={collection.count_documents({})}")


if __name__ == "__main__":
    main()
