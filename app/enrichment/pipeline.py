"""Unified six-dimension enrichment pipeline and output exporters."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

from app.cleaners import filtering as ai_filter
from app.config import BASE_DIR
from app.db import enriched_collection, structured_collection
from app.enrichment.assets import enrich_item_assets
from app.enrichment.attack import enrich_item_attack
from app.enrichment.cvss import enrich_item_cvss
from app.enrichment.papers import enrich_item_papers
from app.enrichment.poc import enrich_item_poc
from app.enrichment.remediation import enrich_item_remediation
from app.logging_config import setup_logging

logger = logging.getLogger(__name__)

OUTPUT_DIR = BASE_DIR / "data" / "output"

ENRICHERS = (
    enrich_item_cvss,
    enrich_item_poc,
    enrich_item_assets,
    enrich_item_papers,
    enrich_item_attack,
    enrich_item_remediation,
)

DIMENSION_KEYS = {
    "enrich_item_cvss": "cvss",
    "enrich_item_poc": "poc",
    "enrich_item_assets": "affected_assets",
    "enrich_item_papers": "related_papers",
    "enrich_item_attack": "attack_chain",
    "enrich_item_remediation": "remediation",
}


def _dimension_filled(enrichment: Dict, dimension: str) -> bool:
    value = enrichment.get(dimension)
    if not value:
        return False
    if dimension == "cvss":
        return value.get("score") is not None
    if dimension == "poc":
        return bool(value.get("repo_url"))
    if dimension == "affected_assets":
        return bool(value.get("exposed_count"))
    if dimension == "remediation":
        return bool(value.get("patch_url") or value.get("mitigation_steps"))
    return bool(value)


def enrich_item(item: Dict) -> Dict:
    for enrich in ENRICHERS:
        try:
            item = enrich(item)
        except Exception as exc:  # pragma: no cover - defensive guard
            logger.warning(
                "Enrichment %s failed for %s: %s",
                enrich.__name__,
                item.get("intel_id"),
                exc,
            )
    return item


def normalize_enrichment(item: Dict) -> Dict:
    enrichment = item.setdefault("enrichment", {})
    defaults = {
        "cvss": None,
        "poc": None,
        "affected_assets": None,
        "related_papers": [],
        "attack_chain": [],
        "remediation": None,
    }
    for key, default in defaults.items():
        enrichment.setdefault(key, default)
    return item


def retag_item(item: Dict) -> Dict:
    text = " ".join(
        [item.get("title") or "", item.get("description") or "", " ".join(item.get("tags") or [])]
    )
    tags = ai_filter.build_tags(text)
    if tags:
        item["tags"] = tags
    category = ai_filter.tag_category(text)
    item["ai_relevant"] = category is not None and category != "F"
    return item


def _strip_mongo_id(item: Dict) -> Dict:
    cleaned = dict(item)
    cleaned.pop("_id", None)
    return cleaned


def _jsonl_lines(items: List[Dict]) -> str:
    lines = [json.dumps(_strip_mongo_id(item), ensure_ascii=False) for item in items]
    return "\n".join(lines) + ("\n" if lines else "")


def export_outputs(enriched: List[Dict], structured: List[Dict]) -> Dict:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    structured_path = OUTPUT_DIR / "structured_intel.jsonl"
    enriched_path = OUTPUT_DIR / "enriched_intel.jsonl"
    remediation_path = OUTPUT_DIR / "remediation_kb.json"

    structured_path.write_text(_jsonl_lines(structured), encoding="utf-8")
    enriched_path.write_text(_jsonl_lines(enriched), encoding="utf-8")

    knowledge_base: Dict = {}
    for item in enriched:
        remediation = (item.get("enrichment") or {}).get("remediation")
        if remediation:
            knowledge_base[str(item.get("intel_id"))] = remediation
    remediation_path.write_text(
        json.dumps(knowledge_base, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    return {
        "structured_file": str(structured_path),
        "enriched_file": str(enriched_path),
        "remediation_kb": str(remediation_path),
        "remediation_count": len(knowledge_base),
    }


def run_enrichment_pipeline(limit: Optional[int] = None, force: bool = False) -> Dict:
    cursor = structured_collection().find({}).sort("publish_time", -1)
    if limit:
        cursor = cursor.limit(limit)
    structured = list(cursor)

    fingerprints = [item.get("fingerprint") for item in structured if item.get("fingerprint")]
    already_enriched: Dict = {}
    if not force:
        already_enriched = {
            doc["fingerprint"]: doc
            for doc in enriched_collection().find({"fingerprint": {"$in": fingerprints}})
        }

    enriched: List[Dict] = []
    coverage: Dict[str, int] = {enrich.__name__: 0 for enrich in ENRICHERS}
    skipped = 0
    for item in structured:
        fingerprint = item.get("fingerprint")
        if not force and fingerprint in already_enriched:
            existing = already_enriched[fingerprint]
            enriched.append(_strip_mongo_id(existing))
            for enrich in ENRICHERS:
                if _dimension_filled(
                    (existing.get("enrichment") or {}), DIMENSION_KEYS[enrich.__name__]
                ):
                    coverage[enrich.__name__] += 1
            skipped += 1
            continue

        result = normalize_enrichment(enrich_item(retag_item(dict(item))))
        enriched.append(result)
        for enrich in ENRICHERS:
            if _dimension_filled(result.get("enrichment") or {}, DIMENSION_KEYS[enrich.__name__]):
                coverage[enrich.__name__] += 1
        enriched_collection().update_one(
            {"fingerprint": fingerprint},
            {"$set": _strip_mongo_id(result)},
            upsert=True,
        )

    files = export_outputs(enriched, structured)
    return {
        "processed": len(structured),
        "newly_enriched": len(structured) - skipped,
        "skipped": skipped,
        "coverage": coverage,
        **files,
    }


if __name__ == "__main__":
    setup_logging()
    force = "--force" in __import__("sys").argv
    summary = run_enrichment_pipeline(force=force)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
