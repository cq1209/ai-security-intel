"""Unified six-dimension enrichment pipeline and output exporters."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

from app.config import BASE_DIR
from app.db import enriched_collection, structured_collection
from app.enrichment.assets import enrich_item_assets
from app.enrichment.attack import enrich_item_attack
from app.enrichment.cvss import enrich_item_cvss
from app.enrichment.papers import enrich_item_papers
from app.enrichment.poc import enrich_item_poc
from app.enrichment.remediation import enrich_item_remediation

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


def run_enrichment_pipeline(limit: Optional[int] = None) -> Dict:
    cursor = structured_collection().find({"ai_relevant": True}).sort("publish_time", -1)
    if limit:
        cursor = cursor.limit(limit)
    structured = list(cursor)

    enriched: List[Dict] = []
    for item in structured:
        result = enrich_item(dict(item))
        enriched.append(result)
        enriched_collection().update_one(
            {"fingerprint": item.get("fingerprint")},
            {"$set": _strip_mongo_id(result)},
            upsert=True,
        )

    files = export_outputs(enriched, structured)
    return {"processed": len(enriched), **files}


if __name__ == "__main__":
    summary = run_enrichment_pipeline()
    print(json.dumps(summary, ensure_ascii=False, indent=2))
