"""AI Security Intel service API.

Provides health checks, intelligence queries, statistics, and webhook ingestion
for other competition modules.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Query

from app.cleaners.dedup import make_fingerprint
from app.cleaners.pipeline import save_structured
from app.db import enriched_collection, raw_collection, structured_collection
from app.schemas import IntelItem

app = FastAPI(title="AI Security Intel Service", version="2.0.0")


def _strip_id(doc: dict) -> dict:
    doc.pop("_id", None)
    return doc


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "raw": raw_collection().count_documents({}),
        "structured": structured_collection().count_documents({}),
        "enriched": enriched_collection().count_documents({}),
    }


@app.get("/intel")
def list_intel(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    source: Optional[str] = None,
    ai_relevant: Optional[bool] = None,
    tag: Optional[str] = None,
) -> dict:
    query: dict = {}
    if source:
        query["source"] = source
    if ai_relevant is not None:
        query["ai_relevant"] = ai_relevant
    if tag:
        query["tags"] = tag

    collection = enriched_collection()
    total = collection.count_documents(query)
    docs = [document for document in collection.find(query).sort("publish_time", -1).skip(offset).limit(limit)]
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [_strip_id(document) for document in docs],
    }


@app.get("/intel/{intel_id}")
def get_intel(intel_id: str) -> dict:
    document = enriched_collection().find_one({"intel_id": intel_id})
    if not document:
        raise HTTPException(status_code=404, detail="intel not found")
    return _strip_id(document)


@app.get("/stats")
def stats() -> dict:
    items = list(enriched_collection().find({}))
    sources = Counter(str(item.get("source")) for item in items)
    categories = Counter()
    for item in items:
        tags = item.get("tags") or []
        if len(tags) > 1 and tags[1] in "ABCDEF":
            categories[tags[1]] += 1
        elif "F" in tags:
            categories["F"] += 1

    coverage = Counter()
    for item in items:
        enrichment = item.get("enrichment") or {}
        if enrichment.get("cvss") and (enrichment["cvss"] or {}).get("score") is not None:
            coverage["cvss"] += 1
        if enrichment.get("poc") and (enrichment["poc"] or {}).get("repo_url"):
            coverage["poc"] += 1
        if enrichment.get("affected_assets") and (enrichment["affected_assets"] or {}).get("exposed_count"):
            coverage["assets"] += 1
        if enrichment.get("related_papers"):
            coverage["papers"] += 1
        if enrichment.get("attack_chain"):
            coverage["attack"] += 1
        if enrichment.get("remediation"):
            coverage["remediation"] += 1

    return {
        "total": len(items),
        "ai_relevant": sum(1 for item in items if item.get("ai_relevant")),
        "sources": dict(sorted(sources.items())),
        "categories": dict(sorted(categories.items())),
        "coverage": dict(sorted(coverage.items())),
    }


@app.post("/webhook/intel")
def receive_intel(item: IntelItem) -> dict:
    data = item.model_dump()
    data["fingerprint"] = make_fingerprint(
        intel_id=data.get("intel_id"),
        raw_url=data.get("raw_url"),
        title=data.get("title"),
        publish_date=str(data.get("publish_time") or ""),
    )
    data["last_check_time"] = datetime.now(timezone.utc).isoformat()
    save_structured(data)
    return {"ok": True, "intel_id": data["intel_id"]}
