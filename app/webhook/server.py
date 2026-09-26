"""FastAPI server for receiving intelligence webhooks."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import FastAPI

from app.cleaners.dedup import make_fingerprint
from app.cleaners.pipeline import save_structured
from app.db import structured_collection
from app.schemas import IntelItem

app = FastAPI(title="AI Security Intel Webhook", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/intel")
def list_intel(limit: int = 100, offset: int = 0) -> list[dict]:
    docs = list(
        structured_collection()
        .find()
        .sort("last_check_time", -1)
        .skip(offset)
        .limit(min(max(limit, 1), 1000))
    )
    for doc in docs:
        doc.pop("_id", None)
    return docs


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
