"""Shared storage helpers for raw and structured intelligence."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict

from app.db import raw_collection, structured_collection


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def save_raw(source_id: str, data: Dict) -> None:
    raw_collection().update_one(
        {"_id": source_id},
        {"$set": {"data": data, "ingested_at": _utc_now()}},
        upsert=True,
    )


def save_structured(item: Dict) -> None:
    structured_collection().update_one(
        {"fingerprint": item["fingerprint"]},
        {"$set": item},
        upsert=True,
    )
