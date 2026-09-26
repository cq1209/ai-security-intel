"""Per-source collection state for incremental runs."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from app.db import get_db


def get_last_check_time(source: str) -> Optional[datetime]:
    doc = get_db()["collection_state"].find_one({"source": source})
    if not doc or not doc.get("last_check_time"):
        return None
    try:
        return datetime.fromisoformat(doc["last_check_time"])
    except ValueError:
        return None


def set_last_check_time(source: str, value: Optional[datetime] = None) -> None:
    value = value or datetime.now(timezone.utc)
    get_db()["collection_state"].update_one(
        {"source": source},
        {"$set": {"last_check_time": value.isoformat()}},
        upsert=True,
    )
