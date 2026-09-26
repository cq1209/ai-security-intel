"""Generic RSS/Atom collector."""
from __future__ import annotations

import calendar
import html
import logging
import re
from datetime import datetime, timezone
from typing import Dict

import feedparser
import httpx

from app.cleaners import filtering as ai_filter
from app.cleaners.dedup import make_fingerprint
from app.cleaners.pipeline import save_raw, save_structured

logger = logging.getLogger(__name__)


def _strip_html(value: str) -> str:
    text = re.sub(r"<[^>]+>", " ", value or "")
    return html.unescape(text).strip()


def _entry_time(entry: Dict) -> datetime:
    for key in ("published_parsed", "updated_parsed"):
        parsed = entry.get(key)
        if parsed:
            return datetime.fromtimestamp(calendar.timegm(parsed), tz=timezone.utc)
    return datetime.now(timezone.utc)


def to_intel_item(entry: Dict, source: str) -> Dict:
    title = entry.get("title") or ""
    summary = _strip_html(entry.get("summary") or entry.get("description") or "")
    link = entry.get("link") or entry.get("id") or title
    published = _entry_time(entry)

    return {
        "intel_id": link,
        "source": source,
        "title": title,
        "description": summary,
        "publish_time": published.isoformat(),
        "raw_url": link,
        "ai_relevant": ai_filter.matches_ai_keywords(f"{title} {summary}"),
        "tags": [source],
        "fingerprint": make_fingerprint(
            raw_url=link,
            title=title,
            publish_date=published.isoformat(),
        ),
        "last_check_time": datetime.now(timezone.utc).isoformat(),
        "enrichment": {},
    }


def collect_feed(source: str, url: str, require_security: bool = False) -> Dict:
    try:
        with httpx.Client(timeout=15, follow_redirects=True) as client:
            response = client.get(url)
            response.raise_for_status()
        feed = feedparser.parse(response.content)
    except Exception as exc:
        logger.warning("Failed to fetch feed source=%s url=%s: %s", source, url, exc)
        return {"raw": 0, "ai_relevant": 0}

    total_raw = 0
    total_ai = 0

    for entry in feed.entries:
        title = entry.get("title") or ""
        summary = _strip_html(entry.get("summary") or entry.get("description") or "")
        link = entry.get("link") or entry.get("id") or title
        if not link:
            continue

        doc = {
            "source": source,
            "title": title,
            "link": link,
            "summary": summary,
            "published": _entry_time(entry).isoformat(),
        }
        save_raw(f"feed:{source}:{link}", doc)
        total_raw += 1

        relevant = ai_filter.matches_ai_keywords(f"{title} {summary}")
        if require_security:
            relevant = relevant and ai_filter.is_security_related(f"{title} {summary}")

        if relevant:
            save_structured(to_intel_item(entry, source))
            total_ai += 1

    return {"raw": total_raw, "ai_relevant": total_ai}
