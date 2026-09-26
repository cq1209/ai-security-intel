"""arXiv paper collector."""
from __future__ import annotations

import calendar
import logging
from datetime import datetime, timezone
from typing import Dict

import feedparser
import httpx

from app.cleaners import filtering as ai_filter
from app.cleaners.dedup import make_fingerprint
from app.cleaners.pipeline import save_raw, save_structured

logger = logging.getLogger(__name__)

ARXIV_API_URL = "https://export.arxiv.org/api/query"


def _parse_time(parsed) -> datetime:
    try:
        return datetime.fromtimestamp(calendar.timegm(parsed), tz=timezone.utc)
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)


def fetch_papers(max_results: int = 50) -> list:
    params = {
        "search_query": "cat:cs.CR OR cat:cs.AI",
        "start": 0,
        "max_results": min(max(max_results, 1), 100),
        "sortBy": "submittedDate",
        "sortOrder": "descending",
    }
    with httpx.Client(timeout=30) as client:
        response = client.get(
            ARXIV_API_URL,
            params=params,
            headers={"User-Agent": "ai-security-intel/0.1", "Accept": "application/atom+xml"},
        )
        response.raise_for_status()
    return feedparser.parse(response.content).entries


def to_intel_item(entry: Dict) -> Dict:
    title = entry.get("title") or ""
    summary = entry.get("summary") or ""
    link = entry.get("id") or entry.get("link")
    published = _parse_time(entry.get("published_parsed"))

    return {
        "intel_id": link,
        "source": "arxiv",
        "title": title,
        "description": summary,
        "publish_time": published.isoformat(),
        "raw_url": link,
        "ai_relevant": ai_filter.matches_ai_keywords(f"{title} {summary}"),
        "tags": ["arxiv"],
        "fingerprint": make_fingerprint(
            raw_url=link,
            title=title,
            publish_date=published.isoformat(),
        ),
        "last_check_time": datetime.now(timezone.utc).isoformat(),
        "enrichment": {"related_papers": [{"title": title, "arxiv_id": link}]},
    }


def collect_arxiv(max_results: int = 50) -> Dict:
    try:
        entries = fetch_papers(max_results=max_results)
    except Exception as exc:
        logger.warning("Failed to fetch arXiv papers: %s", exc)
        return {"raw": 0, "ai_relevant": 0}

    total_raw = 0
    total_ai = 0
    for entry in entries:
        link = entry.get("id") or entry.get("link")
        if not link:
            continue
        save_raw(f"arxiv:{link}", {
            "title": entry.get("title", ""),
            "summary": entry.get("summary", ""),
            "link": link,
            "published": _parse_time(entry.get("published_parsed")).isoformat(),
        })
        total_raw += 1

        if ai_filter.matches_ai_keywords(f"{entry.get('title') or ''} {entry.get('summary') or ''}"):
            save_structured(to_intel_item(entry))
            total_ai += 1

    return {"raw": total_raw, "ai_relevant": total_ai}
