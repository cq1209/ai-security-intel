"""Domestic security vendor announcement collector."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, List, Tuple
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from app.cleaners import filtering as ai_filter
from app.cleaners.dedup import make_fingerprint
from app.cleaners.pipeline import save_raw, save_structured

logger = logging.getLogger(__name__)

VENDOR_PAGES: List[Tuple[str, str]] = [
    ("vendor:qianxin", "https://ti.qianxin.com/"),
    ("vendor:nsfocus", "https://www.nsfocus.com.cn/"),
    ("vendor:venustech", "https://www.venustech.com.cn/"),
]


def _extract_links(html: str, base_url: str) -> List[Dict]:
    soup = BeautifulSoup(html, "html.parser")
    links: List[Dict] = []
    for anchor in soup.find_all("a", href=True):
        text = anchor.get_text(" ", strip=True)
        href = urljoin(base_url, anchor["href"])
        if text and href.startswith("http"):
            links.append({"title": text, "url": href})
    return links


def to_intel_item(link: Dict, source: str) -> Dict:
    title = link["title"]
    now = datetime.now(timezone.utc)
    return {
        "intel_id": link["url"],
        "source": source,
        "title": title,
        "description": "",
        "publish_time": now.isoformat(),
        "raw_url": link["url"],
        "ai_relevant": ai_filter.matches_ai_keywords(title),
        "tags": [source],
        "fingerprint": make_fingerprint(raw_url=link["url"], title=title, publish_date=now.isoformat()),
        "last_check_time": now.isoformat(),
        "enrichment": {},
    }


def collect_domestic_vendors() -> Dict:
    total_raw = 0
    total_ai = 0
    for source, url in VENDOR_PAGES:
        try:
            with httpx.Client(timeout=20, follow_redirects=True) as client:
                response = client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                response.raise_for_status()
        except Exception as exc:
            logger.warning("Failed to fetch domestic vendor source=%s url=%s: %s", source, url, exc)
            continue

        for link in _extract_links(response.text, url):
            save_raw(f"domestic:{source}:{link['url']}", link)
            total_raw += 1

            if ai_filter.matches_ai_keywords(link["title"]) or ai_filter.is_security_related(link["title"]):
                save_structured(to_intel_item(link, source))
                total_ai += 1

    return {"raw": total_raw, "ai_relevant": total_ai}
