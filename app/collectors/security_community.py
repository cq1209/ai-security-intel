"""Security community disclosures collector."""
from __future__ import annotations

from typing import Dict, List, Tuple

from app.collectors.rss import collect_feed


COMMUNITY_FEEDS: List[Tuple[str, str]] = [
    ("community:hackerone", "https://hackerone.com/hacktivity.rss"),
    ("community:bugcrowd", "https://bugcrowd.com/crowdstream.rss"),
]


def collect_security_community() -> Dict:
    total_raw = 0
    total_ai = 0
    for source, url in COMMUNITY_FEEDS:
        result = collect_feed(source, url, require_security=False)
        total_raw += result["raw"]
        total_ai += result["ai_relevant"]
    return {"raw": total_raw, "ai_relevant": total_ai}
