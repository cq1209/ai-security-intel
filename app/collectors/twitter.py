"""X/Twitter security research alert channel."""
from __future__ import annotations

from typing import Dict, List, Tuple

from app.collectors.rss import collect_feed


TWITTER_FEEDS: List[Tuple[str, str]] = [
    ("twitter:openai", "https://nitter.net/OpenAI/rss"),
    ("twitter:deepmind", "https://nitter.net/GoogleDeepMind/rss"),
]


def collect_twitter_alerts() -> Dict:
    total_raw = 0
    total_ai = 0
    for source, url in TWITTER_FEEDS:
        result = collect_feed(source, url, require_security=False)
        total_raw += result["raw"]
        total_ai += result["ai_relevant"]
    return {"raw": total_raw, "ai_relevant": total_ai}
