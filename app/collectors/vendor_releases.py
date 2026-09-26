"""AI vendor release announcements collector."""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import httpx

from app.cleaners import filtering as ai_filter
from app.cleaners.dedup import make_fingerprint
from app.cleaners.pipeline import save_raw, save_structured
from app.config import GITHUB_TOKEN

logger = logging.getLogger(__name__)

REPOS: List[Tuple[str, str]] = [
    ("ollama", "ollama"),
    ("vllm-project", "vllm"),
    ("tensorflow", "tensorflow"),
    ("pytorch", "pytorch"),
    ("huggingface", "transformers"),
    ("langchain-ai", "langchain"),
]

RELEASES_API = "https://api.github.com/repos/{owner}/{repo}/releases"


def _headers() -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "ai-security-intel/0.1",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return headers


def fetch_releases(owner: str, repo: str, per_page: int = 5) -> List[Dict]:
    url = RELEASES_API.format(owner=owner, repo=repo)
    with httpx.Client(timeout=20) as client:
        response = client.get(
            url,
            params={"per_page": min(max(per_page, 1), 100)},
            headers=_headers(),
        )
        response.raise_for_status()
        return response.json()


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def to_intel_item(release: Dict, source: str) -> Dict:
    tag = release.get("tag_name") or ""
    title = release.get("name") or tag
    body = release.get("body") or ""
    published = _parse_time(release.get("published_at")) or _parse_time(release.get("created_at"))
    relevant = ai_filter.matches_ai_keywords(f"{title} {body}")
    relevant = relevant and ai_filter.is_security_related(f"{title} {body}")

    return {
        "intel_id": f"{source}:{tag}",
        "source": source,
        "title": title,
        "description": body,
        "publish_time": (published or datetime.now()).isoformat(),
        "raw_url": release.get("html_url"),
        "ai_relevant": relevant,
        "tags": [source],
        "fingerprint": make_fingerprint(
            raw_url=release.get("html_url"),
            title=title,
            publish_date=(published or datetime.now()).isoformat(),
        ),
        "last_check_time": datetime.now().isoformat(),
        "enrichment": {},
    }


def collect_vendor_releases(per_page: int = 5) -> Dict:
    total_raw = 0
    total_ai = 0

    for owner, repo in REPOS:
        source = f"vendor:{repo}"
        try:
            releases = fetch_releases(owner, repo, per_page=per_page)
        except Exception as exc:
            logger.warning("Failed to fetch releases owner=%s repo=%s: %s", owner, repo, exc)
            continue

        for release in releases:
            tag = release.get("tag_name")
            release_id = release.get("id")
            if not tag or release_id is None:
                continue
            save_raw(f"release:{source}:{release_id}", release)
            total_raw += 1

            text = f"{release.get('name') or ''} {release.get('body') or ''}"
            if ai_filter.matches_ai_keywords(text) and ai_filter.is_security_related(text):
                save_structured(to_intel_item(release, source))
                total_ai += 1

    return {"raw": total_raw, "ai_relevant": total_ai}
