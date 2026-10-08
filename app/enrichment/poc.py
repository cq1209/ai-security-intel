"""POC collection from GitHub."""
from __future__ import annotations

import logging
from typing import Dict, List, Optional

import httpx

from app.config import GITHUB_TOKEN

logger = logging.getLogger(__name__)

GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
EXCLUDE_KEYWORDS = ("defense", "defender", "detector", "detect", "scanner", "scan")


def _headers() -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "ai-security-intel/0.1",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return headers


def search_pocs(cve_id: str, limit: int = 5) -> List[Dict]:
    query = f'"{cve_id}" exploit'
    with httpx.Client(timeout=30) as client:
        response = client.get(
            GITHUB_SEARCH_URL,
            params={"q": query, "per_page": min(max(limit, 1), 30)},
            headers=_headers(),
        )
        response.raise_for_status()
    items = response.json().get("items", [])

    pocs: List[Dict] = []
    for item in items:
        text = f"{item.get('name') or ''} {item.get('description') or ''}".lower()
        if any(keyword in text for keyword in EXCLUDE_KEYWORDS):
            continue
        pocs.append(
            {
                "repo_url": item.get("html_url"),
                "description": item.get("description"),
                "stars": item.get("stargazers_count"),
            }
        )
    return pocs[:limit]


def to_poc(repo: Dict) -> Dict:
    return {
        "repo_url": repo.get("repo_url"),
        "file_path": None,
        "code_snippet": None,
        "status": "unverified",
    }


def enrich_item_poc(item: Dict, limit: int = 3) -> Dict:
    enrichment = item.setdefault("enrichment", {})
    if "poc" in enrichment:
        return item

    cve_id = item.get("intel_id") if str(item.get("intel_id", "")).upper().startswith("CVE-") else None
    if not cve_id:
        return item

    try:
        repos = search_pocs(cve_id, limit=limit)
    except Exception as exc:
        logger.info("POC search failed for %s: %s", cve_id, exc)
        return item

    if repos:
        enrichment["poc"] = to_poc(repos[0])
    else:
        enrichment["poc"] = {
            "repo_url": None,
            "file_path": None,
            "code_snippet": None,
            "status": "unverified",
        }
    return item
