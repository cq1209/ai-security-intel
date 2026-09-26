"""GitHub Security Advisory collector."""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, List, Optional

import httpx

from app.cleaners import filtering as ai_filter
from app.cleaners.dedup import make_fingerprint
from app.cleaners.pipeline import save_raw, save_structured
from app.config import GITHUB_TOKEN

logger = logging.getLogger(__name__)

GHSA_API_URL = "https://api.github.com/advisories"


def _headers() -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "ai-security-intel/0.1",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return headers


def fetch_advisories(per_page: int = 100) -> List[Dict]:
    params = {
        "type": "reviewed",
        "ecosystem": "pip",
        "per_page": min(max(per_page, 1), 100),
        "sort": "updated",
        "direction": "desc",
    }
    with httpx.Client(timeout=30) as client:
        response = client.get(GHSA_API_URL, params=params, headers=_headers())
        response.raise_for_status()
        return response.json()


def _package_names(advisory: Dict) -> List[str]:
    names: List[str] = []
    for vuln in advisory.get("vulnerabilities", []) or []:
        package = vuln.get("package") or {}
        name = package.get("name")
        if name:
            names.append(name)
    return names


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def to_intel_item(advisory: Dict) -> Dict:
    ghsa_id = advisory.get("ghsa_id") or ""
    cve_id = advisory.get("cve_id")
    intel_id = cve_id or ghsa_id
    summary = advisory.get("summary") or ghsa_id
    description = advisory.get("description") or ""
    package_text = " ".join(_package_names(advisory))
    relevant = ai_filter.matches_ai_keywords(f"{summary} {description} {package_text}")

    cvss = advisory.get("cvss") or {}
    published = _parse_time(advisory.get("published_at")) or _parse_time(advisory.get("updated_at"))

    return {
        "intel_id": intel_id,
        "source": "ghsa",
        "title": summary,
        "description": description,
        "publish_time": (published or datetime.now()).isoformat(),
        "raw_url": advisory.get("html_url"),
        "ai_relevant": relevant,
        "tags": ["ai", "ghsa"] if relevant else ["ghsa"],
        "fingerprint": make_fingerprint(intel_id=intel_id, raw_url=advisory.get("html_url")),
        "last_check_time": datetime.now().isoformat(),
        "enrichment": {
            "cvss": {
                "score": cvss.get("score"),
                "vector": cvss.get("vector_string"),
                "severity": advisory.get("severity"),
                "source": "ghsa",
                "confidence": "high",
            }
        },
    }


def collect_ghsa(per_page: int = 100) -> Dict:
    advisories = fetch_advisories(per_page=per_page)
    total_raw = 0
    total_ai = 0

    for advisory in advisories:
        ghsa_id = advisory.get("ghsa_id")
        if not ghsa_id:
            continue
        save_raw(ghsa_id, advisory)
        total_raw += 1

        if ai_filter.matches_ai_keywords(
            f"{advisory.get('summary') or ''} {advisory.get('description') or ''} "
            f"{' '.join(_package_names(advisory))}"
        ):
            save_structured(to_intel_item(advisory))
            total_ai += 1

    return {"raw": total_raw, "ai_relevant": total_ai}
