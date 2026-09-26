"""CISA Known Exploited Vulnerabilities collector."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

import httpx

from app.cleaners import filtering as ai_filter
from app.cleaners.dedup import make_fingerprint
from app.cleaners.pipeline import save_raw, save_structured

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def fetch_kev() -> List[Dict]:
    with httpx.Client(timeout=30) as client:
        response = client.get(KEV_URL, headers={"User-Agent": "ai-security-intel/0.1"})
        response.raise_for_status()
        payload = response.json()
    return payload.get("vulnerabilities", [])


def _parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def to_intel_item(item: Dict) -> Dict:
    cve_id = item.get("cveID") or ""
    title = item.get("vulnerabilityName") or cve_id
    description = item.get("shortDescription") or ""
    vendor = item.get("vendorProject") or ""
    product = item.get("product") or ""
    relevant = ai_filter.matches_ai_keywords(f"{vendor} {product} {title} {description}")

    return {
        "intel_id": cve_id,
        "source": "cisa_kev",
        "title": title,
        "description": description,
        "publish_time": (_parse_date(item.get("dateAdded")) or _utc_now()).isoformat(),
        "raw_url": KEV_CATALOG_URL,
        "ai_relevant": relevant,
        "tags": ["ai", "kev"] if relevant else ["kev"],
        "fingerprint": make_fingerprint(intel_id=cve_id, raw_url=KEV_CATALOG_URL),
        "last_check_time": _utc_now().isoformat(),
        "enrichment": {
            "remediation": {
                "cve_id": cve_id,
                "vendor": vendor,
                "affected_versions": [product],
                "mitigation_steps": [item.get("requiredAction", "")] if item.get("requiredAction") else [],
                "verified": True,
                "status": "official_patch",
            }
        },
    }


def collect_kev() -> Dict:
    items = fetch_kev()
    total_raw = 0
    total_ai = 0

    for item in items:
        cve_id = item.get("cveID")
        if not cve_id:
            continue
        save_raw(cve_id, item)
        total_raw += 1

        if ai_filter.matches_ai_keywords(
            f"{item.get('vendorProject') or ''} {item.get('product') or ''} "
            f"{item.get('vulnerabilityName') or ''} {item.get('shortDescription') or ''}"
        ):
            save_structured(to_intel_item(item))
            total_ai += 1

    return {"raw": total_raw, "ai_relevant": total_ai}
