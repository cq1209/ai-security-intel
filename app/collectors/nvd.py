"""NVD CVE collector prototype."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import httpx

from app.cleaners import filtering as ai_filter
from app.cleaners.dedup import make_fingerprint
from app.config import NVD_API_KEY
from app.db import raw_collection, structured_collection
from app.state import get_last_check_time, set_last_check_time

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"

NVD_KEYWORDS = (
    "tensorflow",
    "pytorch",
    "ollama",
    "vllm",
    "huggingface",
    "transformers",
    "langchain",
    "onnxruntime",
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _nvd_time(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def _headers() -> Dict[str, str]:
    headers = {"User-Agent": "ai-security-intel/0.1"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers


def fetch_cves(
    keyword: Optional[str] = None,
    days_back: int = 7,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    limit: int = 100,
) -> List[Dict]:
    end = end or _utc_now()
    start = start or (end - timedelta(days=days_back))
    params = {
        "resultsPerPage": min(max(limit, 1), 2000),
        "pubStartDate": _nvd_time(start),
        "pubEndDate": _nvd_time(end),
    }
    if keyword:
        params["keywordSearch"] = keyword

    with httpx.Client(timeout=30) as client:
        response = client.get(NVD_API_URL, params=params, headers=_headers())
        response.raise_for_status()
        payload = response.json()

    items = payload.get("vulnerabilities", [])
    cves = [item["cve"] for item in items if isinstance(item, dict) and item.get("cve")]
    return cves[:limit]


def _description(cve: Dict) -> str:
    for entry in cve.get("descriptions", []):
        if entry.get("lang") == "en":
            return entry.get("value", "")
    return ""


def _cvss(cve: Dict) -> Optional[Dict]:
    metrics = cve.get("metrics") or {}
    for version in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(version, []) or []:
            data = entry.get("cvssData") or {}
            if not data:
                continue
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or entry.get("baseSeverity")
            vector = data.get("vectorString")
            source = data.get("source") or entry.get("source")
            if score is not None or severity:
                return {
                    "score": score,
                    "vector": vector,
                    "severity": severity,
                    "source": source,
                    "confidence": "high",
                }
    return None


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def to_intel_item(cve: Dict) -> Dict:
    cve_id = cve.get("id", "")
    published = _parse_time(cve.get("published")) or _utc_now()
    relevant = ai_filter.is_ai_relevant(cve)
    return {
        "intel_id": cve_id,
        "source": "nvd",
        "title": cve_id,
        "description": _description(cve),
        "publish_time": published.isoformat(),
        "raw_url": NVD_DETAIL_URL.format(cve_id=cve_id),
        "ai_relevant": relevant,
        "tags": ["ai"] if relevant else [],
        "fingerprint": make_fingerprint(intel_id=cve_id, raw_url=NVD_DETAIL_URL.format(cve_id=cve_id)),
        "last_check_time": _utc_now().isoformat(),
        "enrichment": {"cvss": _cvss(cve)},
    }


def save_raw(cve: Dict) -> None:
    cve_id = cve.get("id")
    if not cve_id:
        return
    raw_collection().update_one(
        {"_id": cve_id},
        {"$set": {"data": cve, "ingested_at": _utc_now()}},
        upsert=True,
    )


def save_structured(item: Dict) -> None:
    structured_collection().update_one(
        {"fingerprint": item["fingerprint"]},
        {"$set": item},
        upsert=True,
    )


def collect_nvd_recent(days_back: int = 7, limit_per_keyword: int = 100) -> Dict:
    total_raw = 0
    total_ai = 0
    seen: set[str] = set()

    for keyword in NVD_KEYWORDS:
        source_key = f"nvd:{keyword}"
        start = get_last_check_time(source_key) or (_utc_now() - timedelta(days=days_back))
        end = _utc_now()
        try:
            cves = fetch_cves(
                keyword=keyword,
                start=start,
                end=end,
                limit=limit_per_keyword,
            )
        except Exception as exc:  # pragma: no cover - network failures are expected
            logger.warning("Failed to fetch NVD keyword=%s: %s", keyword, exc)
            continue
        set_last_check_time(source_key, end)

        for cve in cves:
            cve_id = cve.get("id")
            if not cve_id or cve_id in seen:
                continue
            seen.add(cve_id)
            save_raw(cve)
            total_raw += 1

            if ai_filter.is_ai_relevant(cve):
                save_structured(to_intel_item(cve))
                total_ai += 1

    return {"raw": total_raw, "ai_relevant": total_ai, "unique": len(seen)}
