"""Affected asset exposure estimation via FOFA/Shodan/Censys."""
from __future__ import annotations

import base64
import logging
import os
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List

import httpx

from app.config import CENSYS_PAT, SHODAN_API_KEY

logger = logging.getLogger(__name__)

FOFA_EMAIL = os.getenv("FOFA_EMAIL", "")
FOFA_API_KEY = os.getenv("FOFA_API_KEY", "")

SHODAN_SEARCH_URL = "https://api.shodan.io/shodan/host/search"
CENSYS_SEARCH_URL = "https://api.platform.censys.io/v3/global/search/query"
FOFA_SEARCH_URL = "https://fofa.info/api/v1/search/all"

AI_COMPONENT_QUERIES = (
    "product:ollama",
    "port:11434",
    "product:vllm",
    "product:tensorflow serving",
    "port:8501",
)


def search_shodan(query: str, limit: int = 5) -> Dict:
    with httpx.Client(timeout=30) as client:
        response = client.get(
            SHODAN_SEARCH_URL,
            params={"key": SHODAN_API_KEY, "query": query, "page": 1},
        )
        response.raise_for_status()
        payload = response.json()
    return payload


def search_censys(query: str, limit: int = 5) -> Dict:
    with httpx.Client(timeout=30) as client:
        response = client.post(
            CENSYS_SEARCH_URL,
            json={"query": query, "page_size": min(max(limit, 1), 100)},
            headers={
                "Authorization": f"Bearer {CENSYS_PAT}",
                "Accept": "application/json",
            },
        )
        response.raise_for_status()
    result = response.json().get("result", response.json())
    hits = result.get("hits", [])
    matches = []
    for hit in hits:
        location = hit.get("location") or {}
        matches.append(
            {
                "ip_str": hit.get("ip") or hit.get("ip_address"),
                "location": {"country_name": location.get("country") or location.get("country_name")},
            }
        )
    return {
        "total": result.get("total") or result.get("total_results") or len(hits),
        "matches": matches,
    }


def _to_fofa_query(query: str) -> str:
    if query.startswith("port:"):
        return f'port="{query[5:]}"'
    if query.startswith("product:"):
        return f'app="{query[8:]}"'
    return query


def search_fofa(query: str, limit: int = 5) -> Dict:
    fofa_query = _to_fofa_query(query)
    with httpx.Client(timeout=30) as client:
        response = client.get(
            FOFA_SEARCH_URL,
            params={
                "email": FOFA_EMAIL,
                "key": FOFA_API_KEY,
                "qbase64": base64.b64encode(fofa_query.encode("utf-8")).decode("ascii"),
                "size": 100,
                "page": 1,
                "fields": "ip,country,city",
            },
        )
        response.raise_for_status()
    payload = response.json()
    if payload.get("error"):
        raise RuntimeError(payload.get("errmsg") or "FOFA query failed")

    matches = []
    for row in payload.get("results") or []:
        if not isinstance(row, (list, tuple)) or len(row) < 2:
            continue
        matches.append(
            {
                "ip_str": row[0] or None,
                "location": {"country_name": row[1] or None},
            }
        )
    return {"total": len(matches), "matches": matches}


def aggregate_query(results: Dict, limit: int = 5) -> Dict:
    total = results.get("total", 0)
    matches = results.get("matches", [])
    countries = Counter(m.get("location", {}).get("country_name", "Unknown") for m in matches)
    ips = [m.get("ip_str") or m.get("ip") for m in matches if m.get("ip_str") or m.get("ip")]
    return {
        "exposed_count": total,
        "top_countries": [name for name, _ in countries.most_common(10)],
        "sample_ips": ips[:limit],
        "query_time": datetime.now(timezone.utc).isoformat(),
    }


def collect_asset_exposure(query: str = "product:ollama", limit: int = 5) -> Dict:
    if FOFA_EMAIL and FOFA_API_KEY:
        try:
            return aggregate_query(search_fofa(query, limit=limit), limit=limit)
        except Exception as exc:
            logger.info("FOFA query failed, trying Shodan: %s", exc)

    if SHODAN_API_KEY:
        try:
            return aggregate_query(search_shodan(query, limit=limit), limit=limit)
        except Exception as exc:
            logger.info("Shodan query failed, trying Censys: %s", exc)

    if CENSYS_PAT:
        try:
            return aggregate_query(search_censys(query, limit=limit), limit=limit)
        except Exception as exc:
            logger.info("Censys query failed: %s", exc)

    return {
        "exposed_count": 0,
        "top_countries": [],
        "sample_ips": [],
        "query_time": datetime.now(timezone.utc).isoformat(),
    }


def enrich_item_assets(item: Dict, limit: int = 5) -> Dict:
    enrichment = item.setdefault("enrichment", {})
    if enrichment.get("affected_assets") and enrichment["affected_assets"].get("query_time"):
        return item

    text = f"{item.get('title') or ''} {item.get('description') or ''}".lower()
    if "ollama" in text:
        query = "product:ollama"
    elif "vllm" in text:
        query = "product:vllm"
    elif "tensorflow" in text:
        query = "product:tensorflow serving"
    else:
        query = "port:11434"

    enrichment["affected_assets"] = collect_asset_exposure(query=query, limit=limit)
    return item
