"""CVSS score completion for structured intelligence."""
from __future__ import annotations

import logging
from typing import Dict, Optional

import httpx

from app.config import GITHUB_TOKEN, NVD_API_KEY

logger = logging.getLogger(__name__)

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_URL = "https://api.github.com/advisories"


def _nvd_headers() -> Dict[str, str]:
    headers = {"User-Agent": "ai-security-intel/0.1"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers


def _ghsa_headers() -> Dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "ai-security-intel/0.1"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return headers


def extract_cvss(cve: Dict) -> Optional[Dict]:
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


def fetch_nvd_cvss(cve_id: str) -> Optional[Dict]:
    with httpx.Client(timeout=30) as client:
        response = client.get(
            NVD_CVE_URL,
            params={"cveId": cve_id},
            headers=_nvd_headers(),
        )
        response.raise_for_status()
    vulnerabilities = response.json().get("vulnerabilities", [])
    if not vulnerabilities:
        return None
    return extract_cvss(vulnerabilities[0].get("cve", {}))


def fetch_ghsa_cvss(cve_id: str) -> Optional[Dict]:
    with httpx.Client(timeout=30) as client:
        response = client.get(
            GHSA_URL,
            params={"cve_id": cve_id},
            headers=_ghsa_headers(),
        )
        response.raise_for_status()
    advisories = response.json()
    if not advisories:
        return None
    advisory = advisories[0]
    cvss = advisory.get("cvss") or {}
    if not cvss and not advisory.get("severity"):
        return None
    return {
        "score": cvss.get("score"),
        "vector": cvss.get("vector_string"),
        "severity": advisory.get("severity"),
        "source": "ghsa",
        "confidence": "high",
    }


def infer_cvss(text: str) -> Dict:
    lowered = text.lower()
    if any(word in lowered for word in ("critical", "remote code execution", "rce", "authentication bypass")):
        score, severity = 9.0, "CRITICAL"
    elif any(word in lowered for word in ("high", "privilege escalation", "code execution")):
        score, severity = 7.5, "HIGH"
    elif any(word in lowered for word in ("medium", "information disclosure")):
        score, severity = 5.0, "MEDIUM"
    else:
        score, severity = 3.0, "LOW"
    return {
        "score": score,
        "vector": None,
        "severity": severity,
        "source": "inferred",
        "confidence": "low",
    }


def enrich_item_cvss(item: Dict) -> Dict:
    enrichment = item.setdefault("enrichment", {})
    if enrichment.get("cvss") and enrichment["cvss"].get("score") is not None:
        return item

    cve_id = item.get("intel_id") if str(item.get("intel_id", "")).upper().startswith("CVE-") else None
    cvss = None
    if cve_id:
        try:
            cvss = fetch_nvd_cvss(cve_id)
        except Exception as exc:
            logger.info("NVD CVSS lookup failed for %s: %s", cve_id, exc)
        if not cvss:
            try:
                cvss = fetch_ghsa_cvss(cve_id)
            except Exception as exc:
                logger.info("GHSA CVSS lookup failed for %s: %s", cve_id, exc)

    if not cvss:
        cvss = infer_cvss(f"{item.get('title') or ''} {item.get('description') or ''}")

    enrichment["cvss"] = cvss
    return item
