"""Remediation knowledge enrichment from NVD and local inference."""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional

import httpx

from app.cleaners import filtering as ai_filter
from app.config import NVD_API_KEY

logger = logging.getLogger(__name__)

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_TAG_PRIORITY = {
    "patch": 0,
    "vendor advisory": 1,
    "third party advisory": 2,
    "fix": 3,
}

_VERSION_TOKEN = r"([0-9][0-9A-Za-z._+-]*)"

_FIX_PATTERNS = (
    re.compile(r"fixed in(?: version)?\s+" + _VERSION_TOKEN, re.IGNORECASE),
    re.compile(r"patched in(?: version)?\s+" + _VERSION_TOKEN, re.IGNORECASE),
    re.compile(r"upgrade(?: to)?\s+" + _VERSION_TOKEN, re.IGNORECASE),
    re.compile(r"(?:has been|was)\s+fixed(?: in(?: version)?)?\s+" + _VERSION_TOKEN, re.IGNORECASE),
)


def _headers() -> Dict[str, str]:
    headers = {"User-Agent": "ai-security-intel/0.1"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers


def _description(cve: Dict) -> str:
    for entry in cve.get("descriptions", []) or []:
        if entry.get("lang") == "en":
            return entry.get("value", "")
    return ""


def _cpe_parts(cve: Dict):
    vendor: Optional[str] = None
    product: Optional[str] = None
    versions: List[str] = []
    for node in cve.get("configurations", []) or []:
        for match in node.get("nodes", []) or []:
            for cpe in match.get("cpeMatch", []) or []:
                criteria = cpe.get("criteria") or ""
                parts = criteria.split(":")
                if len(parts) < 6:
                    continue
                cpe_vendor, cpe_product, cpe_version = parts[3], parts[4], parts[5]
                if cpe_vendor not in ("*", "-") and vendor is None:
                    vendor = cpe_vendor
                if cpe_product not in ("*", "-") and product is None:
                    product = cpe_product
                if cpe_version not in ("*", "-") and cpe_version not in versions:
                    versions.append(cpe_version)
    return vendor, product, versions


def _extract_mitigation(description: str, product: Optional[str], patch_url: Optional[str]) -> List[str]:
    steps: List[str] = []
    for pattern in _FIX_PATTERNS:
        match = pattern.search(description or "")
        if match:
            target = product or "the affected component"
            steps.append(f"Upgrade {target} to version {match.group(1).rstrip('.')} or later.")
    if not steps and patch_url:
        target = product or "the affected component"
        steps.append(f"Upgrade {target} to a patched version. See {patch_url}")
    if not steps:
        steps.append("Apply the vendor's latest security update and review mitigations.")
    return list(dict.fromkeys(steps))


def fetch_nvd_remediation(cve_id: str) -> Optional[Dict]:
    with httpx.Client(timeout=30) as client:
        response = client.get(NVD_CVE_URL, params={"cveId": cve_id}, headers=_headers())
        response.raise_for_status()
    vulnerabilities = response.json().get("vulnerabilities", [])
    if not vulnerabilities:
        return None

    cve = vulnerabilities[0].get("cve", {})
    references = cve.get("references", []) or []
    best_url: Optional[str] = None
    best_priority = 99
    for reference in references:
        tags = [str(tag).lower() for tag in (reference.get("tags") or [])]
        url = reference.get("url")
        if not url:
            continue
        priority = min((_TAG_PRIORITY.get(tag, 99) for tag in tags), default=99)
        if priority < best_priority:
            best_priority = priority
            best_url = url
    patch_url = best_url or (references[0].get("url") if references else None)

    vendor, product, versions = _cpe_parts(cve)
    description = _description(cve)
    mitigation_steps = _extract_mitigation(description, product, patch_url)
    return {
        "cve_id": cve_id,
        "vendor": vendor,
        "affected_versions": versions,
        "patch_url": patch_url,
        "mitigation_steps": mitigation_steps,
        "workaround": None,
        "verified": bool(patch_url),
        "status": "official_patch" if patch_url else "temporary_mitigation",
    }


def _infer_component(text: str) -> Optional[str]:
    lowered = text.lower()
    for keyword in ai_filter.COMPONENT_KEYWORDS:
        if keyword in lowered:
            return keyword
    return None


def infer_remediation(item: Dict) -> Dict:
    intel_id = str(item.get("intel_id") or "")
    cve_id = intel_id if re.match(r"^CVE-\d{4}-\d+$", intel_id, re.IGNORECASE) else None
    component = _infer_component(f"{item.get('title') or ''} {item.get('description') or ''}")
    target = component or "the affected AI component"
    return {
        "cve_id": cve_id,
        "vendor": component,
        "affected_versions": [],
        "patch_url": None,
        "mitigation_steps": [f"Upgrade {target} to the latest patched version."],
        "workaround": None,
        "verified": False,
        "status": "temporary_mitigation",
    }


def enrich_item_remediation(item: Dict) -> Dict:
    enrichment = item.setdefault("enrichment", {})
    existing = enrichment.get("remediation")
    if existing and (existing.get("patch_url") or existing.get("mitigation_steps")):
        return item

    intel_id = str(item.get("intel_id") or "")
    cve_id = intel_id if re.match(r"^CVE-\d{4}-\d+$", intel_id, re.IGNORECASE) else None
    remediation = None
    if cve_id:
        try:
            remediation = fetch_nvd_remediation(cve_id)
        except Exception as exc:
            logger.info("NVD remediation lookup failed for %s: %s", cve_id, exc)

    enrichment["remediation"] = remediation or infer_remediation(item)
    return item
