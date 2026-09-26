"""Fingerprint generation for intelligence deduplication."""
from __future__ import annotations

import hashlib
from typing import Optional


def make_fingerprint(
    intel_id: Optional[str] = None,
    raw_url: Optional[str] = None,
    title: Optional[str] = None,
    publish_date: Optional[str] = None,
) -> str:
    if intel_id:
        key = f"cve:{intel_id}"
    elif raw_url:
        key = f"url:{raw_url}"
    else:
        key = f"title:{title or ''}|date:{publish_date or ''}"
    return hashlib.md5(key.encode("utf-8")).hexdigest()
