"""Diagnostic helper: report which paper-search APIs are reachable."""
from __future__ import annotations

import httpx

SOURCES = [
    ("arxiv", "https://export.arxiv.org/api/query?search_query=all:test&max_results=1"),
    ("semantic_scholar", "https://api.semanticscholar.org/graph/v1/paper/search?query=test&limit=1"),
    ("openalex", "https://api.openalex.org/works?search=test&per-page=1"),
    ("crossref", "https://api.crossref.org/works?query=test&rows=1"),
]


def main() -> None:
    for name, url in SOURCES:
        try:
            response = httpx.get(url, timeout=15, headers={"User-Agent": "ai-security-intel/0.1"})
            print(f"{name} -> {response.status_code}")
        except Exception as exc:
            print(f"{name} -> ERROR {type(exc).__name__}")


if __name__ == "__main__":
    main()
