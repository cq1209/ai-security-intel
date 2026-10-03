"""Diagnostic helper: test FOFA API queries with the configured key."""
from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")


def _query(query: str, size: int = 3) -> None:
    params = {
        "email": os.getenv("FOFA_EMAIL", ""),
        "key": os.getenv("FOFA_API_KEY", ""),
        "qbase64": base64.b64encode(query.encode("utf-8")).decode("ascii"),
        "size": size,
        "fields": "ip,country,title",
    }
    try:
        response = httpx.get("https://fofa.info/api/v1/search/all", params=params, timeout=20)
        payload = response.json()
        print(
            f"{query} -> HTTP {response.status_code} | error={payload.get('error')} | "
            f"errmsg={payload.get('errmsg') or ''} | results={len(payload.get('results') or [])}"
        )
    except Exception as exc:
        print(f"{query} -> ERROR {type(exc).__name__} {str(exc)[:100]}")


def main() -> None:
    _query('port="11434"')
    _query('app="Ollama"')
    _query('title="Ollama"')
    _query('body="ollama"')
    _query('app="vLLM"')
    _query('port="8501"')


if __name__ == "__main__":
    main()
