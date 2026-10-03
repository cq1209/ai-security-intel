"""Fast collection: run primary intelligence sources concurrently."""
from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.collectors.cisa_kev import collect_kev
from app.collectors.ghsa import collect_ghsa
from app.collectors.nvd import collect_nvd_recent
from app.collectors.security_community import collect_security_community
from app.collectors.vendor_releases import collect_vendor_releases
from app.logging_config import setup_logging

COLLECTORS = {
    "nvd": collect_nvd_recent,
    "ghsa": collect_ghsa,
    "cisa_kev": collect_kev,
    "vendor_releases": collect_vendor_releases,
    "security_community": collect_security_community,
}


def main() -> None:
    setup_logging()
    results: dict = {}
    with ThreadPoolExecutor(max_workers=len(COLLECTORS)) as pool:
        futures = {pool.submit(fn): name for name, fn in COLLECTORS.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                results[name] = {"error": str(exc)}
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
