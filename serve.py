"""Run the long-lived intelligence service: scheduler + HTTP API together."""
from __future__ import annotations

import logging
import os

import uvicorn

from app.scheduler import start_scheduler
from app.webhook.server import app


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[logging.FileHandler("service.log", encoding="utf-8")],
    )
    root = logging.getLogger()
    scheduler = None
    try:
        scheduler = start_scheduler()
        host = os.getenv("API_HOST", "0.0.0.0")
        port = int(os.getenv("API_PORT", "8000"))
        root.info("Serving AI security intel API on http://%s:%s", host, port)
        uvicorn.run(app, host=host, port=port, log_config=None)
    except Exception:
        root.exception("Service crashed")
    finally:
        if scheduler is not None:
            scheduler.shutdown()


if __name__ == "__main__":
    main()
