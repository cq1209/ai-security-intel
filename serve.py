"""Run the long-lived intelligence service: scheduler + HTTP API together."""
from __future__ import annotations

import os

import uvicorn

from app.logging_config import setup_logging
from app.scheduler import start_scheduler
from app.webhook.server import app


def main() -> None:
    setup_logging()
    scheduler = start_scheduler()
    host = os.getenv("API_HOST", "0.0.0.0")
    port = int(os.getenv("API_PORT", "8000"))
    print(f"Serving AI security intel API on http://{host}:{port}")
    try:
        uvicorn.run(app, host=host, port=port)
    finally:
        scheduler.shutdown()


if __name__ == "__main__":
    main()
