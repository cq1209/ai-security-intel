"""Run the intelligence collection scheduler."""
from __future__ import annotations

import time

from app.scheduler import start_scheduler


if __name__ == "__main__":
    scheduler = start_scheduler()
    print("Scheduler started. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
        print("Scheduler stopped.")
