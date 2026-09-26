"""Background scheduler entry point."""
from __future__ import annotations

from apscheduler.schedulers.background import BackgroundScheduler

from app.collectors.nvd import collect_nvd_recent
from app.logging_config import setup_logging


def create_scheduler() -> BackgroundScheduler:
    setup_logging()
    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(
        collect_nvd_recent,
        trigger="interval",
        minutes=30,
        id="nvd",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
    )
    return scheduler


def start_scheduler() -> BackgroundScheduler:
    scheduler = create_scheduler()
    scheduler.start()
    return scheduler
