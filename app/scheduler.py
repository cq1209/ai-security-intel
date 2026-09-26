"""Background scheduler entry point."""
from __future__ import annotations

from apscheduler.schedulers.background import BackgroundScheduler

from app.collectors.arxiv import collect_arxiv
from app.collectors.cisa_kev import collect_kev
from app.collectors.domestic_vendors import collect_domestic_vendors
from app.collectors.ghsa import collect_ghsa
from app.collectors.nvd import collect_nvd_recent
from app.collectors.security_community import collect_security_community
from app.collectors.twitter import collect_twitter_alerts
from app.collectors.vendor_releases import collect_vendor_releases
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
    scheduler.add_job(
        collect_ghsa,
        trigger="interval",
        minutes=30,
        id="ghsa",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
    )
    scheduler.add_job(
        collect_kev,
        trigger="cron",
        hour=2,
        minute=0,
        id="cisa_kev",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
    )
    scheduler.add_job(
        collect_vendor_releases,
        trigger="interval",
        hours=2,
        id="vendor_releases",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
    )
    scheduler.add_job(
        collect_security_community,
        trigger="interval",
        hours=2,
        id="security_community",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
    )
    scheduler.add_job(
        collect_arxiv,
        trigger="cron",
        hour=1,
        minute=0,
        id="arxiv",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
    )
    scheduler.add_job(
        collect_domestic_vendors,
        trigger="cron",
        hour="0,12",
        minute=0,
        id="domestic_vendors",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
    )
    scheduler.add_job(
        collect_twitter_alerts,
        trigger="interval",
        minutes=10,
        id="twitter_alerts",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
    )
    return scheduler


def start_scheduler() -> BackgroundScheduler:
    scheduler = create_scheduler()
    scheduler.start()
    return scheduler
