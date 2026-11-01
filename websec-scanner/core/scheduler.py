"""
Built-in recurring scan scheduler, backed by APScheduler.

Schedules are persisted in SQLite (core/db.py) so they survive restarts of
the *data*, but the scheduler itself only runs while this app process is
running -- it's an in-process scheduler, not a system cron job. Fine for
"keep the app running on a machine/VM somewhere"; if you need scans to
happen even when the app isn't running, that's a job for system cron
calling a CLI scan command instead (not built here, flagged in the README
as a natural next step).
"""
from __future__ import annotations

import asyncio

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from core import db
from core.orchestrator import run_scan_with_subdomains

# Pinned to UTC explicitly: APScheduler otherwise tries to auto-detect the
# system timezone via tzlocal, which can throw on some platforms/locales
# (e.g. legacy tz names like "Asia/Calcutta" that aren't in the zoneinfo
# alias table). All scan timestamps elsewhere in this app are UTC too, so
# this keeps everything consistent regardless of the host's local tz.
_scheduler = AsyncIOScheduler(timezone="UTC")
_job_prefix = "websec_schedule_"


def start() -> None:
    if _scheduler.running:
        return
    _scheduler.start()
    _sync_jobs_from_db()


def shutdown() -> None:
    if _scheduler.running:
        _scheduler.shutdown(wait=False)


def _sync_jobs_from_db() -> None:
    """Load all enabled schedules from DB and register them as jobs."""
    for job in _scheduler.get_jobs():
        if job.id.startswith(_job_prefix):
            _scheduler.remove_job(job.id)

    for sched in db.list_schedules():
        if sched["enabled"]:
            _add_job(sched)


def _add_job(sched: dict) -> None:
    job_id = f"{_job_prefix}{sched['id']}"
    _scheduler.add_job(
        _run_scheduled_scan,
        "interval",
        minutes=sched["interval_minutes"],
        id=job_id,
        args=[sched["id"]],
        replace_existing=True,
        next_run_time=None,  # first run after one interval, not immediately
    )


async def _run_scheduled_scan(schedule_id: str) -> None:
    sched = db.get_schedule(schedule_id)
    if not sched or not sched["enabled"]:
        return
    results = await run_scan_with_subdomains(
        sched["target"],
        use_nuclei=bool(sched["use_nuclei"]),
        include_subdomains=bool(sched["include_subdomains"]),
        send_alerts=True,
    )
    if results:
        db.mark_schedule_run(schedule_id, results[0]["id"])


def create_schedule(target: str, interval_minutes: int, use_nuclei: bool,
                     include_subdomains: bool) -> dict:
    sched = db.add_schedule(target, interval_minutes, use_nuclei, include_subdomains)
    if _scheduler.running:
        _add_job(sched)
    return sched


def toggle_schedule(schedule_id: str, enabled: bool) -> None:
    db.set_schedule_enabled(schedule_id, enabled)
    job_id = f"{_job_prefix}{schedule_id}"
    if enabled:
        sched = db.get_schedule(schedule_id)
        if sched and _scheduler.running:
            _add_job(sched)
    else:
        if _scheduler.get_job(job_id):
            _scheduler.remove_job(job_id)


def remove_schedule(schedule_id: str) -> None:
    job_id = f"{_job_prefix}{schedule_id}"
    if _scheduler.get_job(job_id):
        _scheduler.remove_job(job_id)
    db.delete_schedule(schedule_id)


def run_now(schedule_id: str) -> None:
    """Trigger a scheduled scan immediately (in addition to its normal interval)."""
    asyncio.create_task(_run_scheduled_scan(schedule_id))
