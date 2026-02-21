"""Background scheduler for periodic data fetching.

Runs each data source on a conservative schedule with jitter to avoid
predictable request patterns.  Uses HTTP conditional requests (ETag /
If-Modified-Since) where supported so unchanged data is never re-downloaded.

Schedule:
    NVD         — every 4 hours  (±10 min jitter)
    CISA KEV    — every 12 hours (±30 min jitter)
    GHSA        — every 6 hours  (±15 min jitter)
    RSS News    — every 2 hours  (±10 min jitter)
    MITRE       — after each CVE-source cycle, not independently scheduled

State is persisted to ``data/fetch_state.json`` so conditional request
headers survive server restarts.
"""

import json
import logging
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler

from cti_center.database import SessionLocal, upsert_cves, upsert_kev, upsert_news

logger = logging.getLogger(__name__)

_STATE_FILE = Path(__file__).resolve().parent.parent / "data" / "fetch_state.json"

scheduler = BackgroundScheduler(daemon=True)


# ---------------------------------------------------------------------------
# Fetch state persistence (ETag / Last-Modified per source)
# ---------------------------------------------------------------------------

def _load_state() -> dict:
    if _STATE_FILE.exists():
        try:
            return json.loads(_STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            logger.warning("Corrupt fetch state file, starting fresh.")
    return {}


def _save_state(state: dict) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(state, indent=2))


# ---------------------------------------------------------------------------
# Individual source fetch jobs
# ---------------------------------------------------------------------------

def _job_nvd() -> None:
    """Fetch recent CVEs from the NVD API."""
    try:
        from cti_center.nvd import fetch_cves

        cves = fetch_cves()
        db = SessionLocal()
        try:
            new_count, skipped = upsert_cves(db, cves)
            logger.info("NVD scheduled fetch: %d new, %d already existed.", new_count, skipped)
        finally:
            db.close()
    except Exception:
        logger.error("NVD scheduled fetch failed.", exc_info=True)


def _job_kev() -> None:
    """Fetch the CISA KEV catalog with conditional request support."""
    try:
        from cti_center.kev import fetch_kev

        state = _load_state()
        kev_state = state.get("kev", {})

        result = fetch_kev(
            etag=kev_state.get("etag"),
            last_modified=kev_state.get("last_modified"),
        )

        if result is None:
            # 304 Not Modified — nothing to do.
            return

        kev_entries, resp_headers = result
        db = SessionLocal()
        try:
            updated, created = upsert_kev(db, kev_entries)
            logger.info("KEV scheduled fetch: %d enriched, %d new.", updated, created)
        finally:
            db.close()

        # Persist caching headers for next request.
        state["kev"] = resp_headers
        _save_state(state)
    except Exception:
        logger.error("KEV scheduled fetch failed.", exc_info=True)


def _job_ghsa() -> None:
    """Fetch recent advisories from the GitHub Advisory Database."""
    try:
        from cti_center.ghsa import fetch_ghsa

        advisories = fetch_ghsa()
        db = SessionLocal()
        try:
            new_count, skipped = upsert_cves(db, advisories)
            logger.info("GHSA scheduled fetch: %d new, %d already existed.", new_count, skipped)
        finally:
            db.close()
    except Exception:
        logger.error("GHSA scheduled fetch failed.", exc_info=True)


def _job_mitre() -> None:
    """Enrich CVEs missing CVSS scores via MITRE CVE Services."""
    try:
        from cti_center.mitre import enrich_cves

        db = SessionLocal()
        try:
            enriched, failed = enrich_cves(db)
            logger.info("MITRE enrichment: %d enriched, %d failed.", enriched, failed)
        finally:
            db.close()
    except Exception:
        logger.error("MITRE enrichment failed.", exc_info=True)


def _job_news() -> None:
    """Fetch security news from RSS feeds with per-feed conditional requests."""
    try:
        from cti_center.news import fetch_news

        state = _load_state()
        feed_state = state.get("news_feeds", {})

        articles, updated_feed_state = fetch_news(feed_state=feed_state)

        db = SessionLocal()
        try:
            new_count, skipped, new_links = upsert_news(db, articles)
            logger.info(
                "News scheduled fetch: %d new, %d already existed, %d new CVE links.",
                new_count, skipped, new_links,
            )
        finally:
            db.close()

        state["news_feeds"] = updated_feed_state
        _save_state(state)
    except Exception:
        logger.error("News scheduled fetch failed.", exc_info=True)


def _job_full_cycle() -> None:
    """Run a complete fetch cycle: all CVE sources, then MITRE enrichment."""
    logger.info("Starting scheduled fetch cycle.")
    _job_nvd()
    _job_kev()
    _job_ghsa()
    _job_mitre()
    _job_news()
    logger.info("Scheduled fetch cycle complete.")


# ---------------------------------------------------------------------------
# Scheduler lifecycle
# ---------------------------------------------------------------------------

def start_scheduler() -> None:
    """Configure and start the background scheduler.

    Runs an initial full fetch immediately (in a background thread),
    then schedules each source at its own interval with jitter.
    """
    # Individual source schedules with jitter.
    scheduler.add_job(
        _job_nvd,
        "interval",
        hours=4,
        jitter=600,          # ±10 minutes
        id="nvd",
        name="NVD fetch",
    )
    scheduler.add_job(
        _job_kev,
        "interval",
        hours=12,
        jitter=1800,         # ±30 minutes
        id="kev",
        name="KEV fetch",
    )
    scheduler.add_job(
        _job_ghsa,
        "interval",
        hours=6,
        jitter=900,          # ±15 minutes
        id="ghsa",
        name="GHSA fetch",
    )
    scheduler.add_job(
        _job_news,
        "interval",
        hours=2,
        jitter=600,          # ±10 minutes
        id="news",
        name="News fetch",
    )
    # MITRE enrichment runs every 6 hours (after CVE sources may have added
    # new records with missing CVSS).
    scheduler.add_job(
        _job_mitre,
        "interval",
        hours=6,
        jitter=900,
        id="mitre",
        name="MITRE enrichment",
    )

    scheduler.start()
    logger.info("Scheduler started — fetches will run on schedule with jitter.")

    # Run an initial full cycle immediately in a background thread so the
    # server can start accepting requests right away.
    scheduler.add_job(
        _job_full_cycle,
        id="initial_fetch",
        name="Initial full fetch",
    )


def stop_scheduler() -> None:
    """Shut down the scheduler gracefully."""
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped.")
