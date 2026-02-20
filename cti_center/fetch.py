"""CLI entry point for fetching CVEs from NVD, GHSA, and news feeds.

Usage:
    python -m cti_center.fetch
"""

import logging

from cti_center.database import Base, SessionLocal, apply_migrations, engine, upsert_cves, upsert_news
from cti_center.logging_config import setup_logging
from cti_center.nvd import fetch_cves

logger = logging.getLogger(__name__)


def main():
    setup_logging()
    Base.metadata.create_all(bind=engine)
    _mig_db = SessionLocal()
    try:
        apply_migrations(_mig_db)
    finally:
        _mig_db.close()

    logger.info("Fetching CVEs from NVD...")
    cves = fetch_cves()
    logger.info("Fetched %d CVEs from NVD API.", len(cves))

    db = SessionLocal()
    try:
        new_count, skipped = upsert_cves(db, cves)
        logger.info("  %d new, %d already existed.", new_count, skipped)
    finally:
        db.close()

    logger.info("Fetching advisories from GitHub Advisory Database...")
    try:
        from cti_center.ghsa import fetch_ghsa

        advisories = fetch_ghsa()
        logger.info("Fetched %d advisories from GHSA.", len(advisories))

        db = SessionLocal()
        try:
            new_count, skipped = upsert_cves(db, advisories)
            logger.info("  %d new, %d already existed.", new_count, skipped)
        finally:
            db.close()
    except Exception:
        logger.error("GHSA fetch failed.", exc_info=True)

    logger.info("Fetching security news from RSS feeds...")
    try:
        from cti_center.news import fetch_news

        articles = fetch_news()
        logger.info("Fetched %d articles from RSS feeds.", len(articles))

        db = SessionLocal()
        try:
            new_count, skipped, new_links = upsert_news(db, articles)
            logger.info("  %d new, %d already existed, %d new CVE links.", new_count, skipped, new_links)
        finally:
            db.close()
    except Exception:
        logger.error("News fetch failed.", exc_info=True)


if __name__ == "__main__":
    main()
