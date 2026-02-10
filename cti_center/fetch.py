"""CLI entry point for fetching CVEs from NVD and GHSA.

Usage:
    python -m cti_center.fetch
"""

import logging

from cti_center.database import Base, SessionLocal, engine, upsert_cves
from cti_center.logging_config import setup_logging
from cti_center.nvd import fetch_cves

logger = logging.getLogger(__name__)


def main():
    setup_logging()
    Base.metadata.create_all(bind=engine)

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


if __name__ == "__main__":
    main()
