"""CLI entry point for fetching CVEs from NVD.

Usage:
    python -m cti_center.fetch
"""

from cti_center.database import Base, SessionLocal, engine, upsert_cves
from cti_center.nvd import fetch_cves


def main():
    Base.metadata.create_all(bind=engine)

    print("Fetching CVEs from NVD...")
    cves = fetch_cves()
    print(f"Fetched {len(cves)} CVEs from NVD API.")

    db = SessionLocal()
    try:
        new_count, skipped = upsert_cves(db, cves)
        print(f"  {new_count} new, {skipped} already existed.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
