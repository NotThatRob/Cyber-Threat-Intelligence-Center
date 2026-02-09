from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = "sqlite:///cti_center.db"

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def upsert_cves(db, cves):
    """Insert new CVEs, skipping any that already exist by cve_id.

    Returns:
        Tuple of (new_count, skipped_count).
    """
    from cti_center.models import CVE

    existing_ids = {row[0] for row in db.query(CVE.cve_id).all()}
    new_cves = [c for c in cves if c.cve_id not in existing_ids]
    skipped = len(cves) - len(new_cves)

    if new_cves:
        db.add_all(new_cves)
        db.commit()

    return len(new_cves), skipped
