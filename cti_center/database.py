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


def upsert_kev(db, kev_entries):
    """Enrich existing CVEs with KEV data, or create new records for unknown CVEs.

    Returns:
        Tuple of (updated_count, created_count).
    """
    from datetime import date as date_type

    from cti_center.models import CVE

    existing = {row.cve_id: row for row in db.query(CVE).all()}
    updated = 0
    created = 0

    for entry in kev_entries:
        cve_id = entry["cve_id"]
        if not cve_id:
            continue

        if cve_id in existing:
            cve = existing[cve_id]
            cve.kev_date_added = entry["date_added"]
            cve.kev_due_date = entry["due_date"]
            cve.kev_ransomware = entry["ransomware_use"]
            cve.kev_required_action = entry["required_action"]
            updated += 1
        else:
            vendor = entry["vendor_project"]
            product = entry["product"]
            affected = f"{vendor} {product}".strip() if vendor or product else "Unknown"
            description = entry["short_description"] or entry["vulnerability_name"] or "No description available."

            cve = CVE(
                cve_id=cve_id,
                description=description[:2000],
                cvss_score=0.0,
                severity="NONE",
                affected_product=affected[:200],
                date_published=entry["date_added"] or date_type.today(),
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                kev_date_added=entry["date_added"],
                kev_due_date=entry["due_date"],
                kev_ransomware=entry["ransomware_use"],
                kev_required_action=entry["required_action"],
            )
            db.add(cve)
            created += 1

    db.commit()
    return updated, created
