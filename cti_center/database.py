import logging
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import DeclarativeBase, sessionmaker

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_URL = f"sqlite:///{_PROJECT_ROOT / 'cti_center.db'}"

engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False, "timeout": 30},
)
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


def apply_migrations(db):
    """Run lightweight schema migrations that are safe on both new and existing DBs."""
    db.execute(text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_cve_news_link "
        "ON cve_news_links(cve_id, article_id)"
    ))
    # Add cwe_ids column if it doesn't exist yet (SQLite-safe).
    existing_cols = {row[1] for row in db.execute(text("PRAGMA table_info(cves)")).fetchall()}
    if "cwe_ids" not in existing_cols:
        db.execute(text("ALTER TABLE cves ADD COLUMN cwe_ids TEXT"))
        logger.info("Migration: added cwe_ids column to cves table.")
    if "cvss_vector" not in existing_cols:
        db.execute(text("ALTER TABLE cves ADD COLUMN cvss_vector VARCHAR(200)"))
        logger.info("Migration: added cvss_vector column to cves table.")
    # Clamp any published dates that ended up in the future (e.g. event
    # pages whose RSS pubDate was the event date, not the publish date).
    db.execute(text(
        "UPDATE news_articles SET published_date = date('now') "
        "WHERE published_date > date('now')"
    ))

    # Backfill "Unknown" products using description-based extraction.
    from cti_center.models import CVE
    from cti_center.nvd import _product_from_description

    unknowns = db.query(CVE).filter(CVE.affected_product == "Unknown").all()
    backfilled = 0
    for cve in unknowns:
        product = _product_from_description(cve.description or "")
        if product != "Unknown":
            cve.affected_product = product[:200]
            backfilled += 1
    if backfilled:
        logger.info("Backfilled product for %d CVEs from descriptions.", backfilled)

    db.commit()
    logger.info("Migrations applied.")


def upsert_cves(db, cves):
    """Insert new CVEs or update stale existing records.

    Updates CVSS, description, product, and vector when incoming data
    is better than what we already have (e.g., NVD scored a CVE that
    was previously ingested at CVSS 0.0).

    Returns:
        Tuple of (new_count, updated_count).
    """
    from cti_center.models import CVE

    # Deduplicate incoming batch (keep first occurrence).
    seen: set[str] = set()
    unique_cves = []
    for c in cves:
        if c.cve_id not in seen:
            unique_cves.append(c)
            seen.add(c.cve_id)

    incoming_ids = [c.cve_id for c in unique_cves]
    existing = {
        row.cve_id: row
        for row in db.query(CVE).filter(CVE.cve_id.in_(incoming_ids)).all()
    } if incoming_ids else {}

    new_count = 0
    updated = 0
    for c in unique_cves:
        if c.cve_id in existing:
            row = existing[c.cve_id]
            changed = False
            # Update CVSS if incoming has a real score and it differs.
            if c.cvss_score > 0 and c.cvss_score != row.cvss_score:
                row.cvss_score = c.cvss_score
                row.severity = c.severity
                changed = True
            # Update description if incoming is meaningful and current is placeholder.
            if c.description and c.description != "No description available." and c.description != row.description:
                row.description = c.description
                changed = True
            # Update product if incoming is known and current is unknown.
            if c.affected_product not in ("Unknown", "") and row.affected_product in ("Unknown", ""):
                row.affected_product = c.affected_product
                changed = True
            # Update vector if incoming has one and current doesn't.
            if getattr(c, "cvss_vector", None) and not row.cvss_vector:
                row.cvss_vector = c.cvss_vector
                changed = True
            if changed:
                updated += 1
        else:
            db.add(c)
            new_count += 1

    db.commit()
    return new_count, updated


def upsert_kev(db, kev_entries):
    """Enrich existing CVEs with KEV data, or create new records for unknown CVEs.

    Returns:
        Tuple of (updated_count, created_count).
    """
    from datetime import date as date_type

    from cti_center.models import CVE

    kev_cve_ids = [e["cve_id"] for e in kev_entries if e.get("cve_id")]
    existing = {
        row.cve_id: row
        for row in db.query(CVE).filter(CVE.cve_id.in_(kev_cve_ids)).all()
    } if kev_cve_ids else {}
    updated = 0
    created = 0

    for entry in kev_entries:
        cve_id = entry["cve_id"]
        if not cve_id:
            continue

        cwes = entry.get("cwes") or []
        cwe_str = ", ".join(cwes) if cwes else None

        if cve_id in existing:
            cve = existing[cve_id]
            cve.kev_date_added = entry["date_added"]
            cve.kev_due_date = entry["due_date"]
            cve.kev_ransomware = entry["ransomware_use"]
            cve.kev_required_action = entry["required_action"]
            if cwe_str and not cve.cwe_ids:
                cve.cwe_ids = cwe_str
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
                cwe_ids=cwe_str,
            )
            db.add(cve)
            created += 1

    db.commit()
    return updated, created


def upsert_news(db, articles):
    """Insert new news articles and CVE links, re-linking existing articles.

    For new articles: inserts the article and its CVE links.
    For existing articles: attempts to insert any missing CVE links (re-linking).
    All CVENewsLink inserts use INSERT OR IGNORE to tolerate the unique constraint.

    Returns:
        Tuple of (new_articles, skipped, new_links).
    """
    from cti_center.models import CVENewsLink, NewsArticle

    existing = {row.url: row.id for row in db.query(NewsArticle.url, NewsArticle.id).all()}
    new_count = 0
    skipped = 0
    new_links = 0

    for article in articles:
        cve_ids = article.get("cve_ids", [])

        if article["url"] in existing:
            # Re-link: try to add any CVE links that are missing for this article.
            article_id = existing[article["url"]]
            for cve_id in cve_ids:
                stmt = (
                    sqlite_insert(CVENewsLink.__table__)
                    .values(cve_id=cve_id, article_id=article_id)
                    .on_conflict_do_nothing(index_elements=["cve_id", "article_id"])
                )
                result = db.execute(stmt)
                new_links += result.rowcount
            skipped += 1
            continue

        news = NewsArticle(
            url=article["url"],
            title=article["title"],
            source_name=article["source_name"],
            published_date=article.get("published_date"),
            summary=article.get("summary"),
        )
        db.add(news)
        db.flush()  # Get the generated id

        for cve_id in cve_ids:
            stmt = (
                sqlite_insert(CVENewsLink.__table__)
                .values(cve_id=cve_id, article_id=news.id)
                .on_conflict_do_nothing(index_elements=["cve_id", "article_id"])
            )
            result = db.execute(stmt)
            new_links += result.rowcount

        existing[article["url"]] = news.id
        new_count += 1

    db.commit()
    return new_count, skipped, new_links
