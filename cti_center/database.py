import logging

from sqlalchemy import create_engine, text
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import DeclarativeBase, sessionmaker

logger = logging.getLogger(__name__)

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


def apply_migrations(db):
    """Run lightweight schema migrations that are safe on both new and existing DBs."""
    db.execute(text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_cve_news_link "
        "ON cve_news_links(cve_id, article_id)"
    ))
    # Clamp any published dates that ended up in the future (e.g. event
    # pages whose RSS pubDate was the event date, not the publish date).
    db.execute(text(
        "UPDATE news_articles SET published_date = date('now') "
        "WHERE published_date > date('now')"
    ))
    db.commit()
    logger.info("Migrations applied.")


def upsert_cves(db, cves):
    """Insert new CVEs, skipping any that already exist by cve_id.

    Returns:
        Tuple of (new_count, skipped_count).
    """
    from cti_center.models import CVE

    existing_ids = {row[0] for row in db.query(CVE.cve_id).all()}
    new_cves = []
    for c in cves:
        if c.cve_id not in existing_ids:
            new_cves.append(c)
            existing_ids.add(c.cve_id)  # Deduplicate within the batch
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
