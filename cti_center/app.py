import logging
import os
import threading
from datetime import date, timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import select_autoescape
from sqlalchemy import and_, case, or_
from sqlalchemy.orm import Session

from sqlalchemy import func

from cti_center.database import Base, SessionLocal, engine, get_db, upsert_cves, upsert_kev, upsert_news
from cti_center.logging_config import setup_logging
from cti_center.models import CVE, CVENewsLink, NewsArticle
from cti_center.scoring import score_cves
from cti_center.seed import seed

setup_logging()
logger = logging.getLogger(__name__)

# Load API keys from api.env if present (does not override existing env vars)
_env_file = Path(__file__).resolve().parent.parent / "api.env"
if _env_file.exists():
    for line in _env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="CTI-Center")

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(
    directory=str(BASE_DIR / "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)

STATIC_DIR = BASE_DIR.parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _background_fetch():
    """Fetch recent CVEs from NVD and KEV catalog in a background thread."""
    try:
        from cti_center.nvd import fetch_cves

        cves = fetch_cves()
        db = SessionLocal()
        try:
            new_count, skipped = upsert_cves(db, cves)
            logger.info("NVD background fetch: %d new, %d already existed.", new_count, skipped)
        finally:
            db.close()
    except Exception:
        logger.error("NVD background fetch failed.", exc_info=True)

    try:
        from cti_center.kev import fetch_kev

        kev_entries = fetch_kev()
        db = SessionLocal()
        try:
            updated, created = upsert_kev(db, kev_entries)
            logger.info("KEV background fetch: %d enriched, %d new.", updated, created)
        finally:
            db.close()
    except Exception:
        logger.error("KEV background fetch failed.", exc_info=True)

    try:
        from cti_center.ghsa import fetch_ghsa

        advisories = fetch_ghsa()
        db = SessionLocal()
        try:
            new_count, skipped = upsert_cves(db, advisories)
            logger.info("GHSA background fetch: %d new, %d already existed.", new_count, skipped)
        finally:
            db.close()
    except Exception:
        logger.error("GHSA background fetch failed.", exc_info=True)

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

    try:
        from cti_center.news import fetch_news

        articles = fetch_news()
        db = SessionLocal()
        try:
            new_count, skipped = upsert_news(db, articles)
            logger.info("News background fetch: %d new, %d already existed.", new_count, skipped)
        finally:
            db.close()
    except Exception:
        logger.error("News background fetch failed.", exc_info=True)


@app.on_event("startup")
def on_startup():
    seed()
    threading.Thread(target=_background_fetch, daemon=True).start()


@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    tab: str = Query("trending"),
    db: Session = Depends(get_db),
):
    if tab not in ("trending", "recent", "all"):
        tab = "trending"

    today = date.today()

    if tab == "trending":
        kev_cutoff = today - timedelta(days=30)
        recent_cutoff = today - timedelta(days=7)
        cves = (
            db.query(CVE)
            .filter(
                or_(
                    CVE.kev_date_added >= kev_cutoff,
                    and_(
                        CVE.date_published >= recent_cutoff,
                        CVE.severity.in_(["CRITICAL", "HIGH"]),
                    ),
                )
            )
            .order_by(
                case((CVE.kev_date_added.isnot(None), 0), else_=1),
                CVE.kev_date_added.desc().nullslast(),
                CVE.cvss_score.desc(),
            )
            .limit(50)
            .all()
        )
    elif tab == "recent":
        recent_cutoff = today - timedelta(days=7)
        cves = (
            db.query(CVE)
            .filter(CVE.date_published >= recent_cutoff)
            .order_by(CVE.date_published.desc())
            .all()
        )
    else:  # all
        cves = db.query(CVE).order_by(CVE.date_published.desc()).all()

    # Count linked news articles per CVE
    cve_ids = [c.cve_id for c in cves]
    news_counts: dict[str, int] = {}
    if cve_ids:
        rows = (
            db.query(CVENewsLink.cve_id, func.count(CVENewsLink.id))
            .filter(CVENewsLink.cve_id.in_(cve_ids))
            .group_by(CVENewsLink.cve_id)
            .all()
        )
        news_counts = {row[0]: row[1] for row in rows}

    risk_scores = score_cves(cves, news_counts)

    if tab == "trending":
        cves = sorted(cves, key=lambda c: risk_scores[c.cve_id].score, reverse=True)

    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "cves": cves, "active_tab": tab, "news_counts": news_counts, "risk_scores": risk_scores},
    )


@app.get("/news", response_class=HTMLResponse)
def news_page(
    request: Request,
    has_cves: str = Query("all"),
    db: Session = Depends(get_db),
):
    if has_cves not in ("all", "yes", "no"):
        has_cves = "all"

    if has_cves == "yes":
        # Only articles that have at least one CVE link
        article_ids_with_cves = db.query(CVENewsLink.article_id).distinct()
        articles = (
            db.query(NewsArticle)
            .filter(NewsArticle.id.in_(article_ids_with_cves))
            .order_by(NewsArticle.published_date.desc())
            .limit(200)
            .all()
        )
    elif has_cves == "no":
        # Only articles with no CVE links
        article_ids_with_cves = db.query(CVENewsLink.article_id).distinct()
        articles = (
            db.query(NewsArticle)
            .filter(NewsArticle.id.notin_(article_ids_with_cves))
            .order_by(NewsArticle.published_date.desc())
            .limit(200)
            .all()
        )
    else:
        articles = (
            db.query(NewsArticle)
            .order_by(NewsArticle.published_date.desc())
            .limit(200)
            .all()
        )

    # Collect CVE links for each article
    article_ids = [a.id for a in articles]
    article_cves: dict[int, list[str]] = {}
    if article_ids:
        links = (
            db.query(CVENewsLink)
            .filter(CVENewsLink.article_id.in_(article_ids))
            .all()
        )
        for link in links:
            article_cves.setdefault(link.article_id, []).append(link.cve_id)

    return templates.TemplateResponse(
        "news.html",
        {"request": request, "articles": articles, "article_cves": article_cves, "has_cves": has_cves},
    )
