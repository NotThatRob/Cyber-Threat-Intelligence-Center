import logging
import os
from datetime import date, timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import select_autoescape
from sqlalchemy import and_, case, func, or_
from sqlalchemy.orm import Session

from cti_center.database import Base, SessionLocal, apply_migrations, engine, get_db
from cti_center.logging_config import setup_logging
from cti_center.models import CVE, CVENewsLink, NewsArticle
from cti_center.scheduler import start_scheduler, stop_scheduler
from cti_center.scoring import RISK_WEIGHTS, score_cves
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
_mig_db = SessionLocal()
try:
    apply_migrations(_mig_db)
finally:
    _mig_db.close()

app = FastAPI(title="CTI-Center")

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(
    directory=str(BASE_DIR / "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)

STATIC_DIR = BASE_DIR.parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.on_event("startup")
def on_startup():
    seed()
    start_scheduler()


@app.on_event("shutdown")
def on_shutdown():
    stop_scheduler()


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
        {"request": request, "cves": cves, "active_tab": tab, "news_counts": news_counts, "risk_scores": risk_scores, "risk_weights": RISK_WEIGHTS},
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
