import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from fastapi import Cookie, Depends, FastAPI, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import select_autoescape
from sqlalchemy import and_, case, func, or_
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

from cti_center.database import Base, SessionLocal, apply_migrations, engine, get_db
from cti_center.logging_config import setup_logging
from cti_center.models import CVE, CVENewsLink, NewsArticle
from cti_center.scheduler import get_last_updated, start_scheduler, stop_scheduler
from cti_center.scoring import RISK_WEIGHTS, compute_risk_score, score_cves
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

@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    seed()
    start_scheduler()
    yield
    stop_scheduler()


app = FastAPI(title="CTI-Center", lifespan=lifespan)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com"
        )
        return response


app.add_middleware(SecurityHeadersMiddleware)

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(
    directory=str(BASE_DIR / "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)

STATIC_DIR = BASE_DIR.parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# Date format filter — "us" for Feb 21, 2026; "eu" for 21 Feb 2026.
_DATE_FORMATS = {
    "us": "%b %d, %Y",   # Feb 21, 2026
    "eu": "%d %b %Y",    # 21 Feb 2026
}


def _format_date(value, fmt: str = "us") -> str:
    """Jinja2 filter: format a date object according to the user's preference."""
    if value is None:
        return ""
    if fmt not in _DATE_FORMATS:
        fmt = "us"
    try:
        return value.strftime(_DATE_FORMATS[fmt])
    except AttributeError:
        return str(value)


templates.env.filters["format_date"] = _format_date


def _time_ago(value) -> str:
    """Jinja2 filter: convert a datetime to a human-readable relative string."""
    if value is None:
        return ""
    now = datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    delta = now - value
    minutes = int(delta.total_seconds() // 60)
    if minutes < 1:
        return "just now"
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"


templates.env.filters["time_ago"] = _time_ago


templates.env.globals["get_last_updated"] = get_last_updated


def _safe_url(url: str) -> str:
    """Jinja2 filter: only allow http/https URLs, block javascript: and data: protocols."""
    if url and url.strip().lower().startswith(("http://", "https://")):
        return url
    return "#"


templates.env.filters["safe_url"] = _safe_url


@app.get("/settings/date-format", response_class=HTMLResponse)
def toggle_date_format(request: Request, date_fmt: str | None = Cookie(None)):
    """Toggle between American and European date format."""
    new_fmt = "eu" if date_fmt == "us" else "us"
    referer = request.headers.get("referer", "/")
    # Prevent open-redirect: only allow relative paths or same-origin URLs.
    if referer.startswith("/") and not referer.startswith("//"):
        redirect_url = referer
    else:
        from urllib.parse import urlparse
        parsed = urlparse(referer)
        base = urlparse(str(request.base_url))
        if parsed.netloc and parsed.netloc == base.netloc:
            redirect_url = referer
        else:
            redirect_url = "/"
    response = RedirectResponse(url=redirect_url, status_code=303)
    response.set_cookie(
        "date_fmt", new_fmt, max_age=365 * 24 * 3600,
        httponly=True, samesite="lax",
    )
    return response


@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    tab: str = Query("trending"),
    q: str = Query("", max_length=200),
    page: int = Query(1, ge=1),
    severity: str = Query("", max_length=50),
    kev: int = Query(0, ge=0, le=1),
    news: int = Query(0, ge=0, le=1),
    highlighted: int = Query(0, ge=0, le=1),
    sort: str = Query("", max_length=20),
    dir: str = Query("", max_length=4),
    db: Session = Depends(get_db),
    date_fmt: str | None = Cookie(None),
):
    if tab not in ("trending", "recent", "all"):
        tab = "trending"

    q = q.strip()

    # Validate filter/sort params
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    active_severities = [s for s in severity.upper().split(",") if s in valid_severities] if severity else []
    kev = 1 if kev == 1 else 0
    news = 1 if news == 1 else 0
    highlighted = 1 if highlighted == 1 else 0
    valid_sorts = {"risk", "severity", "published"}
    if sort not in valid_sorts:
        sort = ""
    if dir not in ("asc", "desc"):
        dir = ""

    today = date.today()
    has_custom_sort = sort and dir and sort != "risk"

    if tab == "trending":
        kev_cutoff = today - timedelta(days=30)
        recent_cutoff = today - timedelta(days=7)
        query = (
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
        )
        if not has_custom_sort:
            query = query.order_by(
                case((CVE.kev_date_added.isnot(None), 0), else_=1),
                CVE.kev_date_added.desc().nullslast(),
                CVE.cvss_score.desc(),
            )
        query = query.limit(50)
    elif tab == "recent":
        recent_cutoff = today - timedelta(days=7)
        query = db.query(CVE).filter(CVE.date_published >= recent_cutoff)
        if not has_custom_sort:
            query = query.order_by(CVE.date_published.desc())
    else:  # all
        query = db.query(CVE)
        if not has_custom_sort:
            query = query.order_by(CVE.date_published.desc())

    if q:
        q_escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{q_escaped}%"
        query = query.filter(
            or_(
                CVE.cve_id.ilike(pattern, escape="\\"),
                CVE.affected_product.ilike(pattern, escape="\\"),
                CVE.description.ilike(pattern, escape="\\"),
            )
        )

    # Apply filters
    if active_severities:
        query = query.filter(CVE.severity.in_(active_severities))
    if kev:
        query = query.filter(CVE.kev_date_added.isnot(None))
    if news:
        news_subq = db.query(CVENewsLink.cve_id).distinct().subquery()
        query = query.filter(CVE.cve_id.in_(db.query(news_subq.c.cve_id)))

    # Apply SQL-level sort for severity/published
    if has_custom_sort:
        col = CVE.cvss_score if sort == "severity" else CVE.date_published
        query = query.order_by(col.asc() if dir == "asc" else col.desc())

    # Paginate the "all" tab (trending/recent have natural bounds).
    total_pages = 1
    if tab == "all":
        page_size = 100
        total = query.count()
        total_pages = max(1, (total + page_size - 1) // page_size)
        page = min(page, total_pages)
        query = query.offset((page - 1) * page_size).limit(page_size)

    cves = query.all()

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

    if highlighted:
        cves = [c for c in cves if risk_scores[c.cve_id].highlighted]

    # Python-side sort for risk score
    if sort == "risk" and dir:
        cves = sorted(cves, key=lambda c: risk_scores[c.cve_id].score, reverse=(dir == "desc"))
    elif tab == "trending" and not sort:
        cves = sorted(cves, key=lambda c: risk_scores[c.cve_id].score, reverse=True)

    fmt = date_fmt if date_fmt in ("us", "eu") else "us"
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request, "cves": cves, "active_tab": tab,
            "news_counts": news_counts, "risk_scores": risk_scores,
            "risk_weights": RISK_WEIGHTS, "date_fmt": fmt, "q": q,
            "page": page, "total_pages": total_pages,
            "active_severities": active_severities,
            "filter_kev": kev, "filter_news": news, "filter_highlighted": highlighted,
            "sort_col": sort, "sort_dir": dir,
        },
    )


@app.get("/cve/{cve_id}", response_class=HTMLResponse)
def cve_detail(
    request: Request,
    cve_id: str,
    db: Session = Depends(get_db),
    date_fmt: str | None = Cookie(None),
):
    cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
    if not cve:
        return HTMLResponse(status_code=404, content="CVE not found")

    articles = (
        db.query(NewsArticle)
        .join(CVENewsLink, CVENewsLink.article_id == NewsArticle.id)
        .filter(CVENewsLink.cve_id == cve_id)
        .order_by(NewsArticle.published_date.desc())
        .all()
    )

    risk_score = compute_risk_score(cve, news_count=len(articles))

    # Preserve the page the user came from (tab, search query, etc.)
    referer = request.headers.get("referer", "")
    from urllib.parse import urlparse
    parsed = urlparse(referer)
    base = urlparse(str(request.base_url))
    if parsed.netloc and parsed.netloc == base.netloc and parsed.path in ("/", "/news"):
        back_url = referer
    else:
        back_url = "/"

    fmt = date_fmt if date_fmt in ("us", "eu") else "us"
    return templates.TemplateResponse(
        "cve_detail.html",
        {"request": request, "cve": cve, "risk_score": risk_score, "articles": articles, "risk_weights": RISK_WEIGHTS, "date_fmt": fmt, "back_url": back_url},
    )


@app.get("/news", response_class=HTMLResponse)
def news_page(
    request: Request,
    has_cves: str = Query("all"),
    db: Session = Depends(get_db),
    date_fmt: str | None = Cookie(None),
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

    fmt = date_fmt if date_fmt in ("us", "eu") else "us"
    return templates.TemplateResponse(
        "news.html",
        {"request": request, "articles": articles, "article_cves": article_cves, "has_cves": has_cves, "date_fmt": fmt},
    )
