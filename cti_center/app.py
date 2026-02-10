import os
import threading
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import select_autoescape
from sqlalchemy.orm import Session

from cti_center.database import Base, SessionLocal, engine, get_db, upsert_cves, upsert_kev
from cti_center.models import CVE
from cti_center.seed import seed

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
            print(f"NVD background fetch: {new_count} new, {skipped} already existed.")
        finally:
            db.close()
    except Exception as exc:
        print(f"NVD background fetch failed: {exc}")

    try:
        from cti_center.kev import fetch_kev

        kev_entries = fetch_kev()
        db = SessionLocal()
        try:
            updated, created = upsert_kev(db, kev_entries)
            print(f"KEV background fetch: {updated} enriched, {created} new.")
        finally:
            db.close()
    except Exception as exc:
        print(f"KEV background fetch failed: {exc}")


@app.on_event("startup")
def on_startup():
    seed()
    threading.Thread(target=_background_fetch, daemon=True).start()


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    cves = db.query(CVE).order_by(CVE.cvss_score.desc()).all()
    return templates.TemplateResponse("dashboard.html", {"request": request, "cves": cves})
