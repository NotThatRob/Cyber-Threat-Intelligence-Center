# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CTI-Center is a Cyber Threat Intelligence web application that aggregates CVE data from multiple sources (NVD, CISA KEV, GitHub Advisories, MITRE, security news RSS feeds), computes a custom 0-100 risk score, and presents a dashboard for analysts. Built with FastAPI + SQLite (SQLAlchemy 2.0) + Jinja2 server-rendered templates.

## Commands

```bash
# Install (editable, with dev deps)
pip install -e ".[dev]"

# Run dev server
uvicorn cti_center.app:app --reload

# Lint
ruff check cti_center/

# Manual data fetch (all sources)
python -m cti_center.fetch

# Re-seed database with sample data
python -m cti_center.seed

# Run tests
pytest
```

No test suite exists yet — pytest is a dev dependency but no tests have been written.

## Architecture

### Data Flow

1. **Ingestion** — Source-specific fetchers (`nvd.py`, `kev.py`, `ghsa.py`, `news.py`, `mitre.py`) pull data from external APIs/feeds
2. **Upsert** — `database.py` provides `upsert_cves()`, `upsert_kev()`, `upsert_news()` which insert-or-update records, handling deduplication and stale record enrichment
3. **Scoring** — `scoring.py` computes a composite risk score (CVSS 35%, exploit maturity 30%, news velocity 15%, recency 10%, KEV urgency 10%)
4. **Presentation** — `app.py` serves three pages via Jinja2 templates: dashboard (`/`), CVE detail (`/cve/{id}`), news (`/news`)

### Scheduling

`scheduler.py` uses APScheduler `BackgroundScheduler` with per-source intervals and jitter. An initial full fetch cycle runs on startup in a background thread. Conditional request state (ETag/Last-Modified) persists in `data/fetch_state.json`.

### Key Patterns

- **SQLAlchemy 2.0 mapped_column style** — Models use `Mapped[T]` type annotations, not legacy Column()
- **Database migrations** — Lightweight, inline in `database.py:apply_migrations()` using raw SQL (PRAGMA-based column detection + ALTER TABLE). No Alembic.
- **Upsert logic** — `upsert_cves()` updates existing records only when incoming data is "better" (e.g., replaces CVSS 0.0 with a real score, replaces "Unknown" product). CVE news links use SQLite `INSERT OR IGNORE`.
- **API keys** — Optional, loaded from `api.env` file or environment variables (`NVD_API_KEY`, `GITHUB_TOKEN`). Never committed.
- **Security middleware** — `SecurityHeadersMiddleware` adds CSP, X-Frame-Options, etc. URL validation in templates via `safe_url` filter (blocks javascript:/data: protocols). Open-redirect protection on referer-based redirects.

### Database

Single SQLite file `cti_center.db` at project root. Three tables:
- `cves` — CVE records with CVSS, KEV fields, CWE IDs, CVSS vector
- `news_articles` — RSS articles with URL (unique), title, source, date
- `cve_news_links` — Many-to-many join with unique constraint on (cve_id, article_id)

### Frontend

Server-rendered HTML with no JS framework. Single `static/style.css`. Templates in `cti_center/templates/` extend `base.html`. Custom Jinja2 filters: `format_date`, `time_ago`, `safe_url`.
