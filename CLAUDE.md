# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CTI-Center is a web application that finds notable CVEs in the news and analyzes them automatically. It aggregates data from CVE feeds (NVD, MITRE, vendor advisories), security news sources, and community signals, then normalizes, enriches, and highlights the most relevant vulnerabilities for analysts.

See `TODO.md` for the full product roadmap and feature vision.

## Tech Stack

- **FastAPI** + **Jinja2** templates + **SQLite** via SQLAlchemy 2.0
- Dependencies managed via `pyproject.toml` (PEP 621)

## Commands

```bash
# Setup
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run dev server
uvicorn cti_center.app:app --reload

# Lint
ruff check cti_center/

# Re-seed database (if needed)
python -m cti_center.seed

# Fetch CVEs from NVD manually
python -m cti_center.fetch

# Fetch with API key (faster rate limit)
NVD_API_KEY=your-key python -m cti_center.fetch
```

## Architecture

- `cti_center/logging_config.py` — Centralized logging setup; configures rotating file handler (`logs/cti_center.log`) and console handler
- `cti_center/app.py` — FastAPI application entry point, route definitions, template config
- `cti_center/models.py` — SQLAlchemy ORM models (CVE table)
- `cti_center/database.py` — Engine, session factory, `Base` class, `get_db()` dependency
- `cti_center/nvd.py` — NVD API 2.0 client; fetches, parses, and returns CVE model instances
- `cti_center/kev.py` — CISA KEV catalog client; downloads the Known Exploited Vulnerabilities JSON and enriches CVEs with exploitation status, remediation deadlines, and ransomware campaign data
- `cti_center/ghsa.py` — GitHub Advisory Database client; fetches reviewed advisories with CVE IDs across npm, pip, Maven, Go, Rust, etc. Optional `GITHUB_TOKEN` for higher rate limits
- `cti_center/mitre.py` — MITRE CVE Services enrichment; looks up individual CVE records to fill CVSS/description gaps in KEV-created or incomplete records
- `cti_center/fetch.py` — CLI entry point (`python -m cti_center.fetch`) for manual NVD and GHSA ingestion
- `cti_center/seed.py` — Sample data seeder (runs automatically on startup as fallback)
- `cti_center/templates/` — Jinja2 HTML templates (`base.html` layout, `dashboard.html`)
- `static/` — CSS assets served via FastAPI's StaticFiles mount
- `logs/` — Runtime log files (gitignored); created automatically on startup

## Key Concepts

- **Custom risk re-scoring**: Blends CVSS, exploit maturity, news velocity, and asset criticality — not just raw CVSS
- **News-aware analysis**: Correlates CVEs with how they're discussed (patch urgency vs theoretical risk, vendor minimization vs researcher concern)
- **Environment-aware prioritization**: Users define their tech stack/industry/risk tolerance and get CVEs prioritized relative to their environment
- **Signal vs noise**: Suppresses duplicate/derivative articles, detects hype vs actual threat

## Important

Ensure the @.gitignore, @TODO.MD, and @README.md are up to date after every change. The @TODO.md is the lifeblood of this project, it should be the place to check for past and future implementations.

## License

MIT
