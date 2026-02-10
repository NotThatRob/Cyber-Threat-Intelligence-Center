# CTI-Center

A web app that finds notable CVEs in the news and analyzes them automatically.

## Tech Stack

- **FastAPI** — web framework
- **SQLite** — database (via SQLAlchemy 2.0)
- **Jinja2** — HTML templates

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Run

```bash
uvicorn cti_center.app:app --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The database is created and seeded with sample data automatically on first startup. Live CVEs are fetched from the NVD API in a background thread.

## Data Sources

### NVD API

CVEs are fetched automatically from the [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) on server startup and can also be fetched manually:

```bash
python -m cti_center.fetch
```

Optionally set `NVD_API_KEY` for faster rate limits (0.6s vs 6s between requests):

```bash
export NVD_API_KEY=your-api-key
```

Request a free key at [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).

### CISA KEV

The [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog is fetched automatically on startup. CVEs in the KEV catalog are tagged as "Actively Exploited" on the dashboard and include federal remediation deadlines and ransomware campaign indicators.

### GitHub Advisory Database

Reviewed security advisories are fetched from the [GitHub Advisory Database](https://github.com/advisories) on startup and via `python -m cti_center.fetch`. Covers advisories across npm, pip, Maven, Go, Rust, and other ecosystems.

Optionally set `GITHUB_TOKEN` for higher rate limits (5,000 req/hr vs 60 req/hr):

```bash
export GITHUB_TOKEN=your-token
```

### Security News (RSS)

Security news articles are fetched automatically from RSS feeds on startup and via `python -m cti_center.fetch`. Currently ingests BleepingComputer, The Hacker News, Dark Reading, and Krebs on Security. Articles mentioning CVE IDs are linked to CVEs in the database and displayed on the `/news` page. CVEs with news coverage show a badge on the dashboard.

### MITRE CVE Enrichment

CVEs missing CVSS scores (e.g., KEV-only records) are automatically enriched using the [MITRE CVE Services API](https://www.cve.org/AllResources/CveServices) on startup. This fills in CVSS scores, severity ratings, descriptions, and affected product information.

## Logging

All modules log to `logs/cti_center.log` (rotating, 5 MB max, 3 backups) and to the console. The `logs/` directory is created automatically on startup. Log level is DEBUG in the file and INFO on the console.

## Lint

```bash
ruff check cti_center/
```

## License

MIT
