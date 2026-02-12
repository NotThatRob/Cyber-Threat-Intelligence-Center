# Cyber Threat Intelligence Center

**A web application that finds notable CVEs in the news and analyzes them automatically.**

Most CVE tools tell you what exists. CTI-Center tells you what matters, and why, right now. It aggregates data from CVE feeds, security news sources, and exploit catalogs, then normalizes, enriches, and highlights the most relevant vulnerabilities for analysts using a custom risk scoring engine.

## Features

- **Custom Risk Scoring** — A 0-100 risk score that blends CVSS base score (35%), exploit maturity via CISA KEV (30%), news velocity (15%), recency (10%), and federal remediation urgency (10%). Each score includes human-readable explanations of why it differs from raw CVSS.
- **Multi-Source Ingestion** — Pulls from the NVD API, CISA Known Exploited Vulnerabilities catalog, GitHub Advisory Database, MITRE CVE Services, and RSS feeds from major security outlets.
- **News-Aware Analysis** — Links CVEs to security news articles and surfaces coverage volume as a risk signal. CVEs discussed across multiple sources are ranked higher.
- **Exploit-First Prioritization** — CVEs actively exploited in the wild, used in ransomware campaigns, or nearing federal remediation deadlines are surfaced above high-CVSS theoretical risks.
- **Discrepancy Detection** — Flags when CVSS and real-world risk diverge (e.g., "High CVSS but no real-world exploitation observed" or "Low CVSS but actively exploited").

## Tech Stack

- **FastAPI** — web framework
- **SQLite** — database (via SQLAlchemy 2.0)
- **Jinja2** — HTML templates

## Getting Started

### Prerequisites

- Python 3.12+

### Installation

```bash
git clone https://github.com/NotThatRob/CTI-Center.git
cd CTI-Center
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Running

```bash
uvicorn cti_center.app:app --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The database is created and seeded with sample data automatically on first startup. Live CVEs are fetched from all data sources in a background thread.

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

Security news articles are fetched automatically from RSS feeds on startup and via `python -m cti_center.fetch`. Currently ingests:

- BleepingComputer
- The Hacker News
- Dark Reading
- Krebs on Security

Articles mentioning CVE IDs are linked to CVEs in the database and displayed on the `/news` page. CVEs with news coverage show a badge on the dashboard.

### MITRE CVE Enrichment

CVEs missing CVSS scores (e.g., KEV-only records) are automatically enriched using the [MITRE CVE Services API](https://www.cve.org/AllResources/CveServices) on startup. This fills in CVSS scores, severity ratings, descriptions, and affected product information.

## Risk Scoring

CTI-Center computes a custom 0-100 risk score for every CVE, designed to surface what actually matters over what merely has a high CVSS number.

| Component | Default Weight | Description |
|-----------|---------------|-------------|
| `cvss` | 35 | Raw CVSS v3 score mapped proportionally |
| `exploit` | 30 | CISA KEV listing + ransomware indicator |
| `news` | 15 | Number of news sources covering the CVE (capped at 5) |
| `recency` | 10 | How recently the CVE was published (last 7 days = full weight) |
| `urgency` | 10 | Proximity to federal remediation deadline |

Each score includes factor strings explaining the rating, visible via tooltip on the dashboard. Examples:

- *"Actively exploited in the wild (CISA KEV)"*
- *"High CVSS but no real-world exploitation observed"*
- *"Low CVSS but actively exploited — real-world risk exceeds base score"*
- *"Federal remediation deadline overdue"*

### Customizing Weights

Weights are configurable by editing the `RISK_WEIGHTS` dictionary in `cti_center/scoring.py`. Each value is the maximum number of points that component can contribute. Weights must sum to 100.

```python
# cti_center/scoring.py
RISK_WEIGHTS = {
    "cvss":    35,   # Raw CVSS v3 score mapped proportionally
    "exploit": 30,   # CISA KEV listing + ransomware indicator
    "news":    15,   # Number of news sources covering the CVE
    "recency": 10,   # How recently the CVE was published
    "urgency": 10,   # Proximity to federal remediation deadline
}
```

For example, an organization that prioritizes exploit status over CVSS could shift weight from `cvss` to `exploit`:

```python
RISK_WEIGHTS = {
    "cvss":    20,
    "exploit": 45,
    "news":    15,
    "recency": 10,
    "urgency": 10,
}
```

Weights can also be passed programmatically to `compute_risk_score()` and `score_cves()` via the optional `weights` parameter, which overrides `RISK_WEIGHTS` for that call without changing the global default.

## Configuration

All API keys are optional and loaded from environment variables or an `api.env` file in the project root:

```bash
# api.env (optional — does not override existing env vars)
NVD_API_KEY=your-nvd-key
GITHUB_TOKEN=your-github-token
```

## Logging

All modules log to `logs/cti_center.log` (rotating, 5 MB max, 3 backups) and to the console. The `logs/` directory is created automatically on startup. Log level is DEBUG in the file and INFO on the console.

## Development

```bash
# Lint
ruff check cti_center/

# Re-seed database
python -m cti_center.seed

# Manual data fetch
python -m cti_center.fetch
```

## Acknowledgments

This project was developed with assistance from [Claude Code](https://claude.ai/claude-code), Anthropic's AI coding assistant. Claude Code helped with code review, security hardening, bug fixes, and documentation but the core functionality and architecture were human-designed and directed.

## License

See [LICENSE](LICENSE) for details.
