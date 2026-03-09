# Cyber Threat Intelligence Center

**A web application that finds notable CVEs in the news and analyzes them automatically.**

Most CVE tools tell you what exists. CTI-Center tells you what matters, and why, right now. It aggregates data from CVE feeds, security news sources, and exploit catalogs, then normalizes, enriches, and highlights the most relevant vulnerabilities for analysts using a custom risk scoring engine.

## Features

- **Custom Risk Scoring** — A 0-100 risk score that blends CVSS base score (35%), exploit maturity via CISA KEV (30%), news velocity (15%), recency (10%), and federal remediation urgency (10%). Each score includes human-readable explanations of why it differs from raw CVSS. Rejected CVEs are automatically scored at 0.
- **CVE Highlighting** — CVEs meeting key analyst-relevant conditions are visually flagged with an amber indicator and a "why it matters" one-liner. A CVE is highlighted when it has high CVSS plus a network attack vector (AV:N), is listed in CISA KEV, or is covered by 2+ news sources. One-liners synthesize severity, signals, and a recommended action (e.g., *"Critical vuln remotely exploitable, actively exploited in ransomware campaigns — patch immediately"*).
- **Dashboard Filtering & Sorting** — Clickable severity pills (Critical, High, Medium, Low), KEV toggle, In News toggle, and Highlighted toggle for multi-select filtering. Risk, Severity, and Published columns are sortable (desc/asc/default). All filters combine with text search and are preserved across tab switches and pagination.
- **Multi-Source Ingestion** — Pulls from the NVD API, CISA Known Exploited Vulnerabilities catalog, GitHub Advisory Database, MITRE CVE Services, and RSS feeds from major security outlets.
- **News-Aware Analysis** — Links CVEs to security news articles and surfaces coverage volume as a risk signal. CVEs discussed across multiple sources are ranked higher. The news page supports filtering by articles with or without linked CVEs.
- **Exploit-First Prioritization** — CVEs actively exploited in the wild, used in ransomware campaigns, or nearing federal remediation deadlines are surfaced above high-CVSS theoretical risks.
- **Discrepancy Detection** — Flags when CVSS and real-world risk diverge (e.g., "High CVSS but no real-world exploitation observed" or "Low CVSS but actively exploited").
- **CVE Detail Pages** — Each CVE has a dedicated page showing CVSS vector, CWE weakness IDs, risk factor breakdown, KEV remediation details, and linked news articles.
- **Data Freshness** — Stale CVE records are progressively enriched as more sources report data. CVSS scores, descriptions, affected products, and CVSS vectors are updated when better data arrives.
- **Scheduled Fetching** — Each data source runs on its own conservative schedule with randomized jitter. HTTP conditional requests (ETag/If-Modified-Since) avoid re-downloading unchanged data.
- **User Preferences** — Toggleable date format (US: Feb 21, 2026 / EU: 21 Feb 2026) persisted via cookie. A "last updated" timestamp in the header shows when data was last fetched.

## Tech Stack

- **FastAPI** — web framework
- **SQLite** — database (via SQLAlchemy 2.0)
- **Jinja2** — HTML templates

## Getting Started

### Prerequisites

- Python 3.12+

### Installation

```bash
git clone https://github.com/NotThatRob/Cyber-Threat-Intelligence-Center.git
cd Cyber-Threat-Intelligence-Center
python3 -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows (PowerShell — run once if scripts are disabled:
#   Set-ExecutionPolicy -Scope CurrentUser RemoteSigned)
.\.venv\Scripts\Activate.ps1

# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Windows (Command Prompt)
.venv\Scripts\activate.bat

pip install -e ".[dev]"
```

### Running

```bash
uvicorn cti_center.app:app --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The database is created and seeded with sample data automatically on first startup. Live CVEs are fetched from all data sources immediately and then re-fetched on a schedule (see [Fetch Schedule](#fetch-schedule)).

## Pages

### Dashboard (`/`)

The main view with three tabs:

- **Trending** — CVEs added to CISA KEV in the last 30 days or published in the last 7 days with Critical/High severity (capped at 50). Default-sorted by risk score.
- **Recent** — All CVEs published in the last 7 days, sorted by publication date.
- **All** — The full CVE database, paginated at 100 per page.

**Filtering:** Clickable severity pills (Critical, High, Medium, Low) support multi-select. KEV, In News, and Highlighted pills toggle on/off. Each pill shows a live count of matching CVEs in the current view. A "Clear filters" link appears when any filter is active. All filters combine with text search using AND logic.

**Sorting:** Click the Risk, Severity, or Published column headers to cycle through descending, ascending, and default sort order. The active sort column is highlighted with an arrow indicator.

**Search:** Free-text search across CVE IDs, affected products, and descriptions. Filters, sort order, and search are all preserved when switching tabs or navigating pages.

### CVE Detail (`/cve/{id}`)

Shows the full record for a single CVE: description, severity with CVSS score, CVSS vector string, CWE weakness IDs, affected product, and publication date. Highlighted CVEs display a "Why this matters" banner with an action-oriented summary. The risk score breakdown shows points earned per component (CVSS Base, Exploit Maturity, News Velocity, Recency, KEV Urgency) with human-readable factor explanations.

For KEV-listed CVEs, a highlighted section shows the CISA-mandated remediation action, date added, federal due date, and ransomware campaign status. Linked news articles are listed with source and publication date.

### News (`/news`)

Lists security news articles from RSS feeds with three filter tabs: All, With CVEs (articles that mention at least one CVE ID), and Without CVEs. Each article row shows linked CVE IDs as clickable links to their detail pages.

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

Articles mentioning CVE IDs are linked to CVEs in the database and displayed on the `/news` page. CVEs with news coverage show a badge on the dashboard. CVE IDs are extracted in three stages: RSS title and summary first, then `content:encoded` if available, then a full page fetch as a last resort (rate-limited, with robots.txt compliance).

### MITRE CVE Enrichment

CVEs missing CVSS scores (e.g., KEV-only records) are automatically enriched using the [MITRE CVE Services API](https://www.cve.org/AllResources/CveServices) on startup. This fills in CVSS scores, severity ratings, descriptions, and affected product information.

## Fetch Schedule

Data sources are fetched once immediately on startup, then re-fetched on a staggered schedule. Each job includes randomized jitter so requests don't land at predictable intervals.

| Source | Interval | Jitter | Notes |
|--------|----------|--------|-------|
| NVD API | 4 hours | ±10 min | Date-range queries for last 7 days |
| CISA KEV | 12 hours | ±30 min | HTTP conditional request (ETag/If-Modified-Since) — skips download if unchanged |
| GitHub Advisories | 6 hours | ±15 min | Date-range queries for last 7 days |
| RSS News | 2 hours | ±10 min | Per-feed conditional requests — skips unchanged feeds |
| MITRE Enrichment | 6 hours | ±15 min | Only queries CVEs with missing CVSS scores |

Conditional request state (ETag and Last-Modified headers) is persisted to `data/fetch_state.json` so it survives server restarts.

Manual fetches can still be triggered via `python -m cti_center.fetch` at any time.

## Risk Scoring

CTI-Center computes a custom 0-100 risk score for every CVE, designed to surface what actually matters over what merely has a high CVSS number.

| Component | Default Weight | Description |
|-----------|---------------|-------------|
| `cvss` | 35 | Raw CVSS v3 score mapped proportionally |
| `exploit` | 30 | CISA KEV listing + ransomware indicator |
| `news` | 15 | Number of news sources covering the CVE (capped at 5) |
| `recency` | 10 | How recently the CVE was published (last 7 days = full weight) |
| `urgency` | 10 | Proximity to federal remediation deadline |

Scores are categorized into risk labels: Critical (75-100), High (50-74), Medium (25-49), and Low (0-24). Rejected CVEs automatically receive a score of 0. Each score includes factor strings explaining the rating, visible via tooltip on the dashboard. Examples:

- *"Actively exploited in the wild (CISA KEV)"*
- *"Remotely exploitable over the network (AV:N)"*
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

## Deployment

The default `uvicorn ... --reload` command is for local development. To host CTI-Center on a server, follow the guidance below.

### Production Server

Run uvicorn without `--reload`, bound to all interfaces, with multiple workers:

```bash
uvicorn cti_center.app:app --host 0.0.0.0 --port 8000 --workers 4
```

> **Note:** Each worker process spawns its own background data-fetch thread on startup. This is fine for a single-server SQLite setup but means duplicate fetches will run briefly at boot. For most deployments this is harmless.

### Reverse Proxy

In production, place a reverse proxy in front of uvicorn for TLS termination, static file serving, and rate limiting.

**Nginx** — minimal config:

```nginx
server {
    listen 443 ssl;
    server_name cti.example.com;

    ssl_certificate     /etc/letsencrypt/live/cti.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cti.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Caddy** is a simpler alternative with automatic HTTPS — a two-line `Caddyfile`:

```
cti.example.com
reverse_proxy localhost:8000
```

### Docker

Example `Dockerfile` (not included in the repo — create one if needed):

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e .
EXPOSE 8000
CMD ["uvicorn", "cti_center.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

Run it:

```bash
docker build -t cti-center .
docker run -d -p 8000:8000 \
  -v cti-data:/app \
  -e NVD_API_KEY=your-key \
  -e GITHUB_TOKEN=your-token \
  cti-center
```

Or use a `docker-compose.yml`:

```yaml
services:
  cti-center:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - cti-data:/app
    environment:
      - NVD_API_KEY=${NVD_API_KEY}
      - GITHUB_TOKEN=${GITHUB_TOKEN}

volumes:
  cti-data:
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `NVD_API_KEY` | No | NVD API key for faster rate limits (0.6s vs 6s between requests) |
| `GITHUB_TOKEN` | No | GitHub token for higher GHSA rate limits (5,000 req/hr vs 60 req/hr) |

Both can also be set in an `api.env` file in the project root (see [Configuration](#configuration)).

### Deployment Notes

- **SQLite persistence** — The database is a local file (`cti_center.db`). In Docker, mount a volume so data survives container restarts.
- **No built-in authentication** — CTI-Center does not include user auth. If exposing to the internet, put it behind a reverse proxy with authentication, a VPN, or restrict access by IP.
- **Scheduled fetches** — Each worker process starts its own APScheduler instance, so with multiple workers you'll get duplicate fetches. For multi-worker deployments, consider running fetches via a separate cron job (`python -m cti_center.fetch`) instead.

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
