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

## NVD API

CVEs are fetched automatically from the [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) on server startup and can also be fetched manually:

```bash
python -m cti_center.fetch
```

Optionally set `NVD_API_KEY` for faster rate limits (0.6s vs 6s between requests):

```bash
export NVD_API_KEY=your-api-key
```

Request a free key at [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).

## Lint

```bash
ruff check cti_center/
```

## License

MIT
