# Plan: Add GitHub Advisory, MSRC, and MITRE CVE Data Sources

## Context

The dashboard currently ingests CVEs from two sources: NVD API 2.0 and CISA KEV catalog. The TODO.md roadmap calls for additional data sources including MITRE CVE and vendor advisories. Adding these sources improves coverage — MITRE catches CVEs before NVD processes them (NVD backlog can be days/weeks), GitHub Advisory Database covers open-source ecosystem vulnerabilities with EPSS data, and MSRC provides Microsoft Patch Tuesday details faster than NVD enrichment.

All three APIs are free, require no authentication, and follow REST/JSON patterns consistent with our existing `nvd.py` and `kev.py` modules.

## New Modules

### 1. `cti_center/ghsa.py` — GitHub Advisory Database

**API**: `GET https://api.github.com/advisories`
- No authentication required for public advisories
- Query params: `type=reviewed`, `severity=critical,high,medium,low`, `published=YYYY-MM-DD..`, `per_page=100`, `sort=published`, `direction=desc`
- Rate limit: 60 requests/hour unauthenticated (sufficient — one paginated fetch covers recent advisories)
- Pagination via `Link` header (standard GitHub pagination)

**Function**: `fetch_ghsa(days_back: int = 7) -> list[CVE]`
- Fetch reviewed advisories published in the last `days_back` days
- Paginate through results (max 100 per page)
- Parse response fields:
  - `cve_id` → `cve_id` (skip advisories without a CVE ID — GHSA-only entries don't fit our CVE-centric model yet)
  - `summary` → `description` (truncated to 2000 chars)
  - `cvss_severities.score_v3` → `cvss_score`
  - `severity` → `severity` (uppercased to match our convention)
  - `vulnerabilities[0].package.name` → `affected_product` (first affected package)
  - `published_at` → `date_published`
  - `html_url` → `source_url`
- Return unsaved CVE model instances (same pattern as `nvd.py`)
- User-Agent: `CTI-Center/0.1 (vulnerability-aggregator)`
- Sleep 1s between paginated requests to respect rate limits

### 2. `cti_center/msrc.py` — Microsoft Security Response Center

**API**: Two-step process:
1. `GET https://api.msrc.microsoft.com/cvrf/v3.0/updates` → list of monthly releases with IDs like `"2026-Feb"`
2. `GET https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{id}` → full CVRF document with all CVEs for that month

**Function**: `fetch_msrc(months_back: int = 2) -> list[CVE]`
- Fetch the `/updates` index, filter to the last `months_back` monthly releases
- For each release, fetch the full CVRF document (Accept: `application/json`)
- Parse `Vulnerability` array entries:
  - `CVE` → `cve_id`
  - `Title.Value` → part of `affected_product`
  - `Notes` array (Type=Description) → `description`
  - CVSS extracted from `CVSSScoreSets` in `Threats` or from the `ScoreSet` entries → `cvss_score` + `severity`
  - `RevisionHistory[0].Date` → `date_published`
  - Source URL: `https://msrc.microsoft.com/update-guide/vulnerability/{CVE-ID}`
- Return unsaved CVE model instances
- User-Agent: `CTI-Center/0.1 (vulnerability-aggregator)`
- Sleep 2s between monthly release fetches (responses are large)

### 3. `cti_center/mitre.py` — MITRE CVE via cvelistV5 Delta Downloads

**Approach**: Download hourly/daily delta releases from the cvelistV5 GitHub repository rather than using the CVE Services API (which is designed for CNAs, not consumers).

**API**: GitHub Releases API for `CVEProject/cvelistV5`
- `GET https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=5` → get latest releases
- Each release has assets including delta zip files with new/modified CVE records
- Delta files contain CVE JSON 5.0 records

**Function**: `fetch_mitre_recent(hours_back: int = 24) -> list[CVE]`
- Fetch latest releases from the cvelistV5 repo
- Download the most recent delta zip asset (hourly updates available)
- Extract and parse CVE JSON 5.0 records:
  - `cveMetadata.cveId` → `cve_id`
  - `containers.cna.descriptions[0].value` → `description`
  - `containers.cna.metrics[0].cvssV3_1.baseScore` → `cvss_score`
  - `containers.cna.metrics[0].cvssV3_1.baseSeverity` → `severity`
  - `containers.cna.affected[0].product` → `affected_product`
  - `cveMetadata.datePublished` → `date_published`
  - Source URL: `https://www.cve.org/CVERecord?id={CVE-ID}`
- Return unsaved CVE model instances
- Fallback: If no delta releases found, skip gracefully with a log message

## Database Changes

### `cti_center/database.py`

No schema changes needed. The existing `upsert_cves()` function handles deduplication by `cve_id` — if a CVE from GitHub Advisory or MSRC already exists from NVD, it's skipped. This is the correct behavior: NVD data is generally richer (better CVSS, CPE data), so we keep the first-ingested version.

Add a new helper for sources that may have better data than what's already stored:

**`upsert_cves_merge(db, cves) -> tuple[int, int, int]`**
- For each incoming CVE:
  - If `cve_id` doesn't exist → insert (new)
  - If `cve_id` exists but has `cvss_score=0.0` (placeholder from KEV) → update with real data (merged)
  - If `cve_id` exists with real data → skip
- Returns `(new_count, merged_count, skipped_count)`
- This handles the case where KEV created a placeholder CVE (cvss=0.0) that a later source can enrich

## Integration

### `cti_center/app.py` — `_background_fetch()`

Add the three new sources to the background fetch thread, after NVD and KEV:

```python
# Existing
fetch NVD → upsert_cves
fetch KEV → upsert_kev

# New (order matters — NVD first gives us rich baseline)
fetch GHSA → upsert_cves_merge
fetch MSRC → upsert_cves_merge
fetch MITRE → upsert_cves_merge
```

Each wrapped in its own try/except block with logging (same pattern as existing sources).

### `cti_center/fetch.py`

Add CLI flags or separate entry points for manual fetching:
- `python -m cti_center.fetch` — fetches all sources (NVD + new ones)
- Each source logs its results independently

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `cti_center/ghsa.py` | **Create** | GitHub Advisory Database client |
| `cti_center/msrc.py` | **Create** | Microsoft MSRC CVRF client |
| `cti_center/mitre.py` | **Create** | MITRE cvelistV5 delta download client |
| `cti_center/database.py` | **Modify** | Add `upsert_cves_merge()` function |
| `cti_center/app.py` | **Modify** | Add new sources to `_background_fetch()` |
| `cti_center/fetch.py` | **Modify** | Add manual fetch support for new sources |
| `TODO.md` | **Modify** | Mark MITRE and vendor advisories as done |
| `README.md` | **Modify** | Document new data sources |

## Implementation Order

1. `database.py` — Add `upsert_cves_merge()` (needed by all three sources)
2. `ghsa.py` — Simplest API, good for validating the pattern
3. `msrc.py` — More complex CVRF parsing but well-documented
4. `mitre.py` — GitHub releases + zip extraction, most involved
5. `app.py` — Wire all sources into background fetch
6. `fetch.py` — Add manual fetch support
7. `TODO.md` + `README.md` — Documentation updates

## Verification

1. `ruff check cti_center/` — passes lint
2. Test each module independently:
   - `python -c "from cti_center.ghsa import fetch_ghsa; print(len(fetch_ghsa()))"`
   - `python -c "from cti_center.msrc import fetch_msrc; print(len(fetch_msrc()))"`
   - `python -c "from cti_center.mitre import fetch_mitre_recent; print(len(fetch_mitre_recent()))"`
3. `uvicorn cti_center.app:app --reload` — new sources fetch in background, logs show results
4. Dashboard shows CVEs from all sources (check for Microsoft-specific CVEs, open-source package CVEs)
5. Verify deduplication: CVEs appearing in multiple sources should only have one database entry
