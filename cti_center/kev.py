"""CISA Known Exploited Vulnerabilities (KEV) catalog client."""

import logging
from datetime import date, datetime

import httpx

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
USER_AGENT = "CTI-Center/0.1 (vulnerability-aggregator)"


def _parse_date(value: str) -> date | None:
    """Parse a YYYY-MM-DD date string, returning None on failure."""
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


def fetch_kev(
    etag: str | None = None,
    last_modified: str | None = None,
) -> tuple[list[dict], dict[str, str]] | None:
    """Download and parse the CISA KEV catalog.

    Args:
        etag: ETag from a previous response for conditional request.
        last_modified: Last-Modified from a previous response.

    Returns:
        Tuple of (entries list, response headers dict) on success,
        or None if the server returned 304 Not Modified.
    """
    headers: dict[str, str] = {"User-Agent": USER_AGENT}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified

    with httpx.Client(timeout=30.0) as client:
        response = client.get(KEV_URL, headers=headers)

        if response.status_code == 304:
            logger.info("KEV: not modified since last fetch, skipping.")
            return None

        response.raise_for_status()
        data = response.json()

    # Capture caching headers for next request.
    resp_headers = {}
    if response.headers.get("ETag"):
        resp_headers["etag"] = response.headers["ETag"]
    if response.headers.get("Last-Modified"):
        resp_headers["last_modified"] = response.headers["Last-Modified"]

    catalog_version = data.get("catalogVersion", "unknown")
    vulnerabilities = data.get("vulnerabilities", [])
    logger.info("KEV catalog version %s: %d entries", catalog_version, len(vulnerabilities))

    entries = []
    for vuln in vulnerabilities:
        entries.append({
            "cve_id": vuln.get("cveID", ""),
            "vendor_project": vuln.get("vendorProject", ""),
            "product": vuln.get("product", ""),
            "vulnerability_name": vuln.get("vulnerabilityName", ""),
            "short_description": vuln.get("shortDescription", ""),
            "date_added": _parse_date(vuln.get("dateAdded", "")),
            "due_date": _parse_date(vuln.get("dueDate", "")),
            "required_action": vuln.get("requiredAction", ""),
            "ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown"),
            "cwes": vuln.get("cwes", []),
        })

    return entries, resp_headers
