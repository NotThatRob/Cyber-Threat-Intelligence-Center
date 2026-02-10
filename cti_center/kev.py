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


def fetch_kev() -> list[dict]:
    """Download and parse the CISA KEV catalog.

    Returns:
        List of dicts with keys: cve_id, vendor_project, product,
        vulnerability_name, short_description, date_added, due_date,
        required_action, ransomware_use, cwes.
    """
    headers = {"User-Agent": USER_AGENT}

    with httpx.Client(timeout=30.0) as client:
        response = client.get(KEV_URL, headers=headers)
        response.raise_for_status()
        data = response.json()

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

    return entries
