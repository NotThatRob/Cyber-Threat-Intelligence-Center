"""GitHub Advisory Database client for fetching reviewed security advisories."""

import logging
import os
import time
from datetime import date, datetime, timedelta, timezone

import httpx

from cti_center.models import CVE

logger = logging.getLogger(__name__)

GHSA_API_URL = "https://api.github.com/advisories"
USER_AGENT = "CTI-Center/0.1 (vulnerability-aggregator)"


def _parse_severity(cvss_score: float) -> str:
    if cvss_score >= 9.0:
        return "CRITICAL"
    if cvss_score >= 7.0:
        return "HIGH"
    if cvss_score >= 4.0:
        return "MEDIUM"
    if cvss_score > 0:
        return "LOW"
    return "NONE"


def _extract_affected_product(advisory: dict) -> str:
    """Extract ecosystem + package name from the first vulnerability entry."""
    vulnerabilities = advisory.get("vulnerabilities") or []
    if not vulnerabilities:
        return "Unknown"
    vuln = vulnerabilities[0]
    pkg = vuln.get("package") or {}
    ecosystem = pkg.get("ecosystem", "")
    name = pkg.get("name", "")
    if ecosystem and name:
        return f"{ecosystem} {name}"
    return name or ecosystem or "Unknown"


def fetch_ghsa(days_back: int = 7) -> list[CVE]:
    """Fetch recent reviewed advisories from the GitHub Advisory Database.

    Args:
        days_back: Number of days to look back for published advisories.

    Returns:
        List of unsaved CVE model instances.
    """
    token = os.environ.get("GITHUB_TOKEN")
    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=days_back)).strftime("%Y-%m-%d")
    until = now.strftime("%Y-%m-%d")

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    params = {
        "type": "reviewed",
        "published": f"{since}..{until}",
        "per_page": 100,
        "sort": "published",
        "direction": "desc",
    }

    logger.info("Fetching GHSA advisories published since %s...", since)

    cves: list[CVE] = []
    fetched = 0
    max_advisories = 500

    with httpx.Client(timeout=30.0) as client:
        url = GHSA_API_URL
        while url and fetched < max_advisories:
            response = client.get(url, params=params, headers=headers)
            response.raise_for_status()
            advisories = response.json()

            if not advisories:
                break

            for advisory in advisories:
                cve_id = advisory.get("cve_id")
                if not cve_id:
                    continue

                cvss_data = advisory.get("cvss") or {}
                cvss_score = float(cvss_data.get("score", 0) or 0)

                severity_raw = advisory.get("severity", "")
                severity = severity_raw.upper() if severity_raw else _parse_severity(cvss_score)

                summary = advisory.get("summary", "No description available.")
                affected_product = _extract_affected_product(advisory)

                published_str = advisory.get("published_at", "")
                try:
                    date_published = datetime.fromisoformat(
                        published_str.replace("Z", "+00:00")
                    ).date()
                except (ValueError, AttributeError):
                    date_published = date.today()

                source_url = advisory.get("html_url", f"https://nvd.nist.gov/vuln/detail/{cve_id}")

                cves.append(
                    CVE(
                        cve_id=cve_id,
                        description=summary[:2000],
                        cvss_score=cvss_score,
                        severity=severity,
                        affected_product=affected_product[:200],
                        date_published=date_published,
                        source_url=source_url,
                    )
                )
                fetched += 1
                logger.debug("GHSA advisory: %s (%s, CVSS %.1f)", cve_id, severity, cvss_score)

            # Pagination via Link header
            params = {}  # Clear params for subsequent pages (URL contains them)
            link_header = response.headers.get("Link", "")
            url = None
            for part in link_header.split(","):
                if 'rel="next"' in part:
                    url = part.split(";")[0].strip().strip("<>")
                    break

            time.sleep(1.0)

    logger.info("GHSA fetch complete: %d advisories.", len(cves))
    return cves
