"""MITRE CVE Services enrichment client.

Looks up individual CVE records via the public MITRE CVE API to fill
data gaps (e.g., KEV-created records with cvss_score=0.0).
"""

import logging
import time

import httpx
from sqlalchemy.orm import Session

from cti_center.models import CVE

logger = logging.getLogger(__name__)

MITRE_CVE_API = "https://cveawg.mitre.org/api/cve"
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


def _extract_cvss(metrics: list) -> tuple[float, str]:
    """Extract CVSS score from CNA metrics array (CVE 5.x format)."""
    for metric in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV31", "cvssV30", "cvssV4_0", "cvssV40"):
            cvss_data = metric.get(key)
            if cvss_data:
                score = float(cvss_data.get("baseScore", 0))
                if score > 0:
                    severity = cvss_data.get("baseSeverity", "")
                    if not severity:
                        severity = _parse_severity(score)
                    return score, severity.upper()
    return 0.0, "NONE"


def _extract_description(descriptions: list) -> str:
    """Extract English description from CNA descriptions array."""
    for desc in descriptions:
        if desc.get("lang", "").startswith("en"):
            return desc.get("value", "")
    if descriptions:
        return descriptions[0].get("value", "")
    return ""


def _extract_product(affected: list) -> str:
    """Extract vendor + product from CNA affected array."""
    if not affected:
        return ""
    entry = affected[0]
    vendor = entry.get("vendor", "")
    product = entry.get("product", "")
    if vendor and product:
        return f"{vendor} {product}"
    return product or vendor or ""


def fetch_cve_record(cve_id: str) -> dict | None:
    """Fetch a single CVE record from MITRE CVE Services API.

    Returns:
        Dict with cvss_score, severity, description, affected_product,
        or None on failure.
    """
    url = f"{MITRE_CVE_API}/{cve_id}"
    headers = {"User-Agent": USER_AGENT}

    try:
        with httpx.Client(timeout=20.0) as client:
            response = client.get(url, headers=headers)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError):
        return None

    containers = data.get("containers", {})
    cna = containers.get("cna", {})
    if not cna:
        return None

    metrics = cna.get("metrics", [])
    cvss_score, severity = _extract_cvss(metrics)

    descriptions = cna.get("descriptions", [])
    description = _extract_description(descriptions)

    affected = cna.get("affected", [])
    affected_product = _extract_product(affected)

    return {
        "cvss_score": cvss_score,
        "severity": severity,
        "description": description,
        "affected_product": affected_product,
    }


def enrich_cves(db: Session, limit: int = 50) -> tuple[int, int]:
    """Enrich CVEs that have no CVSS score using MITRE CVE data.

    Queries CVEs with cvss_score == 0.0 and attempts to fill in
    CVSS, severity, description, and product info from MITRE.

    Returns:
        Tuple of (enriched_count, failed_count).
    """
    incomplete = db.query(CVE).filter(CVE.cvss_score == 0.0).limit(limit).all()
    logger.info("MITRE enrichment: %d CVEs with missing CVSS data.", len(incomplete))
    enriched = 0
    failed = 0

    for cve in incomplete:
        record = fetch_cve_record(cve.cve_id)
        if record is None:
            logger.warning("MITRE lookup failed for %s.", cve.cve_id)
            failed += 1
            time.sleep(1.0)
            continue

        if record["cvss_score"] > 0:
            cve.cvss_score = record["cvss_score"]
            cve.severity = record["severity"]

        if record["description"] and cve.description in (
            "No description available.",
            "",
        ):
            cve.description = record["description"][:2000]

        if record["affected_product"] and cve.affected_product in ("Unknown", ""):
            cve.affected_product = record["affected_product"][:200]

        logger.debug("Enriched %s: CVSS %.1f %s", cve.cve_id, cve.cvss_score, cve.severity)
        enriched += 1
        time.sleep(1.0)

    if enriched > 0:
        db.commit()

    return enriched, failed
