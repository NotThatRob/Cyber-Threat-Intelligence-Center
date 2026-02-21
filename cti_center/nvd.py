"""NVD API 2.0 client for fetching recent CVEs."""

import logging
import os
import re
import time
from datetime import date, datetime, timedelta, timezone

import httpx

from cti_center.models import CVE

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
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


def _extract_cvss(metrics: dict) -> tuple[float, str]:
    """Extract CVSS score and severity from NVD metrics object."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key)
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "")
            if not severity:
                severity = _parse_severity(score)
            return float(score), severity.upper()
    return 0.0, "NONE"


def _extract_product(configurations: list) -> str:
    """Best-effort product extraction from CPE configurations."""
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria", "")
                # CPE format: cpe:2.3:a:vendor:product:version:...
                parts = criteria.split(":")
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    return f"{vendor} {product}".replace("_", " ")
    return "Unknown"


# Verbs/phrases that typically follow the product name in NVD descriptions.
_PRODUCT_BOUNDARY = re.compile(
    r"\s+(?:"
    r"(?:is|are)\s+vulnerable"
    r"|allows?"
    r"|enables?"
    r"|permits?"
    r"|could\s+allow"
    r"|has\s+a\b"
    r"|contains?"
    r"|(?:before|through|up\s+to)\s+\d"
    r"|versions?\s"
    r"|(?:in\s+)?all\s+versions"
    r"|ships\s+with"
    r"|discloses?"
    r"|suffers"
    r"|(?:the\s+)?following\s+vulnerability"
    r")",
    re.IGNORECASE,
)

# Prefixes to strip before extracting the product subject.
_SUBJECT_PREFIX = re.compile(
    r"^(?:A\s+|An\s+)?"
    r"(?:vulnerability|issue|flaw|bug|weakness|problem)\s+"
    r"(?:was\s+(?:found|identified|detected|determined)\s+)?in\s+",
    re.IGNORECASE,
)

# CWE-style lead-ins: "Improper Neutralization of ... vulnerability in Product"
_CWE_PREFIX = re.compile(
    r"^[A-Z][A-Za-z\s,'\-()]+?(?:vulnerability|issue)\s+in\s+",
    re.IGNORECASE,
)

# "A flaw has been found in X" / "A vulnerability was identified in X. This ..."
_FLAW_FOUND_IN = re.compile(
    r"^(?:A\s+)?(?:vulnerability|flaw|weakness|bug|issue)\s+"
    r"(?:has\s+been\s+|was\s+)?(?:found|identified|detected|determined|discovered)\s+in\s+"
    r"(.+?)(?:\.\s|\s+that\s|\s+which\s)",
    re.IGNORECASE,
)

# "The X plugin for WordPress" → "WordPress X plugin"
_WORDPRESS_PLUGIN = re.compile(
    r"^The\s+(.+?)\s+plugin\s+for\s+WordPress",
    re.IGNORECASE,
)

# "In the Linux kernel, ..." or "In Product X, ..."
_IN_PREFIX = re.compile(r"^In\s+(?:the\s+)?", re.IGNORECASE)


def _product_from_description(description: str) -> str:
    """Best-effort product extraction from the opening of a CVE description.

    Returns "Unknown" if no product can be identified.
    """
    if not description:
        return "Unknown"

    # WordPress plugins are extremely common and follow a consistent pattern.
    wp = _WORDPRESS_PLUGIN.match(description)
    if wp:
        plugin_name = wp.group(1).strip()
        return f"WordPress {plugin_name}"

    # "A flaw has been found in X." — grab the product before the period.
    flaw_m = _FLAW_FOUND_IN.match(description)
    if flaw_m:
        product = flaw_m.group(1).strip().rstrip(",.")
        if product and 3 <= len(product) <= 80:
            return re.sub(r"\s+", " ", product)

    # Strip CWE-style lead-ins: "Improper ... vulnerability in Product allows"
    text = _CWE_PREFIX.sub("", description)

    # Strip "A vulnerability was found in ..." style prefixes.
    text = _SUBJECT_PREFIX.sub("", text)

    # Strip "In the ..." prefix.
    text = _IN_PREFIX.sub("", text)

    # Find where the product name ends and the vulnerability verb begins.
    m = _PRODUCT_BOUNDARY.search(text)
    if not m:
        return "Unknown"

    product = text[: m.start()].strip().rstrip(",.")
    if not product or len(product) < 3:
        return "Unknown"

    # Clean up common noise.
    product = re.sub(r"\s+", " ", product)

    # Avoid returning the entire first sentence if it's too long.
    if len(product) > 80:
        return "Unknown"

    return product


def _extract_description(descriptions: list) -> str:
    """Extract English description from NVD descriptions list."""
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    if descriptions:
        return descriptions[0].get("value", "")
    return "No description available."


def fetch_cves(days_back: int = 7) -> list[CVE]:
    """Fetch recent CVEs from the NVD API 2.0.

    Args:
        days_back: Number of days to look back for published CVEs.

    Returns:
        List of unsaved CVE model instances.
    """
    api_key = os.environ.get("NVD_API_KEY")
    delay = 0.6 if api_key else 6.0

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days_back)

    # NVD requires ISO 8601 format with no timezone offset
    date_fmt = "%Y-%m-%dT%H:%M:%S.000"
    params = {
        "pubStartDate": start.strftime(date_fmt),
        "pubEndDate": end.strftime(date_fmt),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }

    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key

    cves: list[CVE] = []
    total_results = None

    with httpx.Client(timeout=30.0) as client:
        while True:
            response = client.get(NVD_API_URL, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()

            if total_results is None:
                total_results = data.get("totalResults", 0)
                logger.info("NVD API: %d total CVEs in the last %d days", total_results, days_back)

            for vuln in data.get("vulnerabilities", []):
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")
                if not cve_id:
                    continue

                descriptions = cve_data.get("descriptions", [])
                metrics = cve_data.get("metrics", {})
                configurations = cve_data.get("configurations", [])

                cvss_score, severity = _extract_cvss(metrics)
                description = _extract_description(descriptions)
                affected_product = _extract_product(configurations)
                if affected_product == "Unknown":
                    affected_product = _product_from_description(description)

                published_str = cve_data.get("published", "")
                try:
                    date_published = datetime.fromisoformat(
                        published_str.replace("Z", "+00:00")
                    ).date()
                except (ValueError, AttributeError):
                    date_published = date.today()

                source_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                cves.append(
                    CVE(
                        cve_id=cve_id,
                        description=description[:2000],
                        cvss_score=cvss_score,
                        severity=severity,
                        affected_product=affected_product[:200],
                        date_published=date_published,
                        source_url=source_url,
                    )
                )

            # Pagination
            params["startIndex"] += len(data.get("vulnerabilities", []))
            if params["startIndex"] >= total_results:
                break

            time.sleep(delay)

    return cves
