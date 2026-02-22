"""Shared utility functions used across data-source clients."""


def parse_severity(cvss_score: float) -> str:
    """Map a CVSS score to a severity label (CRITICAL/HIGH/MEDIUM/LOW/NONE)."""
    if cvss_score >= 9.0:
        return "CRITICAL"
    if cvss_score >= 7.0:
        return "HIGH"
    if cvss_score >= 4.0:
        return "MEDIUM"
    if cvss_score > 0:
        return "LOW"
    return "NONE"
