"""Custom risk re-scoring engine.

Blends CVSS, exploit maturity, news velocity, recency, and KEV urgency
into a single 0-100 risk score with human-readable explanations.

Weights are configurable via ``RISK_WEIGHTS``.  Each weight defines the
maximum number of points its component can contribute to the 0-100 score.
The defaults sum to 100 but any combination that sums to 100 is valid.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from cti_center.models import CVE


def parse_attack_vector(cvss_vector: str | None) -> str | None:
    """Extract the Attack Vector metric from a CVSS v3.x vector string.

    Returns one of 'N' (Network), 'A' (Adjacent), 'L' (Local), 'P' (Physical),
    or None if the vector is missing or unparseable.
    """
    if not cvss_vector:
        return None
    for part in cvss_vector.split("/"):
        if part.startswith("AV:"):
            return part[3:]
    return None


# ---------------------------------------------------------------------------
# Configurable weights — edit these to shift scoring priorities.
# Each value is the max points that component can contribute (must sum to 100).
# ---------------------------------------------------------------------------
RISK_WEIGHTS: dict[str, float] = {
    "cvss":    35,   # Raw CVSS v3 score mapped proportionally
    "exploit": 30,   # CISA KEV listing + ransomware indicator
    "news":    15,   # Number of news sources covering the CVE
    "recency": 10,   # How recently the CVE was published
    "urgency": 10,   # Proximity to federal remediation deadline
}


@dataclass
class RiskScore:
    score: int
    factors: list[str] = field(default_factory=list)
    cvss_component: float = 0.0
    exploit_component: float = 0.0
    news_component: float = 0.0
    recency_component: float = 0.0
    urgency_component: float = 0.0
    highlighted: bool = False
    why_it_matters: str = ""

    @property
    def label(self) -> str:
        if self.score >= 75:
            return "critical"
        if self.score >= 50:
            return "high"
        if self.score >= 25:
            return "medium"
        return "low"


def compute_risk_score(
    cve: CVE,
    news_count: int = 0,
    weights: dict[str, float] | None = None,
) -> RiskScore:
    """Score a single CVE on a 0-100 scale.

    Args:
        cve: The CVE model instance to score.
        news_count: Number of linked news articles.
        weights: Optional override for ``RISK_WEIGHTS``.
    """
    w = weights or RISK_WEIGHTS
    factors: list[str] = []
    today = date.today()

    # Rejected CVEs get a score of 0.
    if cve.description and cve.description.startswith("Rejected reason:"):
        return RiskScore(score=0, factors=["CVE rejected by NVD"])

    # --- CVSS Base (0-w["cvss"]) ---
    cvss = cve.cvss_score or 0.0
    cvss_component = cvss * (w["cvss"] / 10.0)

    # --- Exploit Maturity (0-w["exploit"]) ---
    exploit_component = 0.0
    if cve.kev_date_added is not None:
        exploit_component = w["exploit"] * (25.0 / 30.0)
        factors.append("Actively exploited in the wild (CISA KEV)")
        if cve.kev_ransomware == "Known":
            exploit_component = w["exploit"]
            factors.append("Used in ransomware campaigns")

    # --- News Velocity (0-w["news"]) ---
    news_component = min(news_count, 5) * (w["news"] / 5.0)
    if news_count >= 3:
        factors.append(f"Covered by {news_count} news sources")
    elif news_count > 0:
        factors.append(f"Mentioned in {news_count} news source(s)")

    # --- Recency (0-w["recency"]) ---
    recency_component = 0.0
    if cve.date_published:
        age = (today - cve.date_published).days
        if age <= 7:
            recency_component = w["recency"]
        elif age <= 30:
            recency_component = w["recency"] * 0.6
        elif age <= 90:
            recency_component = w["recency"] * 0.3

    # --- KEV Urgency (0-w["urgency"]) ---
    urgency_component = 0.0
    if cve.kev_due_date is not None:
        days_until = (cve.kev_due_date - today).days
        if days_until < 0:
            urgency_component = w["urgency"]
            factors.append("Federal remediation deadline overdue")
        elif days_until <= 7:
            urgency_component = w["urgency"] * 0.8
            factors.append(f"Federal remediation due within {days_until} day(s)")
        elif days_until <= 30:
            urgency_component = w["urgency"] * 0.5
        else:
            urgency_component = w["urgency"] * 0.2

    # --- Composite score ---
    raw = cvss_component + exploit_component + news_component + recency_component + urgency_component
    score = min(int(round(raw)), 100)

    # --- Highlighting logic ---
    attack_vector = parse_attack_vector(cve.cvss_vector)
    is_network = attack_vector == "N"
    is_high_cvss_network = cvss >= 7.0 and is_network
    is_exploited = cve.kev_date_added is not None
    is_multi_news = news_count >= 2

    if is_high_cvss_network:
        factors.append("Remotely exploitable over the network (AV:N)")

    highlighted = is_high_cvss_network or is_exploited or is_multi_news

    why_it_matters = ""
    if highlighted:
        if cvss >= 9.0:
            sev = "Critical"
        elif cvss >= 7.0:
            sev = "High-severity"
        else:
            sev = "Notable"

        parts: list[str] = []
        if is_network:
            parts.append("remotely exploitable")
        if is_exploited and cve.kev_ransomware == "Known":
            parts.append("actively exploited in ransomware campaigns")
        elif is_exploited:
            parts.append("actively exploited in the wild")
        if is_multi_news:
            parts.append(f"covered by {news_count} news sources")

        if is_exploited:
            if cve.kev_due_date and (cve.kev_due_date - today).days <= 7:
                action = "remediate before federal deadline"
            else:
                action = "patch immediately"
        elif is_high_cvss_network:
            action = "assess exposure urgently"
        else:
            action = "monitor and assess"

        description = ", ".join(parts)
        why_it_matters = f"{sev} vuln {description} \u2014 {action}"

    # Discrepancy callouts
    if cvss >= 7.0 and cve.kev_date_added is None and news_count == 0:
        factors.append("High CVSS but no real-world exploitation observed")
    if cvss < 7.0 and cve.kev_date_added is not None:
        factors.append("Low CVSS but actively exploited — real-world risk exceeds base score")

    return RiskScore(
        score=score,
        factors=factors,
        cvss_component=cvss_component,
        exploit_component=exploit_component,
        news_component=news_component,
        recency_component=recency_component,
        urgency_component=urgency_component,
        highlighted=highlighted,
        why_it_matters=why_it_matters,
    )


def score_cves(
    cves: list[CVE],
    news_counts: dict[str, int],
    weights: dict[str, float] | None = None,
) -> dict[str, RiskScore]:
    """Score a batch of CVEs, returning {cve_id: RiskScore}."""
    return {
        cve.cve_id: compute_risk_score(cve, news_counts.get(cve.cve_id, 0), weights)
        for cve in cves
    }
