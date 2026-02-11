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
