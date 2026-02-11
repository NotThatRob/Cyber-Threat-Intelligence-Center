"""Custom risk re-scoring engine.

Blends CVSS, exploit maturity, news velocity, recency, and KEV urgency
into a single 0-100 risk score with human-readable explanations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from cti_center.models import CVE


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


def compute_risk_score(cve: CVE, news_count: int = 0) -> RiskScore:
    """Score a single CVE on a 0-100 scale."""
    factors: list[str] = []
    today = date.today()

    # --- CVSS Base (0-35) ---
    cvss = cve.cvss_score or 0.0
    cvss_component = cvss * 3.5

    # --- Exploit Maturity (0-30) ---
    exploit_component = 0.0
    if cve.kev_date_added is not None:
        exploit_component = 25.0
        factors.append("Actively exploited in the wild (CISA KEV)")
        if cve.kev_ransomware == "Known":
            exploit_component = 30.0
            factors.append("Used in ransomware campaigns")

    # --- News Velocity (0-15) ---
    news_component = min(news_count, 5) * 3.0
    if news_count >= 3:
        factors.append(f"Covered by {news_count} news sources")
    elif news_count > 0:
        factors.append(f"Mentioned in {news_count} news source(s)")

    # --- Recency (0-10) ---
    recency_component = 0.0
    if cve.date_published:
        age = (today - cve.date_published).days
        if age <= 7:
            recency_component = 10.0
        elif age <= 30:
            recency_component = 6.0
        elif age <= 90:
            recency_component = 3.0

    # --- KEV Urgency (0-10) ---
    urgency_component = 0.0
    if cve.kev_due_date is not None:
        days_until = (cve.kev_due_date - today).days
        if days_until < 0:
            urgency_component = 10.0
            factors.append("Federal remediation deadline overdue")
        elif days_until <= 7:
            urgency_component = 8.0
            factors.append(f"Federal remediation due within {days_until} day(s)")
        elif days_until <= 30:
            urgency_component = 5.0
        else:
            urgency_component = 2.0

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


def score_cves(cves: list[CVE], news_counts: dict[str, int]) -> dict[str, RiskScore]:
    """Score a batch of CVEs, returning {cve_id: RiskScore}."""
    return {
        cve.cve_id: compute_risk_score(cve, news_counts.get(cve.cve_id, 0))
        for cve in cves
    }
