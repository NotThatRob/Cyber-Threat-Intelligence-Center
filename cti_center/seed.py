"""Create tables and insert sample CVE data."""

import logging
from datetime import date

from cti_center.database import Base, SessionLocal, engine
from cti_center.models import CVE

logger = logging.getLogger(__name__)

SAMPLE_CVES = [
    CVE(
        cve_id="CVE-2024-3094",
        description="Backdoor in xz/liblzma compromising SSH authentication on affected Linux distributions.",
        cvss_score=10.0,
        severity="CRITICAL",
        affected_product="xz-utils",
        date_published=date(2024, 3, 29),
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
    ),
    CVE(
        cve_id="CVE-2024-21887",
        description="Command injection vulnerability in Ivanti Connect Secure and Policy Secure web components.",
        cvss_score=9.1,
        severity="CRITICAL",
        affected_product="Ivanti Connect Secure",
        date_published=date(2024, 1, 10),
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2024-21887",
    ),
    CVE(
        cve_id="CVE-2021-44228",
        description="Remote code execution via crafted JNDI lookup strings in Apache Log4j2.",
        cvss_score=10.0,
        severity="CRITICAL",
        affected_product="Apache Log4j",
        date_published=date(2021, 12, 10),
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    ),
    CVE(
        cve_id="CVE-2024-23222",
        description="Type confusion vulnerability in WebKit allowing arbitrary code execution.",
        cvss_score=8.8,
        severity="HIGH",
        affected_product="Apple Safari / WebKit",
        date_published=date(2024, 1, 22),
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2024-23222",
    ),
    CVE(
        cve_id="CVE-2024-1709",
        description="Authentication bypass in ConnectWise ScreenConnect allowing unauthorized access.",
        cvss_score=10.0,
        severity="CRITICAL",
        affected_product="ConnectWise ScreenConnect",
        date_published=date(2024, 2, 19),
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2024-1709",
    ),
    CVE(
        cve_id="CVE-2023-4966",
        description="Buffer overflow in Citrix NetScaler ADC and Gateway leading to sensitive information disclosure.",
        cvss_score=7.5,
        severity="HIGH",
        affected_product="Citrix NetScaler ADC",
        date_published=date(2023, 10, 10),
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2023-4966",
    ),
    CVE(
        cve_id="CVE-2024-27198",
        description="Authentication bypass in JetBrains TeamCity allowing unauthenticated administrative access.",
        cvss_score=9.8,
        severity="CRITICAL",
        affected_product="JetBrains TeamCity",
        date_published=date(2024, 3, 4),
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2024-27198",
    ),
]


def seed():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(CVE).count() == 0:
            db.add_all(SAMPLE_CVES)
            db.commit()
            logger.info("Seeded %d CVEs.", len(SAMPLE_CVES))
        else:
            logger.info("Database already has data, skipping seed.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
