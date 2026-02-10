from datetime import date
from typing import Optional

from sqlalchemy import String, Float, Date, Text
from sqlalchemy.orm import Mapped, mapped_column

from cti_center.database import Base


class CVE(Base):
    __tablename__ = "cves"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(20), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text)
    cvss_score: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(10))
    affected_product: Mapped[str] = mapped_column(String(200))
    date_published: Mapped[date] = mapped_column(Date)
    source_url: Mapped[str] = mapped_column(String(500))

    # CISA KEV (Known Exploited Vulnerabilities) fields
    kev_date_added: Mapped[Optional[date]] = mapped_column(Date, nullable=True, default=None)
    kev_due_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True, default=None)
    kev_ransomware: Mapped[Optional[str]] = mapped_column(String(20), nullable=True, default=None)
    kev_required_action: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
