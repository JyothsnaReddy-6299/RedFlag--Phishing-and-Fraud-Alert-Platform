from datetime import datetime, timezone
import uuid
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Index
from sqlalchemy.orm import relationship
from app.db.session import Base

def generate_report_id() -> str:
    return f"RPT-{datetime.now(timezone.utc).strftime('%Y%m')}-{uuid.uuid4().hex[:6].upper()}"

class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(String(32), unique=True, index=True, default=generate_report_id)
    scam_category = Column(String(64), index=True)
    description = Column(Text, nullable=True)
    raw_message = Column(Text, nullable=True)
    raw_url = Column(String(512), nullable=True)
    phone_number = Column(String(32), nullable=True, index=True)
    upi_id = Column(String(128), nullable=True, index=True)
    organization = Column(String(128), nullable=True, index=True)
    location_city = Column(String(64), nullable=True, index=True)
    location_area = Column(String(128), nullable=True, index=True)
    
    # Status: PENDING, UNDER_REVIEW, VERIFIED, REJECTED
    status = Column(String(32), default="PENDING", index=True)
    reporter_hash = Column(String(64), nullable=True)
    initial_risk_score = Column(Integer, default=0)
    
    verified_by = Column(String(64), nullable=True)
    verification_notes = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True, index=True)
    # PHONE, UPI, URL, DOMAIN
    indicator_type = Column(String(32), index=True)
    indicator_value = Column(String(256), index=True)
    category = Column(String(64), nullable=True)
    # UNCONFIRMED, VERIFIED_MALICIOUS, WHITELISTED
    status = Column(String(32), default="UNCONFIRMED", index=True)
    report_count = Column(Integer, default=1)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_indicator_type_value", "indicator_type", "indicator_value"),
    )

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    action = Column(String(64), index=True)
    actor = Column(String(64), default="SYSTEM")
    target_id = Column(String(64), nullable=True)
    details = Column(Text, nullable=True)
