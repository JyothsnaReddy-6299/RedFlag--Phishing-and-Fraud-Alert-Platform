"""Persistence layer (contract section 20).

SQLite by default (zero-config demo), PostgreSQL via REDFLAG_DATABASE_URL.
Privacy posture: entities are stored with a canonical HASH as the join key;
raw evidence is stored only on the private `evidence` rows and is never served
through public campaign endpoints.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy import (
    JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text,
    UniqueConstraint, create_engine, Index,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_SQLITE = f"sqlite:///{os.path.join(BASE_DIR, 'redflag.db')}"
DATABASE_URL = os.getenv("REDFLAG_DATABASE_URL", DEFAULT_SQLITE)

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


def utcnow() -> datetime:
    """Naive UTC. SQLite/SQLAlchemy DateTime columns are timezone-naive, so we
    keep one consistent representation and avoid aware/naive comparisons."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"
    id = Column(String(40), primary_key=True)
    role = Column(String(20), default="citizen")        # citizen | moderator | analyst
    display_name = Column(String(80), default="Anonymous")
    consent_flags = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utcnow)


class Analysis(Base):
    __tablename__ = "analyses"
    id = Column(String(40), primary_key=True)
    user_id = Column(String(40), nullable=True)
    input_type = Column(String(16), nullable=False)      # text | url | image | qr
    language = Column(String(12))
    language_label = Column(String(64))
    verdict = Column(String(24))
    risk_score = Column(Integer)
    confidence = Column(Float)
    scam_category = Column(String(48))
    summary = Column(Text)
    model_version = Column(String(48))
    message_fingerprint = Column(String(64), index=True)
    payload = Column(JSON)                               # full canonical result
    created_at = Column(DateTime, default=utcnow, index=True)

    risk_factors = relationship("RiskFactor", back_populates="analysis",
                                cascade="all, delete-orphan")
    links = relationship("AnalysisEntity", back_populates="analysis",
                         cascade="all, delete-orphan")
    evidence_items = relationship("Evidence", back_populates="analysis",
                                  cascade="all, delete-orphan")


class Evidence(Base):
    """Private by default. `redacted_value` is what may be surfaced."""
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String(40), ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    type = Column(String(24))                            # raw_text | ocr_text | url | upload
    redacted_value = Column(Text)
    storage_ref = Column(String(255), nullable=True)
    hash = Column(String(64), index=True)
    is_public = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)

    analysis = relationship("Analysis", back_populates="evidence_items")


class Entity(Base):
    __tablename__ = "entities"
    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String(20), index=True)
    canonical_value_hash = Column(String(64), index=True)
    display_value = Column(String(255))
    report_count = Column(Integer, default=0)
    sighting_count = Column(Integer, default=0)
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)
    campaign_id = Column(String(40), ForeignKey("campaigns.id"), nullable=True)

    __table_args__ = (UniqueConstraint("type", "canonical_value_hash", name="uq_entity"),)


class AnalysisEntity(Base):
    __tablename__ = "analysis_entities"
    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String(40), ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    entity_id = Column(Integer, ForeignKey("entities.id"), index=True)
    confidence = Column(Float, default=0.9)
    evidence_span = Column(Text)

    analysis = relationship("Analysis", back_populates="links")
    entity = relationship("Entity")


class RiskFactor(Base):
    __tablename__ = "risk_factors"
    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String(40), ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    factor = Column(String(64))
    family = Column(String(32))
    weight = Column(Float)
    observed_value = Column(Text)
    evidence_span = Column(Text)
    source = Column(String(32))

    analysis = relationship("Analysis", back_populates="risk_factors")


class Report(Base):
    __tablename__ = "reports"
    id = Column(String(40), primary_key=True)
    analysis_id = Column(String(40), ForeignKey("analyses.id"), nullable=True, index=True)
    reporter_id = Column(String(40), nullable=True)
    category = Column(String(48))
    channel = Column(String(24))                         # sms | whatsapp | email | call | social | web
    occurred_at = Column(DateTime, nullable=True)
    narrative = Column(Text)
    locality = Column(String(80), nullable=True)
    visibility = Column(String(16), default="private")   # private | public
    consent = Column(Boolean, default=False)
    status = Column(String(20), default="pending")       # pending | approved | rejected | merged
    moderation_state = Column(JSON, default=dict)
    duplicate_of = Column(String(40), nullable=True)
    campaign_id = Column(String(40), ForeignKey("campaigns.id"), nullable=True, index=True)
    message_fingerprint = Column(String(64), index=True)
    created_at = Column(DateTime, default=utcnow, index=True)


class Relationship(Base):
    __tablename__ = "relationships"
    id = Column(Integer, primary_key=True, autoincrement=True)
    source_type = Column(String(20))
    source_value = Column(String(255))
    relation = Column(String(32))     # reported_in | mentions | redirects_to | similar_to
                                      # | shares_template | same_indicator
    target_type = Column(String(20))
    target_value = Column(String(255))
    evidence_id = Column(Integer, nullable=True)
    weight = Column(Float, default=1.0)
    created_at = Column(DateTime, default=utcnow)


Index("ix_rel_source", Relationship.source_type, Relationship.source_value)
Index("ix_rel_target", Relationship.target_type, Relationship.target_value)


class Campaign(Base):
    __tablename__ = "campaigns"
    id = Column(String(40), primary_key=True)
    label = Column(String(140))
    description = Column(Text, nullable=True)
    score = Column(Integer, default=0)
    status = Column(String(20), default="active")        # active | monitoring | closed
    primary_category = Column(String(48), nullable=True)
    languages = Column(JSON, default=list)
    report_count = Column(Integer, default=0)
    sighting_count = Column(Integer, default=0)
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
