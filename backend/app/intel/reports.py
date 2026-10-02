"""Community reporting + moderation (contract sections 15, P1 moderator row).

Duplicate detection compares normalized indicators and message fingerprints.
Moderators approve / merge / reject; only APPROVED reports feed the public
campaign graph. Reports are private by default.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy.orm import Session

from app.intel import db as m, graph

CHANNELS = ("sms", "whatsapp", "email", "call", "social", "web", "qr", "other")


def find_duplicates(session: Session, fingerprint: str,
                    entity_dicts: List[dict], limit: int = 5) -> List[dict]:
    """A new report duplicates an older one when the message template matches
    or a hard indicator is shared."""
    out: dict = {}

    if fingerprint:
        for r in (session.query(m.Report)
                  .filter(m.Report.message_fingerprint == fingerprint)
                  .order_by(m.Report.created_at.desc()).limit(limit).all()):
            out[r.id] = {"report_id": r.id, "reason": "identical message template",
                         "relation": "shares_template", "status": r.status,
                         "campaign_id": r.campaign_id,
                         "created_at": r.created_at.isoformat() if r.created_at else None}

    hashes = [e["canonical_hash"] for e in entity_dicts
              if e["type"] in graph.HARD_INDICATORS]
    if hashes:
        rels = (session.query(m.Relationship)
                .filter(m.Relationship.relation == "mentions",
                        m.Relationship.target_value.in_(hashes))
                .limit(200).all())
        for rel in rels:
            if rel.source_value in out:
                out[rel.source_value]["reason"] += " + shared indicator"
                continue
            r = session.get(m.Report, rel.source_value)
            if not r:
                continue
            out[r.id] = {"report_id": r.id,
                         "reason": f"shared {rel.target_type} indicator",
                         "relation": "same_indicator", "status": r.status,
                         "campaign_id": r.campaign_id,
                         "created_at": r.created_at.isoformat() if r.created_at else None}
    return list(out.values())[:limit]


def create_report(session: Session, *, analysis_id: Optional[str], category: str,
                  channel: str, narrative: str, locality: Optional[str],
                  occurred_at: Optional[datetime], consent: bool,
                  visibility: str, reporter_id: Optional[str],
                  auto_approve: bool = False) -> dict:
    analysis = session.get(m.Analysis, analysis_id) if analysis_id else None
    payload = (analysis.payload or {}) if analysis else {}
    entity_dicts = payload.get("entities", [])
    fingerprint = payload.get("message_fingerprint") or graph.message_fingerprint(narrative or "")
    text = payload.get("input_preview", narrative or "")

    duplicates = find_duplicates(session, fingerprint, entity_dicts)

    report = m.Report(
        id="rep_" + uuid.uuid4().hex[:10],
        analysis_id=analysis_id, reporter_id=reporter_id,
        category=category or payload.get("scam_category") or "unclassified",
        channel=channel if channel in CHANNELS else "other",
        occurred_at=occurred_at, narrative=(narrative or "")[:4000],
        locality=locality, visibility="public" if (consent and visibility == "public") else "private",
        consent=bool(consent),
        status="pending", moderation_state={"queued_at": m.utcnow().isoformat(),
                                            "duplicate_candidates": duplicates},
        message_fingerprint=fingerprint, created_at=m.utcnow(),
    )
    session.add(report)
    session.flush()

    campaign = None
    if auto_approve:
        campaign = approve(session, report.id, entity_dicts=entity_dicts, text=text,
                           language=payload.get("language", "und"))

    session.commit()
    return {
        "report": serialize(report),
        "duplicate_candidates": duplicates,
        "campaign": {"id": campaign.id, "label": campaign.label} if campaign else None,
        "note": ("Your report is queued for moderation. Community reports become shared "
                 "intelligence only after review and corroboration — this is how we "
                 "resist report poisoning."),
    }


def approve(session: Session, report_id: str, entity_dicts: Optional[List[dict]] = None,
            text: str = "", language: str = "und") -> Optional[m.Campaign]:
    report = session.get(m.Report, report_id)
    if report is None:
        return None
    if entity_dicts is None:
        analysis = session.get(m.Analysis, report.analysis_id) if report.analysis_id else None
        payload = (analysis.payload or {}) if analysis else {}
        entity_dicts = payload.get("entities", [])
        text = payload.get("input_preview", report.narrative or "")
        language = payload.get("language", "und")

    report.status = "approved"
    state = dict(report.moderation_state or {})
    state["approved_at"] = m.utcnow().isoformat()
    report.moderation_state = state

    return graph.attach_to_campaign(session, report, entity_dicts or [], text,
                                    report.category or "unclassified", language)


def reject(session: Session, report_id: str, reason: str = "") -> Optional[m.Report]:
    report = session.get(m.Report, report_id)
    if report is None:
        return None
    report.status = "rejected"
    state = dict(report.moderation_state or {})
    state.update({"rejected_at": m.utcnow().isoformat(), "reason": reason})
    report.moderation_state = state
    return report


def merge(session: Session, report_id: str, into_report_id: str) -> Optional[m.Report]:
    report = session.get(m.Report, report_id)
    target = session.get(m.Report, into_report_id)
    if report is None or target is None:
        return None
    report.status = "merged"
    report.duplicate_of = target.id
    report.campaign_id = target.campaign_id
    state = dict(report.moderation_state or {})
    state.update({"merged_at": m.utcnow().isoformat(), "merged_into": target.id})
    report.moderation_state = state

    if target.campaign_id:
        campaign = session.get(m.Campaign, target.campaign_id)
        if campaign:
            campaign.sighting_count = (campaign.sighting_count or 0) + 1
            campaign.last_seen = m.utcnow()
    session.add(m.Relationship(
        source_type="report", source_value=report.id,
        relation="similar_to", target_type="report", target_value=target.id,
    ))
    return report


def set_campaign_status(session: Session, campaign_id: str, status: str) -> Optional[m.Campaign]:
    campaign = session.get(m.Campaign, campaign_id)
    if campaign is None or status not in ("active", "monitoring", "closed"):
        return None
    campaign.status = status
    return campaign


def serialize(report: m.Report, public: bool = False) -> dict:
    data = {
        "id": report.id,
        "analysis_id": report.analysis_id,
        "category": report.category,
        "channel": report.channel,
        "locality": report.locality,
        "status": report.status,
        "visibility": report.visibility,
        "campaign_id": report.campaign_id,
        "duplicate_of": report.duplicate_of,
        "message_fingerprint": (report.message_fingerprint or "")[:12],
        "occurred_at": report.occurred_at.isoformat() if report.occurred_at else None,
        "created_at": report.created_at.isoformat() if report.created_at else None,
    }
    if public:
        # Public feed never exposes the raw narrative.
        data["narrative_excerpt"] = redact(report.narrative or "")
    else:
        data["narrative"] = report.narrative
        data["moderation_state"] = report.moderation_state
    return data


def redact(text: str, length: int = 180) -> str:
    """Mask contact details before anything goes on the public feed."""
    import re
    out = re.sub(r"(?<!\d)([6-9]\d{2})\d{5}(\d{2})(?!\d)", r"\1*****\2", text)
    out = re.sub(r"\b([A-Za-z0-9._%+-]{2})[A-Za-z0-9._%+-]*@", r"\1***@", out)
    out = re.sub(r"\b(\d{4})\d{4,11}(\d{2})\b", r"\1****\2", out)
    return (out[:length] + "…") if len(out) > length else out


def public_feed(session: Session, limit: int = 40, category: Optional[str] = None,
                locality: Optional[str] = None) -> List[dict]:
    q = session.query(m.Report).filter(m.Report.status.in_(["approved", "merged"]),
                                       m.Report.visibility == "public")
    if category:
        q = q.filter(m.Report.category == category)
    if locality:
        q = q.filter(m.Report.locality == locality)
    rows = q.order_by(m.Report.created_at.desc()).limit(limit).all()
    return [serialize(r, public=True) for r in rows]


def evidence_bundle(session: Session, analysis_id: str) -> Optional[dict]:
    """Structured incident summary for official reporting (contract s.5, P1)."""
    analysis = session.get(m.Analysis, analysis_id)
    if analysis is None:
        return None
    payload = analysis.payload or {}
    reports = session.query(m.Report).filter(m.Report.analysis_id == analysis_id).all()
    evid = session.query(m.Evidence).filter(m.Evidence.analysis_id == analysis_id).all()

    return {
        "bundle_version": "1.0",
        "generated_at": m.utcnow().isoformat(),
        "analysis": {
            "analysis_id": analysis.id,
            "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
            "input_type": analysis.input_type,
            "language": analysis.language,
            "verdict": analysis.verdict,
            "risk_score": analysis.risk_score,
            "confidence": analysis.confidence,
            "scam_category": analysis.scam_category,
            "summary": analysis.summary,
            "model_version": analysis.model_version,
        },
        "indicators": [{
            "type": e["type"], "value": e["display_value"],
            "evidence_span": e["raw_value"], "confidence": e["confidence"],
        } for e in payload.get("entities", [])],
        "risk_factors": payload.get("risk_factors", []),
        "red_flags": payload.get("red_flags", []),
        "campaign_links": payload.get("campaign_links", []),
        "evidence": [{
            "type": e.type, "hash": e.hash,
            "value": e.redacted_value, "storage_ref": e.storage_ref,
        } for e in evid],
        "community_reports": [serialize(r) for r in reports],
        "degraded_checks": payload.get("degraded_checks", []),
        "official_reporting": {
            "helpline": "1930 (National Cyber Crime Helpline, India)",
            "portal": "https://cybercrime.gov.in",
            "note": ("Attach the original message/screenshot when you file. This bundle "
                     "is decision support, not a legal determination of fraud."),
        },
        "disclaimer": payload.get("disclaimer", ""),
    }
