"""Threat intelligence & campaign graph (contract sections 16, 17).

Deterministic by design for the 24-hour MVP: two observations belong to the
same campaign when they share a hard indicator (domain / phone / UPI / handle)
or when their message fingerprints are highly similar. Explainability beats
algorithmic complexity here — every edge records WHY it exists.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.intel import db as m

# Indicator types strong enough to merge campaigns on their own.
HARD_INDICATORS = ("domain", "phone", "upi", "handle", "email", "ifsc")

_WORD = re.compile(r"[a-z\u0B80-\u0BFF]{3,}")
_VOLATILE = re.compile(r"\d+|https?://\S+|www\.\S+", re.I)


def message_fingerprint(text: str) -> str:
    """Template fingerprint: digits and URLs removed so that the same scam
    template with a rotated link/amount still collides."""
    skeleton = _VOLATILE.sub(" ", (text or "").lower())
    tokens = sorted(set(_WORD.findall(skeleton)))
    return hashlib.sha256(" ".join(tokens).encode()).hexdigest()[:32]


def shingles(text: str, n: int = 3) -> set:
    toks = _WORD.findall(_VOLATILE.sub(" ", (text or "").lower()))
    if len(toks) < n:
        return set(toks)
    return {" ".join(toks[i:i + n]) for i in range(len(toks) - n + 1)}


def jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


# ---------------------------------------------------------------------------
# Entity registry
# ---------------------------------------------------------------------------
def upsert_entity(session: Session, etype: str, canonical_hash: str,
                  display: str, when: Optional[datetime] = None,
                  as_report: bool = False) -> m.Entity:
    when = when or m.utcnow()
    ent = (session.query(m.Entity)
           .filter(m.Entity.type == etype,
                   m.Entity.canonical_value_hash == canonical_hash)
           .one_or_none())
    if ent is None:
        ent = m.Entity(type=etype, canonical_value_hash=canonical_hash,
                       display_value=display, first_seen=when, last_seen=when,
                       sighting_count=0, report_count=0)
        session.add(ent)
        session.flush()
    ent.last_seen = max(ent.last_seen or when, when)
    ent.sighting_count = (ent.sighting_count or 0) + 1
    if as_report:
        ent.report_count = (ent.report_count or 0) + 1
    return ent


def entity_reputation(session: Session, entities: Iterable[dict]) -> List[dict]:
    """Prior-sighting lookup for the scoring engine.

    Only entities with a confirmed REPORT history count as reputation; a mere
    previous scan is informational, because scans are unverified user input.
    """
    out: List[dict] = []
    for e in entities:
        if e["type"] not in HARD_INDICATORS:
            continue
        row = (session.query(m.Entity)
               .filter(m.Entity.type == e["type"],
                       m.Entity.canonical_value_hash == e["canonical_hash"])
               .one_or_none())
        if row is None:
            continue
        if (row.report_count or 0) <= 0 and (row.sighting_count or 0) <= 1:
            continue
        out.append({
            "type": e["type"],
            "display_value": row.display_value,
            "canonical_hash": row.canonical_hash if hasattr(row, "canonical_hash") else row.canonical_value_hash,
            "report_count": row.report_count or 0,
            "sighting_count": row.sighting_count or 0,
            "first_seen": row.first_seen.isoformat() if row.first_seen else None,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            "campaign_id": row.campaign_id,
            "evidence_span": e.get("raw_value", ""),
        })
    return out


# ---------------------------------------------------------------------------
# Campaign correlation
# ---------------------------------------------------------------------------
def find_campaign_links(session: Session, entities: List[dict],
                        fingerprint: str, text: str,
                        exclude_analysis_id: Optional[str] = None) -> List[dict]:
    """Return the campaigns this observation plausibly belongs to, with the
    exact reason for each link."""
    links: Dict[str, dict] = {}

    # (a) shared hard indicator already attached to a campaign
    for e in entities:
        if e["type"] not in HARD_INDICATORS:
            continue
        row = (session.query(m.Entity)
               .filter(m.Entity.type == e["type"],
                       m.Entity.canonical_value_hash == e["canonical_hash"],
                       m.Entity.campaign_id.isnot(None))
               .one_or_none())
        if row and row.campaign_id:
            link = links.setdefault(row.campaign_id, {
                "campaign_id": row.campaign_id, "reasons": [], "strength": 0.0,
            })
            link["reasons"].append({
                "relation": "same_indicator",
                "indicator_type": e["type"],
                "indicator": row.display_value,
                "evidence_span": e.get("raw_value", ""),
            })
            link["strength"] = min(1.0, link["strength"] + 0.5)

    # (b) identical or near-identical message template
    if fingerprint:
        rows = (session.query(m.Analysis)
                .filter(m.Analysis.message_fingerprint == fingerprint)
                .limit(50).all())
        mine = shingles(text)
        for row in rows:
            if exclude_analysis_id and row.id == exclude_analysis_id:
                continue
            rep = (session.query(m.Report)
                   .filter(m.Report.analysis_id == row.id,
                           m.Report.campaign_id.isnot(None))
                   .first())
            cid = rep.campaign_id if rep else None
            if not cid:
                continue
            other = shingles((row.payload or {}).get("input_preview", ""))
            sim = jaccard(mine, other) if other else 1.0
            link = links.setdefault(cid, {"campaign_id": cid, "reasons": [], "strength": 0.0})
            link["reasons"].append({
                "relation": "shares_template",
                "indicator_type": "message_fingerprint",
                "indicator": fingerprint[:12],
                "similarity": round(sim, 2),
            })
            link["strength"] = min(1.0, link["strength"] + 0.4)

    # Decorate with campaign metadata
    out: List[dict] = []
    for cid, link in links.items():
        c = session.get(m.Campaign, cid)
        if not c:
            continue
        out.append({
            **link,
            "label": c.label,
            "status": c.status,
            "primary_category": c.primary_category,
            "report_count": c.report_count,
            "first_seen": c.first_seen.isoformat() if c.first_seen else None,
            "last_seen": c.last_seen.isoformat() if c.last_seen else None,
        })
    return sorted(out, key=lambda x: -x["strength"])


def attach_to_campaign(session: Session, report: m.Report, entities: List[dict],
                       text: str, category: str, language: str) -> m.Campaign:
    """Attach an approved report to an existing campaign or open a new one."""
    links = find_campaign_links(session, entities, report.message_fingerprint or "", text)
    if links:
        campaign = session.get(m.Campaign, links[0]["campaign_id"])
    else:
        campaign = None

    if campaign is None:
        indicator = next((e for e in entities if e["type"] in ("domain", "upi", "phone")), None)
        hint = indicator["display_value"] if indicator else (category or "unclassified")
        campaign = m.Campaign(
            id="camp_" + uuid.uuid4().hex[:10],
            label=f"{_pretty(category)} cluster — {hint}",
            description="Auto-opened from a moderated community report.",
            primary_category=category, status="monitoring",
            languages=[language], report_count=0, sighting_count=0,
            first_seen=m.utcnow(), last_seen=m.utcnow(),
        )
        session.add(campaign)
        session.flush()

    report.campaign_id = campaign.id
    campaign.report_count = (campaign.report_count or 0) + 1
    campaign.sighting_count = (campaign.sighting_count or 0) + 1
    campaign.last_seen = m.utcnow()
    langs = set(campaign.languages or [])
    langs.add(language)
    campaign.languages = sorted(langs)
    if (campaign.report_count or 0) >= 3 and campaign.status == "monitoring":
        campaign.status = "active"
    campaign.score = min(100, 25 + 15 * (campaign.report_count or 0))

    # Bind indicators to the campaign and record graph edges.
    for e in entities:
        if e["type"] not in HARD_INDICATORS:
            continue
        ent = upsert_entity(session, e["type"], e["canonical_hash"],
                            e["display_value"], as_report=True)
        if ent.campaign_id is None:
            ent.campaign_id = campaign.id
        session.add(m.Relationship(
            source_type="report", source_value=report.id,
            relation="mentions", target_type=e["type"],
            target_value=e["canonical_hash"], weight=1.0,
        ))
        session.add(m.Relationship(
            source_type=e["type"], source_value=e["canonical_hash"],
            relation="reported_in", target_type="campaign",
            target_value=campaign.id, weight=1.0,
        ))
    if report.message_fingerprint:
        session.add(m.Relationship(
            source_type="message_fingerprint", source_value=report.message_fingerprint,
            relation="shares_template", target_type="campaign",
            target_value=campaign.id, weight=1.0,
        ))
    return campaign


def _pretty(category: Optional[str]) -> str:
    return (category or "unclassified").replace("_", " ").title()


# ---------------------------------------------------------------------------
# Graph & analytics views
# ---------------------------------------------------------------------------
def campaign_graph(session: Session, campaign_id: str) -> dict:
    """Nodes/edges for the campaign view. Only normalized indicators are
    exposed — never raw private narratives."""
    campaign = session.get(m.Campaign, campaign_id)
    if not campaign:
        return {}

    reports = (session.query(m.Report)
               .filter(m.Report.campaign_id == campaign_id,
                       m.Report.status.in_(["approved", "merged"]))
               .order_by(m.Report.created_at).all())
    report_ids = [r.id for r in reports]

    nodes: List[dict] = [{
        "id": campaign.id, "type": "campaign", "label": campaign.label,
        "status": campaign.status, "size": 26,
    }]
    edges: List[dict] = []

    for r in reports:
        nodes.append({
            "id": r.id, "type": "report",
            "label": f"Report {r.id[-6:]}",
            "category": r.category, "locality": r.locality,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "size": 12,
        })
        edges.append({"source": r.id, "target": campaign.id,
                      "relation": "reported_in"})

    rels = (session.query(m.Relationship)
            .filter(m.Relationship.source_type == "report",
                    m.Relationship.source_value.in_(report_ids or [""]),
                    m.Relationship.relation == "mentions").all())

    indicator_reports: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for rel in rels:
        indicator_reports[(rel.target_type, rel.target_value)].append(rel.source_value)

    for (etype, ehash), rids in indicator_reports.items():
        ent = (session.query(m.Entity)
               .filter(m.Entity.type == etype,
                       m.Entity.canonical_value_hash == ehash).one_or_none())
        if not ent:
            continue
        nid = f"{etype}:{ehash[:10]}"
        nodes.append({
            "id": nid, "type": etype, "label": ent.display_value,
            "report_count": ent.report_count, "shared_by": len(set(rids)),
            "first_seen": ent.first_seen.isoformat() if ent.first_seen else None,
            "last_seen": ent.last_seen.isoformat() if ent.last_seen else None,
            "size": 10 + 4 * min(5, len(set(rids))),
        })
        for rid in set(rids):
            edges.append({"source": rid, "target": nid, "relation": "mentions"})
        if len(set(rids)) > 1:
            edges.append({"source": nid, "target": campaign.id,
                          "relation": "same_indicator",
                          "note": f"shared by {len(set(rids))} reports"})

    timeline = [{
        "report_id": r.id,
        "at": r.created_at.isoformat() if r.created_at else None,
        "category": r.category, "channel": r.channel, "locality": r.locality,
    } for r in reports]

    shared = [n for n in nodes if n.get("shared_by", 0) > 1]
    domains = [n for n in nodes if n["type"] == "domain"]

    return {
        "campaign": {
            "id": campaign.id, "label": campaign.label,
            "description": campaign.description, "status": campaign.status,
            "score": campaign.score, "primary_category": campaign.primary_category,
            "languages": campaign.languages or [],
            "report_count": campaign.report_count,
            "first_seen": campaign.first_seen.isoformat() if campaign.first_seen else None,
            "last_seen": campaign.last_seen.isoformat() if campaign.last_seen else None,
        },
        "nodes": nodes,
        "edges": edges,
        "timeline": timeline,
        "shared_indicators": sorted(shared, key=lambda n: -n["shared_by"]),
        "infrastructure_rotation": {
            "distinct_domains": len(domains),
            "detected": len(domains) > 1,
            "note": ("Multiple domains are connected to this campaign — consistent with "
                     "infrastructure rotation. Shared infrastructure is evidence of "
                     "overlap, not proof of identical actors.")
            if len(domains) > 1 else "Single domain observed so far.",
        },
    }


def threat_pulse(session: Session, days: int = 14) -> dict:
    """Counts, trends, top indicators and emerging campaigns (section 17)."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    reports = (session.query(m.Report)
               .filter(m.Report.created_at >= since.replace(tzinfo=None)).all())
    analyses = (session.query(m.Analysis)
                .filter(m.Analysis.created_at >= since.replace(tzinfo=None)).all())

    by_day: Counter = Counter()
    for r in reports:
        if r.created_at:
            by_day[r.created_at.date().isoformat()] += 1

    cats = Counter(r.category for r in reports if r.category)
    langs = Counter(a.language for a in analyses if a.language)
    locs = Counter(r.locality for r in reports if r.locality)
    verdicts = Counter(a.verdict for a in analyses if a.verdict)

    top_entities = (session.query(m.Entity)
                    .filter(m.Entity.report_count > 0)
                    .order_by(m.Entity.report_count.desc())
                    .limit(12).all())

    campaigns = session.query(m.Campaign).all()
    emerging = sorted(
        campaigns,
        key=lambda c: ((c.report_count or 0), c.last_seen or datetime.min),
        reverse=True,
    )[:6]

    return {
        "window_days": days,
        "totals": {
            "analyses": len(analyses),
            "reports": len(reports),
            "approved_reports": sum(1 for r in reports if r.status == "approved"),
            "pending_reports": sum(1 for r in reports if r.status == "pending"),
            "campaigns": len(campaigns),
            "tracked_indicators": session.query(m.Entity).count(),
        },
        "reports_by_day": [{"date": d, "count": c} for d, c in sorted(by_day.items())],
        "by_category": [{"key": k, "label": _pretty(k), "count": v} for k, v in cats.most_common()],
        "by_language": [{"key": k, "count": v} for k, v in langs.most_common()],
        "by_locality": [{"key": k, "count": v} for k, v in locs.most_common(8)],
        "by_verdict": [{"key": k, "count": v} for k, v in verdicts.most_common()],
        "top_indicators": [{
            "type": e.type, "display_value": e.display_value,
            "report_count": e.report_count, "sighting_count": e.sighting_count,
            "first_seen": e.first_seen.isoformat() if e.first_seen else None,
            "last_seen": e.last_seen.isoformat() if e.last_seen else None,
            "campaign_id": e.campaign_id,
        } for e in top_entities],
        "emerging_campaigns": [{
            "id": c.id, "label": c.label, "status": c.status,
            "report_count": c.report_count, "score": c.score,
            "primary_category": c.primary_category,
            "last_seen": c.last_seen.isoformat() if c.last_seen else None,
        } for c in emerging],
    }
