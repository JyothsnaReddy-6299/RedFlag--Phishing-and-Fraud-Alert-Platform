"""RedFlag Intelligence API (contract section 21).

POST /api/analyze/text | /url | /image | /qr
GET  /api/analysis/{id}            GET /api/analysis/{id}/evidence
POST /api/reports                  GET /api/reports/queue
POST /api/reports/{id}/approve|reject|merge
GET  /api/feed
GET  /api/entities/{type}/{value}
GET  /api/campaigns                GET /api/campaigns/{id}
POST /api/campaigns/{id}/status
GET  /api/pulse                    GET /api/health
GET  /api/meta
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.intel import MODEL_VERSION, adapters, analyzer, classifier, graph, reports
from app.intel import db as m
from app.intel.entities import BRANDS, host_of
from app.intel.intent import SCAM_CLASSES

router = APIRouter()

MAX_TEXT = 8000


# ---------------------------------------------------------------------------
# Request models (input validation = security basics, contract s.19)
# ---------------------------------------------------------------------------
class TextAnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=MAX_TEXT, json_schema_extra={
        "example": "Dear SBI customer, unga account KYC kaalavadhi mudinjiduchu. "
                   "Udane http://sbi-kyc-verify.xyz/login la update pannunga illana "
                   "account block aagidum."})
    sender_id: Optional[str] = Field(None, max_length=40)
    user_id: Optional[str] = Field(None, max_length=40)

    @field_validator("text")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Message text cannot be empty.")
        return v


class UrlAnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, json_schema_extra={
        "example": "http://sbi-kyc-update-portal.xyz/login"})
    context: Optional[str] = Field(None, max_length=MAX_TEXT)
    user_id: Optional[str] = Field(None, max_length=40)

    @field_validator("url")
    @classmethod
    def _check(cls, v: str) -> str:
        v = v.strip()
        if any(v.lower().startswith(s) for s in
               ("javascript:", "data:", "file:", "vbscript:")):
            raise ValueError("Unsupported URL scheme.")
        if not host_of(v) or "." not in host_of(v):
            raise ValueError("That does not look like a URL.")
        return v


class ReportRequest(BaseModel):
    analysis_id: Optional[str] = Field(None, max_length=40)
    category: str = Field("unclassified", max_length=48)
    channel: str = Field("sms", max_length=16)
    narrative: str = Field("", max_length=4000)
    locality: Optional[str] = Field(None, max_length=80)
    occurred_at: Optional[datetime] = None
    consent: bool = False
    visibility: str = Field("private", pattern="^(private|public)$")
    reporter_id: Optional[str] = Field(None, max_length=40)


class MergeRequest(BaseModel):
    into_report_id: str = Field(..., max_length=40)


class StatusRequest(BaseModel):
    status: str = Field(..., pattern="^(active|monitoring|closed)$")


class RejectRequest(BaseModel):
    reason: str = Field("", max_length=500)


# ---------------------------------------------------------------------------
# Analyze
# ---------------------------------------------------------------------------
@router.post("/analyze/text", tags=["Analyze"], summary="Analyze a message (Tamil/English/Tanglish)")
def analyze_text(req: TextAnalyzeRequest, db: Session = Depends(m.get_session)):
    return analyzer.analyze(req.text, input_type="text", sender_id=req.sender_id,
                            session=db, user_id=req.user_id)


@router.post("/analyze/url", tags=["Analyze"], summary="Analyze a URL")
def analyze_url(req: UrlAnalyzeRequest, db: Session = Depends(m.get_session)):
    text = (req.context or "").strip()
    combined = f"{text}\n{req.url}".strip() if text else req.url
    return analyzer.analyze(combined, input_type="url", session=db,
                            extra_urls=[req.url], user_id=req.user_id)


@router.post("/analyze/image", tags=["Analyze"],
             summary="OCR a screenshot, then run the same pipeline")
async def analyze_image(file: UploadFile = File(...),
                        sender_id: Optional[str] = Form(None),
                        text_override: Optional[str] = Form(None),
                        db: Session = Depends(m.get_session)):
    data = await file.read()
    err = adapters.validate_upload(file.content_type, len(data))
    if err:
        raise HTTPException(status_code=400, detail=err)
    if not adapters.sniff_is_image(data):
        raise HTTPException(status_code=400,
                            detail="File content does not match an allowed image format.")

    ocr = adapters.run_ocr(data)
    qr = adapters.decode_qr(data)
    ocr_dict, qr_dict = ocr.to_dict(), qr.to_dict()

    # The user can always correct OCR output before analysis.
    text = (text_override or "").strip() or ocr.text
    extra = [p["data"] for p in qr.payloads if p.get("looks_like_url")]

    if not text and not extra:
        return JSONResponse(status_code=200, content={
            "analysis_id": None,
            "needs_input": True,
            "ocr": ocr_dict, "qr": qr_dict,
            "message": ("No text could be extracted from this image. Type or paste the "
                        "message content and submit again — nothing is ever invented to "
                        "fill the gap."),
        })

    result = analyzer.analyze(text or extra[0], input_type="image", sender_id=sender_id,
                              session=db, ocr=ocr_dict, qr=qr_dict, extra_urls=extra)
    if text_override:
        result["ocr"]["user_corrected"] = True
    return result


@router.post("/analyze/qr", tags=["Analyze"],
             summary="Decode a QR locally, show the destination, then analyze it")
async def analyze_qr(file: UploadFile = File(...), db: Session = Depends(m.get_session)):
    data = await file.read()
    err = adapters.validate_upload(file.content_type, len(data))
    if err:
        raise HTTPException(status_code=400, detail=err)
    if not adapters.sniff_is_image(data):
        raise HTTPException(status_code=400,
                            detail="File content does not match an allowed image format.")

    qr = adapters.decode_qr(data)
    qr_dict = qr.to_dict()
    if not qr.payloads:
        return JSONResponse(status_code=200, content={
            "analysis_id": None, "needs_input": True, "qr": qr_dict,
            "message": qr.reason or "No QR code found in this image.",
        })

    payloads = [p["data"] for p in qr.payloads]
    urls = [p["data"] for p in qr.payloads if p.get("looks_like_url")]
    result = analyzer.analyze("\n".join(payloads), input_type="qr", session=db,
                              qr=qr_dict, extra_urls=urls)
    result["qr_destination_preview"] = payloads
    return result


@router.get("/analysis/{analysis_id}", tags=["Analyze"])
def get_analysis(analysis_id: str, db: Session = Depends(m.get_session)):
    row = db.get(m.Analysis, analysis_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return row.payload


@router.get("/analysis/{analysis_id}/evidence", tags=["Analyze"],
            summary="Structured evidence bundle for official reporting")
def get_evidence(analysis_id: str, db: Session = Depends(m.get_session)):
    bundle = reports.evidence_bundle(db, analysis_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return bundle


# ---------------------------------------------------------------------------
# Community reporting + moderation
# ---------------------------------------------------------------------------
@router.post("/reports", tags=["Community"])
def submit_report(req: ReportRequest,
                  auto_approve: bool = Query(False, description="Demo convenience: "
                                             "skip the moderation queue."),
                  db: Session = Depends(m.get_session)):
    if req.analysis_id and db.get(m.Analysis, req.analysis_id) is None:
        raise HTTPException(status_code=404, detail="Referenced analysis not found.")
    return reports.create_report(
        db, analysis_id=req.analysis_id, category=req.category, channel=req.channel,
        narrative=req.narrative, locality=req.locality, occurred_at=req.occurred_at,
        consent=req.consent, visibility=req.visibility, reporter_id=req.reporter_id,
        auto_approve=auto_approve)


@router.get("/reports/queue", tags=["Moderation"])
def moderation_queue(status: str = Query("pending"), limit: int = Query(50, le=200),
                     db: Session = Depends(m.get_session)):
    q = db.query(m.Report)
    if status != "all":
        q = q.filter(m.Report.status == status)
    rows = q.order_by(m.Report.created_at.desc()).limit(limit).all()
    return {"count": len(rows), "reports": [reports.serialize(r) for r in rows]}


@router.post("/reports/{report_id}/approve", tags=["Moderation"])
def approve_report(report_id: str, db: Session = Depends(m.get_session)):
    campaign = reports.approve(db, report_id)
    if campaign is None and db.get(m.Report, report_id) is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    db.commit()
    row = db.get(m.Report, report_id)
    return {"report": reports.serialize(row),
            "campaign": {"id": campaign.id, "label": campaign.label,
                         "status": campaign.status,
                         "report_count": campaign.report_count} if campaign else None}


@router.post("/reports/{report_id}/reject", tags=["Moderation"])
def reject_report(report_id: str, req: RejectRequest,
                  db: Session = Depends(m.get_session)):
    row = reports.reject(db, report_id, req.reason)
    if row is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    db.commit()
    return {"report": reports.serialize(row)}


@router.post("/reports/{report_id}/merge", tags=["Moderation"])
def merge_report(report_id: str, req: MergeRequest,
                 db: Session = Depends(m.get_session)):
    row = reports.merge(db, report_id, req.into_report_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    db.commit()
    return {"report": reports.serialize(row)}


@router.get("/feed", tags=["Community"], summary="Moderated public community feed")
def feed(limit: int = Query(40, le=100), category: Optional[str] = None,
         locality: Optional[str] = None, db: Session = Depends(m.get_session)):
    rows = reports.public_feed(db, limit=limit, category=category, locality=locality)
    return {"count": len(rows), "reports": rows,
            "note": "Only moderated reports with reporter consent appear here, and "
                    "contact details are masked."}


# ---------------------------------------------------------------------------
# Entities & campaigns
# ---------------------------------------------------------------------------
@router.get("/entities/{entity_type}/{value}", tags=["Intelligence"])
def entity_lookup(entity_type: str, value: str, db: Session = Depends(m.get_session)):
    """`value` may be the canonical hash or the display value."""
    q = db.query(m.Entity).filter(m.Entity.type == entity_type)
    row = (q.filter(m.Entity.canonical_value_hash == value).one_or_none()
           or q.filter(m.Entity.display_value == value).first())
    if row is None:
        return {"found": False, "type": entity_type, "query": value,
                "note": "This indicator has not been seen by RedFlag yet."}

    rels = (db.query(m.Relationship)
            .filter(m.Relationship.target_value == row.canonical_value_hash,
                    m.Relationship.relation == "mentions").all())
    report_ids = [r.source_value for r in rels]
    rows = (db.query(m.Report).filter(m.Report.id.in_(report_ids or [""]),
                                      m.Report.status.in_(["approved", "merged"])).all())
    return {
        "found": True,
        "entity": {
            "type": row.type, "display_value": row.display_value,
            "canonical_hash": row.canonical_value_hash,
            "report_count": row.report_count, "sighting_count": row.sighting_count,
            "first_seen": row.first_seen.isoformat() if row.first_seen else None,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            "campaign_id": row.campaign_id,
        },
        "reports": [reports.serialize(r, public=True) for r in rows],
        "note": "Appearing here means the indicator was reported. It does not identify "
                "or accuse any person — ownership is never inferred.",
    }


@router.get("/entities", tags=["Intelligence"], summary="Search tracked indicators")
def entity_search(q: str = Query("", max_length=120), type: Optional[str] = None,
                  limit: int = Query(25, le=100), db: Session = Depends(m.get_session)):
    query = db.query(m.Entity)
    if type:
        query = query.filter(m.Entity.type == type)
    if q:
        query = query.filter(m.Entity.display_value.ilike(f"%{q}%"))
    rows = query.order_by(m.Entity.report_count.desc(),
                          m.Entity.last_seen.desc()).limit(limit).all()
    return {"count": len(rows), "entities": [{
        "type": e.type, "display_value": e.display_value,
        "canonical_hash": e.canonical_value_hash,
        "report_count": e.report_count, "sighting_count": e.sighting_count,
        "first_seen": e.first_seen.isoformat() if e.first_seen else None,
        "last_seen": e.last_seen.isoformat() if e.last_seen else None,
        "campaign_id": e.campaign_id,
    } for e in rows]}


@router.get("/campaigns", tags=["Intelligence"])
def list_campaigns(db: Session = Depends(m.get_session)):
    rows = db.query(m.Campaign).order_by(m.Campaign.last_seen.desc()).all()
    return {"count": len(rows), "campaigns": [{
        "id": c.id, "label": c.label, "description": c.description,
        "status": c.status, "score": c.score,
        "primary_category": c.primary_category,
        "primary_category_label": SCAM_CLASSES.get(c.primary_category or "", {}).get(
            "label", (c.primary_category or "Unclassified").replace("_", " ").title()),
        "languages": c.languages or [], "report_count": c.report_count,
        "sighting_count": c.sighting_count,
        "first_seen": c.first_seen.isoformat() if c.first_seen else None,
        "last_seen": c.last_seen.isoformat() if c.last_seen else None,
    } for c in rows]}


@router.get("/campaigns/{campaign_id}", tags=["Intelligence"])
def campaign_detail(campaign_id: str, db: Session = Depends(m.get_session)):
    data = graph.campaign_graph(db, campaign_id)
    if not data:
        raise HTTPException(status_code=404, detail="Campaign not found.")
    return data


@router.post("/campaigns/{campaign_id}/status", tags=["Moderation"])
def campaign_status(campaign_id: str, req: StatusRequest,
                    db: Session = Depends(m.get_session)):
    c = reports.set_campaign_status(db, campaign_id, req.status)
    if c is None:
        raise HTTPException(status_code=404, detail="Campaign not found.")
    db.commit()
    return {"id": c.id, "status": c.status}


@router.get("/pulse", tags=["Intelligence"], summary="Threat pulse: counts, trends, indicators")
def pulse(days: int = Query(14, ge=1, le=90), db: Session = Depends(m.get_session)):
    return graph.threat_pulse(db, days=days)


# ---------------------------------------------------------------------------
# Health & metadata
# ---------------------------------------------------------------------------
@router.get("/health", tags=["System"],
            summary="Dependency state without exposing secrets")
def health(db: Session = Depends(m.get_session)):
    checks = {}
    try:
        db.query(m.Campaign).count()
        checks["database"] = {"status": "ok", "engine": m.engine.dialect.name}
    except Exception as exc:
        checks["database"] = {"status": "down", "reason": str(exc)[:160]}

    import shutil
    checks["ocr"] = ({"status": "ok", "engine": "tesseract"} if shutil.which("tesseract")
                     else {"status": "unavailable",
                           "reason": "tesseract binary not installed; manual text entry still works"})
    try:
        import pyzbar.pyzbar  # noqa: F401
        checks["qr"] = {"status": "ok", "engine": "pyzbar"}
    except Exception:
        try:
            import cv2  # noqa: F401
            checks["qr"] = {"status": "ok", "engine": "opencv"}
        except Exception:
            checks["qr"] = {"status": "unavailable", "reason": "no QR decoder installed"}

    clf = classifier.status()
    checks["ml_classifier"] = ({"status": "ok"} if clf["available"]
                               else {"status": "unavailable", "reason": clf["reason"],
                                     "impact": "rule engine still fully operational"})
    checks["url_engine"] = {"status": "ok"}
    checks["external_threat_feeds"] = {
        "status": "local_only",
        "note": "No live external reputation feed is connected in this build. "
                "Local heuristics and the seeded threat list are used. "
                "We do not claim a live feed we do not have.",
    }

    degraded = [k for k, v in checks.items() if v.get("status") not in ("ok", "local_only")]
    return {
        "status": "degraded" if degraded else "online",
        "service": "RedFlag Intelligence API",
        "model_version": MODEL_VERSION,
        "checks": checks,
        "degraded": degraded,
    }


@router.get("/meta", tags=["System"], summary="Enums the UI needs")
def meta():
    return {
        "scam_categories": [{"key": k, "label": v["label"]} for k, v in SCAM_CLASSES.items()],
        "channels": list(reports.CHANNELS),
        "risk_bands": [{"min": lo, "max": hi, "key": k, "label": l}
                       for lo, hi, k, l in analyzer.BANDS],
        "brands": [{"key": k, "display": v["display"], "official_domains": v["domains"]}
                   for k, v in BRANDS.items()],
        "model_version": MODEL_VERSION,
        "languages": [{"key": "ta", "label": "Tamil"},
                      {"key": "en", "label": "English"},
                      {"key": "ta-en", "label": "Tanglish"}],
    }
