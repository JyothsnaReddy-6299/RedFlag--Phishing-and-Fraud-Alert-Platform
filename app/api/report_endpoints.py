from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.report_schemas import (
    ReportCreateRequest,
    ReportVerifyRequest,
    ReportPublicResponse,
    ReportDetailResponse,
    IndicatorSummary
)
from app.services.report_engine import report_engine
from app.db.models import Report, ThreatIndicator

router = APIRouter()

@router.post("/reports", response_model=ReportPublicResponse)
def submit_report(
    req: ReportCreateRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Submit a community fraud report. The platform automatically scans indicators,
    calculates initial risk, records audit logs, and adds indicators to tracking.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    created_report = report_engine.submit_report(db, req, client_ip)
    
    # Return masked public view
    public_list = report_engine.get_public_reports(db, limit=1, offset=0)
    for r in public_list:
        if r.report_id == created_report.report_id:
            return r
            
    # Fallback response
    return ReportPublicResponse(
        report_id=created_report.report_id,
        scam_category=created_report.scam_category,
        description=created_report.description,
        masked_phone="****" if created_report.phone_number else None,
        masked_upi="****" if created_report.upi_id else None,
        defanged_url=created_report.raw_url,
        organization=created_report.organization,
        location_city=created_report.location_city,
        location_area=created_report.location_area,
        status=created_report.status,
        initial_risk_score=created_report.initial_risk_score,
        created_at=created_report.created_at
    )

@router.get("/reports", response_model=List[ReportPublicResponse])
def get_public_reports(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None, description="Filter by status: PENDING, VERIFIED, REJECTED, UNDER_REVIEW"),
    db: Session = Depends(get_db)
):
    """
    Retrieves community reports with privacy-first data masking (masked phone numbers and UPI IDs).
    """
    return report_engine.get_public_reports(db, limit=limit, offset=offset, status_filter=status)

@router.get("/reports/{report_id}", response_model=ReportDetailResponse)
def get_report_detail(
    report_id: str,
    db: Session = Depends(get_db)
):
    """
    Retrieves full report details for fraud analysts and investigators.
    """
    report = db.query(Report).filter(Report.report_id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report

@router.patch("/reports/{report_id}/verify", response_model=ReportDetailResponse)
def verify_report(
    report_id: str,
    req: ReportVerifyRequest,
    db: Session = Depends(get_db)
):
    """
    Analyst verification workflow. Transitions report status to VERIFIED, REJECTED,
    or UNDER_REVIEW. Marking VERIFIED promotes associated indicators to verified threat intelligence.
    """
    updated_report = report_engine.verify_report(db, report_id, req)
    if not updated_report:
        raise HTTPException(status_code=404, detail="Report not found")
    return updated_report

@router.get("/indicators", response_model=List[IndicatorSummary])
def get_threat_indicators(
    indicator_type: Optional[str] = Query(None, description="PHONE, UPI, URL, or DOMAIN"),
    status: Optional[str] = Query(None, description="UNCONFIRMED, VERIFIED_MALICIOUS, WHITELISTED"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """
    Returns threat indicators tracked across all community reports.
    """
    query = db.query(ThreatIndicator)
    if indicator_type:
        query = query.filter(ThreatIndicator.indicator_type == indicator_type.upper())
    if status:
        query = query.filter(ThreatIndicator.status == status.upper())
    indicators = query.order_by(ThreatIndicator.report_count.desc()).limit(limit).all()
    return indicators
