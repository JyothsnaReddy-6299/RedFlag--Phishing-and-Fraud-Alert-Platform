from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.orm import Session
from app.db.models import Report, ThreatIndicator, AuditLog
from app.models.report_schemas import ReportCreateRequest, ReportVerifyRequest, ReportPublicResponse
from app.services.entity_extractor import entity_extractor
from app.services.url_analyzer import url_analyzer
from app.services.message_analyzer import message_analyzer
from app.services.risk_scorer import risk_scorer
from app.utils.privacy import hash_identifier, mask_phone_number, mask_upi_id, mask_url

class ReportEngine:
    def submit_report(self, db: Session, req: ReportCreateRequest, client_ip: str = "127.0.0.1") -> Report:
        # Extract entities from raw message or URL if available
        combined_text = f"{req.raw_message or ''} {req.raw_url or ''} {req.description or ''}".strip()
        extracted = entity_extractor.extract_all(combined_text)

        phone = req.phone_number or (extracted.phone_numbers[0] if extracted.phone_numbers else None)
        upi = req.upi_id or (extracted.upi_ids[0] if extracted.upi_ids else None)
        url = req.raw_url or (extracted.urls[0] if extracted.urls else None)
        org = req.organization or (extracted.organizations[0] if extracted.organizations else None)

        # Automated initial risk assessment
        url_res = url_analyzer.analyze(url) if url else None
        msg_res = message_analyzer.analyze(req.raw_message) if req.raw_message else None
        
        assessment = risk_scorer.evaluate(
            url_analysis=url_res,
            message_analysis=msg_res,
            extracted_entities=extracted
        )
        calculated_score = assessment.risk_score
        detected_category = req.scam_category or assessment.primary_category.value

        reporter_hash = hash_identifier(client_ip)

        # Create report record
        report = Report(
            scam_category=detected_category,
            description=req.description,
            raw_message=req.raw_message,
            raw_url=url,
            phone_number=phone,
            upi_id=upi,
            organization=org,
            location_city=req.location_city,
            location_area=req.location_area,
            status="PENDING",
            reporter_hash=reporter_hash,
            initial_risk_score=calculated_score
        )
        db.add(report)
        db.commit()
        db.refresh(report)

        # Record / Update Threat Indicators
        indicators_to_track = []
        if phone:
            indicators_to_track.append(("PHONE", phone))
        if upi:
            indicators_to_track.append(("UPI", upi.lower()))
        if url:
            indicators_to_track.append(("URL", url))
            if extracted.domains:
                indicators_to_track.append(("DOMAIN", extracted.domains[0].lower()))

        for ind_type, ind_val in indicators_to_track:
            existing = db.query(ThreatIndicator).filter(
                ThreatIndicator.indicator_type == ind_type,
                ThreatIndicator.indicator_value == ind_val
            ).first()
            if existing:
                existing.report_count += 1
                existing.last_seen = datetime.now(timezone.utc)
            else:
                new_ind = ThreatIndicator(
                    indicator_type=ind_type,
                    indicator_value=ind_val,
                    category=detected_category,
                    status="UNCONFIRMED",
                    report_count=1
                )
                db.add(new_ind)

        # Audit Log
        audit = AuditLog(
            action="SUBMIT_REPORT",
            actor=f"REPORTER_{reporter_hash[:8]}",
            target_id=report.report_id,
            details=f"Community report filed with category: {detected_category}, risk score: {calculated_score}"
        )
        db.add(audit)
        db.commit()
        db.refresh(report)

        return report

    def verify_report(self, db: Session, report_id: str, req: ReportVerifyRequest) -> Optional[Report]:
        report = db.query(Report).filter(Report.report_id == report_id).first()
        if not report:
            return None

        report.status = req.status.upper()
        report.verified_by = req.analyst_id
        report.verification_notes = req.notes
        report.updated_at = datetime.now(timezone.utc)

        # If verified, promote associated indicators to VERIFIED_MALICIOUS
        if report.status == "VERIFIED":
            indicators_to_promote = []
            if report.phone_number:
                indicators_to_promote.append(("PHONE", report.phone_number))
            if report.upi_id:
                indicators_to_promote.append(("UPI", report.upi_id.lower()))
            if report.raw_url:
                indicators_to_promote.append(("URL", report.raw_url))
                extracted = entity_extractor.extract_all(report.raw_url)
                if extracted.domains:
                    indicators_to_promote.append(("DOMAIN", extracted.domains[0].lower()))

            for ind_type, ind_val in indicators_to_promote:
                ind = db.query(ThreatIndicator).filter(
                    ThreatIndicator.indicator_type == ind_type,
                    ThreatIndicator.indicator_value == ind_val
                ).first()
                if ind:
                    ind.status = "VERIFIED_MALICIOUS"

        # Audit Log
        audit = AuditLog(
            action=f"ANALYST_{report.status}",
            actor=req.analyst_id,
            target_id=report.report_id,
            details=f"Report status transitioned to {report.status}. Notes: {req.notes or 'None'}"
        )
        db.add(audit)
        db.commit()
        db.refresh(report)

        return report

    def get_public_reports(self, db: Session, limit: int = 50, offset: int = 0, status_filter: Optional[str] = None) -> List[ReportPublicResponse]:
        query = db.query(Report)
        if status_filter:
            query = query.filter(Report.status == status_filter.upper())
        reports = query.order_by(Report.created_at.desc()).offset(offset).limit(limit).all()

        public_list = []
        for r in reports:
            public_list.append(ReportPublicResponse(
                report_id=r.report_id,
                scam_category=r.scam_category,
                description=r.description,
                masked_phone=mask_phone_number(r.phone_number) if r.phone_number else None,
                masked_upi=mask_upi_id(r.upi_id) if r.upi_id else None,
                defanged_url=mask_url(r.raw_url) if r.raw_url else None,
                organization=r.organization,
                location_city=r.location_city,
                location_area=r.location_area,
                status=r.status,
                initial_risk_score=r.initial_risk_score,
                created_at=r.created_at
            ))
        return public_list

report_engine = ReportEngine()
