from fastapi import APIRouter, HTTPException
from app.models.schemas import (
    URLScanRequest,
    URLScanResponse,
    MessageScanRequest,
    MessageScanResponse,
    UnifiedScanRequest,
    UnifiedScanResponse,
    ExtractedEntities
)
from app.services.url_analyzer import url_analyzer
from app.services.message_analyzer import message_analyzer
from app.services.entity_extractor import entity_extractor
from app.services.threat_engine import threat_engine
from app.services.risk_scorer import risk_scorer

router = APIRouter()

@router.post("/scan/url", response_model=URLScanResponse)
def scan_url(request: URLScanRequest):
    """
    Analyzes a URL using structural heuristics, entropy, brand impersonation checks,
    and threat intelligence cross-referencing.
    """
    if not request.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    url_analysis = url_analyzer.analyze(request.url)
    entities = entity_extractor.extract_all(request.url)
    threat_match = threat_engine.check_entities(entities)
    
    risk_assessment = risk_scorer.evaluate(
        url_analysis=url_analysis,
        threat_match=threat_match,
        extracted_entities=entities
    )

    return URLScanResponse(
        url_analysis=url_analysis,
        extracted_entities=entities,
        risk_assessment=risk_assessment
    )

@router.post("/scan/message", response_model=MessageScanResponse)
def scan_message(request: MessageScanRequest):
    """
    Analyzes an SMS/text message in English, Tamil, or Tanglish for social engineering,
    urgency, impersonation, and fraud indicators.
    """
    if not request.message.strip():
        raise HTTPException(status_code=400, detail="Message text cannot be empty")

    msg_analysis = message_analyzer.analyze(request.message)
    threat_match = threat_engine.check_entities(msg_analysis.extracted_entities)
    
    risk_assessment = risk_scorer.evaluate(
        message_analysis=msg_analysis,
        threat_match=threat_match,
        extracted_entities=msg_analysis.extracted_entities
    )

    return MessageScanResponse(
        message_analysis=msg_analysis,
        risk_assessment=risk_assessment
    )

@router.post("/scan/unified", response_model=UnifiedScanResponse)
def scan_unified(request: UnifiedScanRequest):
    """
    Unified multi-vector scanner: extracts embedded URLs from text, performs concurrent
    structural heuristics, multilingual NLP analysis, and correlates all entities.
    """
    text = request.text.strip() if request.text else ""
    explicit_url = request.url.strip() if request.url else ""

    if not text and not explicit_url:
        raise HTTPException(status_code=400, detail="Must provide either text or url to scan")

    # Extract entities from both text and explicit URL
    combined_content = f"{text} {explicit_url}".strip()
    entities = entity_extractor.extract_all(combined_content)

    # URL analysis
    target_url = explicit_url or (entities.urls[0] if entities.urls else None)
    url_analysis = url_analyzer.analyze(target_url) if target_url else None

    # Message analysis
    msg_analysis = message_analyzer.analyze(text) if text else None

    # Threat engine check
    threat_match = threat_engine.check_entities(entities)

    # Risk scoring
    risk_assessment = risk_scorer.evaluate(
        url_analysis=url_analysis,
        message_analysis=msg_analysis,
        threat_match=threat_match,
        extracted_entities=entities
    )

    input_type = "HYBRID" if (url_analysis and msg_analysis) else ("URL" if url_analysis else "MESSAGE")

    return UnifiedScanResponse(
        input_type=input_type,
        url_analysis=url_analysis,
        message_analysis=msg_analysis,
        extracted_entities=entities,
        risk_assessment=risk_assessment
    )
