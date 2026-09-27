from fastapi import APIRouter, HTTPException, Query
from app.models.schemas import URLScanRequest, URLScanResponse
from app.services.url_analyzer import url_analyzer, KNOWN_MALICIOUS_DOMAINS
from app.services.risk_scorer import url_risk_scorer

router = APIRouter()

@router.post("/scan/url", response_model=URLScanResponse)
def scan_url(request: URLScanRequest):
    """
    Primary real-time URL inspection endpoint.
    Performs comprehensive structural heuristics, Shannon entropy, brand impersonation detection,
    and threat feed correlation.
    """
    url_clean = request.url.strip()
    if not url_clean:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    features = url_analyzer.analyze(url_clean)
    threat_match = url_analyzer.check_threat_feeds(features.domain)
    return url_risk_scorer.evaluate(features, threat_match)

@router.get("/scan/quick", response_model=URLScanResponse)
def quick_scan_url(url: str = Query(..., description="The URL to inspect")):
    """
    Quick GET endpoint for one-click URL verification.
    """
    url_clean = url.strip()
    if not url_clean:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    features = url_analyzer.analyze(url_clean)
    threat_match = url_analyzer.check_threat_feeds(features.domain)
    return url_risk_scorer.evaluate(features, threat_match)

@router.get("/threats/known")
def get_known_threats():
    """
    Returns verified malicious seed threat domains tracked by RedFlag.
    """
    return {
        "count": len(KNOWN_MALICIOUS_DOMAINS),
        "threats": [
            {"domain": domain, "category": data["category"], "source": data["source"]}
            for domain, data in KNOWN_MALICIOUS_DOMAINS.items()
        ]
    }
