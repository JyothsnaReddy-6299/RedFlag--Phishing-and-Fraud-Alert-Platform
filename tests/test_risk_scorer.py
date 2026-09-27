import pytest
from app.services.risk_scorer import risk_scorer
from app.services.url_analyzer import url_analyzer
from app.services.message_analyzer import message_analyzer
from app.services.threat_engine import threat_engine
from app.models.schemas import RiskLevel, ScamCategory

def test_risk_scorer_critical():
    url_str = "http://sbi-kyc-update.xyz/login"
    url_res = url_analyzer.analyze(url_str)
    msg_res = message_analyzer.analyze("Dear user, your SBI account is suspended! Update KYC urgently or card will be blocked.")
    threat_match = threat_engine.check_entities(msg_res.extracted_entities)
    
    # Combined check
    assessment = risk_scorer.evaluate(
        url_analysis=url_res,
        message_analysis=msg_res,
        threat_match={"matched": True, "threat_score_boost": 50.0, "matched_indicators": [{"type": "DOMAIN", "value": "sbi-kyc-update.xyz"}]}
    )
    assert assessment.risk_score >= 85
    assert assessment.risk_level in [RiskLevel.HIGH_RISK, RiskLevel.CRITICAL]
    assert len(assessment.contributing_factors) > 0
    assert len(assessment.mitigation_advice) > 0

def test_risk_scorer_benign():
    url_res = url_analyzer.analyze("https://www.google.com")
    msg_res = message_analyzer.analyze("Hey, how are you doing today?")
    assessment = risk_scorer.evaluate(url_analysis=url_res, message_analysis=msg_res)
    assert assessment.risk_score < 30
    assert assessment.risk_level == RiskLevel.SAFE_LOW
