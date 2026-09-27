import pytest
from app.services.risk_scorer import url_risk_scorer
from app.services.url_analyzer import url_analyzer
from app.models.schemas import RiskLevel, URLCategory

def test_risk_scorer_critical():
    url_str = "http://sbi-kyc-update.xyz/login"
    features = url_analyzer.analyze(url_str)
    threat_match = url_analyzer.check_threat_feeds(features.domain)
    
    assessment = url_risk_scorer.evaluate(features, threat_match)
    assert assessment.risk_score >= 85
    assert assessment.risk_level in [RiskLevel.HIGH_RISK, RiskLevel.CRITICAL]
    assert assessment.category == URLCategory.KNOWN_PHISHING
    assert assessment.threat_intel_match is True
    assert len(assessment.contributing_factors) > 0
    assert len(assessment.mitigation_advice) > 0

def test_risk_scorer_brand_impersonation():
    url_str = "http://hdfc-login-portal-verification.top"
    features = url_analyzer.analyze(url_str)
    assessment = url_risk_scorer.evaluate(features)
    assert assessment.risk_score >= 60
    assert assessment.risk_level in [RiskLevel.HIGH_RISK, RiskLevel.CRITICAL]
    assert assessment.category == URLCategory.BRAND_IMPERSONATION

def test_risk_scorer_benign():
    features = url_analyzer.analyze("https://www.google.com")
    assessment = url_risk_scorer.evaluate(features)
    assert assessment.risk_score < 30
    assert assessment.risk_level == RiskLevel.SAFE_LOW
    assert assessment.category == URLCategory.LEGITIMATE
