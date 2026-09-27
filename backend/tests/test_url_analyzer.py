import pytest
from app.services.url_analyzer import url_analyzer

def test_legitimate_url():
    res = url_analyzer.analyze("https://www.onlinesbi.sbi/portal")
    assert res.base_risk_score < 30
    assert res.brand_impersonated is None
    assert res.suspicious_tld is False

def test_phishing_brand_impersonation():
    res = url_analyzer.analyze("http://sbi-kyc-update-verification.xyz/login")
    assert res.brand_impersonated == "SBI"
    assert res.suspicious_tld is True
    assert res.base_risk_score >= 60
    assert any("Brand impersonation" in s for s in res.threat_signals)

def test_ip_based_url():
    res = url_analyzer.analyze("http://192.168.1.100/paytm/verify")
    assert res.ip_based is True
    assert any("raw IP" in s for s in res.threat_signals)
    assert res.base_risk_score >= 40

def test_obfuscated_at_symbol():
    res = url_analyzer.analyze("http://legitsite.com@evil-phishing-host.live/steal")
    assert "@" in res.url
    assert any("@" in s for s in res.threat_signals)
