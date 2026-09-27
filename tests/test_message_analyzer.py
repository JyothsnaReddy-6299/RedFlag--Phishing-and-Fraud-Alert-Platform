import pytest
from app.services.message_analyzer import message_analyzer
from app.models.schemas import DetectedLanguage, ScamCategory

def test_english_banking_phishing():
    msg = "Dear customer, your SBI account is suspended! Update KYC immediately or account blocked in 24 hours. Call 9876543210."
    res = message_analyzer.analyze(msg)
    assert res.detected_language == DetectedLanguage.ENGLISH
    assert res.scam_category == ScamCategory.KYC_EXPIRY
    assert res.social_engineering.urgency_detected is True
    assert res.social_engineering.fear_or_threat_detected is True
    assert res.base_risk_score >= 60

def test_tanglish_tneb_scam():
    msg = "Ungal TNEB power bill kattavum udane illaiyendral innum 2 hours la current vettpadum. Send money to tneb.officer984@okhdfcbank"
    res = message_analyzer.analyze(msg)
    assert res.detected_language == DetectedLanguage.TANGLISH
    assert res.scam_category == ScamCategory.ELECTRICITY_BILL
    assert res.social_engineering.fear_or_threat_detected is True
    assert "tneb.officer984@okhdfcbank" in res.extracted_entities.upi_ids
    assert res.base_risk_score >= 60

def test_tamil_script_electricity_scam():
    msg = "அன்புள்ள வாடிக்கையாளரே, உங்களின் மின்சார கட்டணம் செலுத்தப்படவில்லை. இன்றிரவு மின்சாரம் துண்டிக்கப்படும். உடனே தொடர்பு கொள்ளவும்: 9840123456"
    res = message_analyzer.analyze(msg)
    assert res.detected_language in [DetectedLanguage.TAMIL, DetectedLanguage.MIXED]
    assert res.scam_category == ScamCategory.ELECTRICITY_BILL
    assert res.social_engineering.urgency_detected is True

def test_benign_message():
    msg = "Hello team, please find the project report attached. Let's discuss in our meeting tomorrow at 10 AM."
    res = message_analyzer.analyze(msg)
    assert res.scam_category == ScamCategory.LEGITIMATE
    assert res.base_risk_score <= 15
