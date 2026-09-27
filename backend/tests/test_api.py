import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "online"

def test_frontend_root():
    res = client.get("/")
    assert res.status_code == 200
    assert "RedFlag" in res.text
    assert "network-canvas" in res.text

def test_scan_url_endpoint():
    payload = {"url": "http://sbi-verification-portal.xyz/login"}
    res = client.post("/api/v1/scan/url", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "url_analysis" in data
    assert "risk_assessment" in data
    assert data["risk_assessment"]["risk_score"] > 50

def test_scan_message_endpoint():
    payload = {"message": "Ungal TNEB bill kattavum udane illaiyendral current vettpadum. Call 9840123456"}
    res = client.post("/api/v1/scan/message", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "message_analysis" in data
    assert data["message_analysis"]["scam_category"] == "ELECTRICITY_BILL"

def test_scan_unified_endpoint():
    payload = {
        "text": "Your account has been suspended! Restore now: http://hdfc-verify.xyz/auth",
        "url": "http://hdfc-verify.xyz/auth"
    }
    res = client.post("/api/v1/scan/unified", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["input_type"] == "HYBRID"
    assert data["risk_assessment"]["risk_level"] in ["HIGH_RISK", "CRITICAL", "SUSPICIOUS"]
