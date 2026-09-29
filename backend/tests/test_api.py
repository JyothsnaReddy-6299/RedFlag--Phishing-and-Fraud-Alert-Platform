import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "online"
    assert "Malicious Links" in res.json()["focus"]

def test_frontend_root():
    res = client.get("/")
    assert res.status_code == 200
    assert "RedFlag" in res.text

def test_scan_url_endpoint():
    payload = {"url": "http://sbi-verification-portal.xyz/login"}
    res = client.post("/api/v1/scan/url", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "url" in data
    assert "risk_score" in data
    assert data["risk_score"] > 50
    assert data["url_features"]["brand_impersonated"] == "SBI"
    assert len(data["contributing_factors"]) > 0

def test_official_sbi_bank_in_api():
    payload = {"url": "https://onlinesbi.sbi.bank.in/"}
    res = client.post("/api/v1/scan/url", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] == 0
    assert data["risk_level"] == "SAFE_LOW"
    assert data["category"] == "LEGITIMATE"
    assert data["url_features"]["is_official_domain"] is True

def test_quick_scan_url():
    res = client.get("/api/v1/scan/quick?url=http://192.168.1.1/login")
    assert res.status_code == 200
    data = res.json()
    assert data["url_features"]["ip_based"] is True
    assert data["risk_score"] >= 35

def test_known_threats_endpoint():
    res = client.get("/api/v1/threats/known")
    assert res.status_code == 200
    data = res.json()
    assert data["count"] > 0
    assert len(data["threats"]) > 0

def test_scan_sms_endpoint():
    payload = {
        "text": "Dear customer, your electricity will be disconnected tonight at 9:30 PM. Call officer at 9876543210 immediately.",
        "sender_id": "+919876543210"
    }
    res = client.post("/api/v1/scan/sms", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] >= 60
    assert "UTILITY" in data["scam_category"]
    assert len(data["threat_signals"]) > 0
