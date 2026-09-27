import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal, Base, engine

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    # Cleanup can be done here if needed

def test_submit_community_report():
    payload = {
        "description": "Scammer called pretending to be electricity board officer.",
        "raw_message": "Pay TNEB bill immediately or power disconnected tonight. Contact 9840998877",
        "phone_number": "9840998877",
        "organization": "TNEB",
        "location_city": "Chennai",
        "location_area": "Mylapore"
    }
    res = client.post("/api/v1/reports", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["report_id"].startswith("RPT-")
    assert data["status"] == "PENDING"
    assert data["masked_phone"] == "98****8877"
    assert data["scam_category"] == "ELECTRICITY_BILL"

def test_public_reports_feed():
    res = client.get("/api/v1/reports")
    assert res.status_code == 200
    reports = res.json()
    assert isinstance(reports, list)
    assert len(reports) > 0
    # Confirm phone numbers are masked in public feed
    for r in reports:
        if r.get("masked_phone"):
            assert "****" in r["masked_phone"]

def test_analyst_verification_and_continuous_growth():
    # 1. Submit a report with a new unknown fraudulent UPI handle
    unique_upi = "fraudster.test.999@okhdfcbank"
    report_res = client.post("/api/v1/reports", json={
        "description": "Fake KYC portal demanding payment to this UPI",
        "raw_message": f"Update KYC urgently or bank account blocked! Pay fee to {unique_upi}",
        "upi_id": unique_upi,
        "scam_category": "KYC_EXPIRY"
    })
    assert report_res.status_code == 200
    report_id = report_res.json()["report_id"]

    # 2. Before analyst verification, scan message - shouldn't have confirmed DB threat
    pre_scan = client.post("/api/v1/scan/message", json={"message": f"Send fee to {unique_upi}"})
    assert pre_scan.status_code == 200
    # Not yet verified in DB threat engine
    assert not any("Verified Threat Database" in f for f in pre_scan.json()["risk_assessment"]["contributing_factors"])

    # 3. Analyst reviews and verifies the report
    verify_res = client.patch(f"/api/v1/reports/{report_id}/verify", json={
        "status": "VERIFIED",
        "analyst_id": "CYBER_ANALYST_007",
        "notes": "Confirmed phishing syndicate account"
    })
    assert verify_res.status_code == 200
    assert verify_res.json()["status"] == "VERIFIED"
    assert verify_res.json()["verified_by"] == "CYBER_ANALYST_007"

    # 4. Continuous Threat Growth check:
    # Scan again with a different message containing the same UPI
    post_scan = client.post("/api/v1/scan/message", json={"message": f"Pay pending charges to {unique_upi} immediately."})
    assert post_scan.status_code == 200
    post_data = post_scan.json()
    
    # It must now be caught dynamically by the verified threat intelligence engine!
    factors = post_data["risk_assessment"]["contributing_factors"]
    assert any("Confirmed Threat Match" in f or "Verified Threat Database" in f for f in factors)
    assert post_data["risk_assessment"]["risk_score"] >= 80

def test_indicators_endpoint():
    res = client.get("/api/v1/indicators")
    assert res.status_code == 200
    indicators = res.json()
    assert isinstance(indicators, list)
    assert len(indicators) > 0
