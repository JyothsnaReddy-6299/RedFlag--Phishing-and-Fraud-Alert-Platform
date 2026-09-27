import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_campaign_clustering_and_graph_analysis():
    # 1. Submit two distinct reports that share a common telephone number
    shared_phone = "9988112233"
    
    # Report 1
    rep1 = client.post("/api/v1/reports", json={
        "description": "SMS phishing claiming electricity will be disconnected",
        "raw_message": f"Your electricity power cut tonight. Call officer at {shared_phone}",
        "phone_number": shared_phone,
        "raw_url": "http://power-bill-payment-update.xyz",
        "organization": "TNEB",
        "location_city": "Chennai",
        "location_area": "Velachery"
    })
    assert rep1.status_code == 200

    # Report 2: Different URL, different area, but SAME phone number!
    rep2 = client.post("/api/v1/reports", json={
        "description": "WhatsApp message asking to clear electricity arrears",
        "raw_message": f"Urgent notice: TNEB power bill pending. Contact {shared_phone} or pay via tneb.pay@okhdfcbank",
        "phone_number": shared_phone,
        "upi_id": "tneb.pay@okhdfcbank",
        "raw_url": "http://eb-quick-recharge.live",
        "organization": "TNEB",
        "location_city": "Chennai",
        "location_area": "Guindy"
    })
    assert rep2.status_code == 200

    # 2. Test Full Graph Endpoint
    graph_res = client.get("/api/v1/graph/full")
    assert graph_res.status_code == 200
    graph_data = graph_res.json()
    assert len(graph_data["nodes"]) > 0
    assert len(graph_data["edges"]) > 0

    # Verify nodes contain shared phone
    node_labels = [n["label"] for n in graph_data["nodes"]]
    assert shared_phone in node_labels

    # 3. Test Campaign Detection Endpoint
    campaigns_res = client.get("/api/v1/graph/campaigns")
    assert campaigns_res.status_code == 200
    campaigns = campaigns_res.json()
    assert len(campaigns) >= 1

    # Find the campaign containing our shared phone
    target_camp = None
    for camp in campaigns:
        camp_node_labels = [n["label"] for n in camp["nodes"]]
        if shared_phone in camp_node_labels:
            target_camp = camp
            break

    assert target_camp is not None
    assert target_camp["report_count"] >= 2
    assert "TNEB" in (target_camp["impersonated_brand"] or "")
    assert target_camp["threat_indicators_count"] >= 3  # Phone + 2 URLs/UPI

    # 4. Test Entity Investigation Search Endpoint
    investigate_res = client.get(f"/api/v1/graph/investigate/{shared_phone}")
    assert investigate_res.status_code == 200
    inv_data = investigate_res.json()
    assert inv_data["found"] is True
    assert inv_data["entity_type"] == "PHONE"
    assert inv_data["connection_count"] >= 2
    assert len(inv_data["connected_campaign_ids"]) >= 1
