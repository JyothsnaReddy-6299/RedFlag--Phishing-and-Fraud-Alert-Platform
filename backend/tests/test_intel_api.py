"""API-level acceptance tests for the contract endpoints (section 21)."""
import io
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

# See conftest.py — the test database is always separate from the demo one.
os.environ.setdefault("REDFLAG_DATABASE_URL", "sqlite:///" + os.path.join(
    tempfile.gettempdir(), "redflag_pytest.db"))

from app.intel import db as m  # noqa: E402
from app.main import app  # noqa: E402

TANGLISH = ("Dear SBI user, unga account KYC kaalavadhi mudinjiduchu. Udane "
            "http://sbi-kyc-verify.xyz/login la update pannunga illana account block aagidum.")


@pytest.fixture(scope="module")
def client():
    m.Base.metadata.drop_all(bind=m.engine)
    m.init_db()
    with TestClient(app) as c:
        yield c


# --------------------------------------------------------------------------
# P0: preserve baseline
# --------------------------------------------------------------------------
def test_baseline_v1_endpoints_still_work(client):
    r = client.post("/api/v1/scan/url", json={"url": "http://sbi-kyc-update-portal.xyz/login"})
    assert r.status_code == 200
    assert r.json()["risk_score"] > 0

    r = client.post("/api/v1/scan/sms", json={"text": "Your KYC expired, click http://x.xyz"})
    assert r.status_code == 200

    assert client.get("/api/v1/threats/known").status_code == 200
    assert client.get("/health").status_code == 200


# --------------------------------------------------------------------------
# P0: unified multimodal API — same core schema
# --------------------------------------------------------------------------
CORE = {"analysis_id", "input_type", "language", "verdict", "risk_score", "confidence",
        "scam_category", "summary", "red_flags", "risk_factors", "entities",
        "campaign_links", "recommended_actions", "model_version", "degraded_checks",
        "created_at"}


def _png(text: str) -> bytes:
    from PIL import Image, ImageDraw
    img = Image.new("RGB", (900, 220), "white")
    d = ImageDraw.Draw(img)
    for i, line in enumerate(text.split("\n")):
        d.text((14, 20 + i * 34), line, fill="black")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_text_and_url_share_the_same_schema(client):
    a = client.post("/api/analyze/text", json={"text": TANGLISH}).json()
    b = client.post("/api/analyze/url", json={"url": "http://sbi-kyc-verify.xyz/login"}).json()
    assert CORE <= set(a)
    assert CORE <= set(b)
    assert a["input_type"] == "text" and b["input_type"] == "url"


def test_image_endpoint_shares_the_schema_or_asks_for_input(client):
    pytest.importorskip("PIL")
    data = _png("SBI KYC expired\nclick http://sbi-kyc-verify.xyz/login\nwithin 24 hours")
    r = client.post("/api/analyze/image",
                    files={"file": ("shot.png", data, "image/png")})
    assert r.status_code == 200
    body = r.json()
    if body.get("needs_input"):
        assert body["ocr"]["available"] is False or body["ocr"]["text"] == ""
    else:
        assert CORE <= set(body)
        assert body["input_type"] == "image"
        assert body["ocr"] is not None


def test_image_override_lets_the_user_correct_ocr(client):
    pytest.importorskip("PIL")
    data = _png("blurry")
    r = client.post("/api/analyze/image",
                    files={"file": ("shot.png", data, "image/png")},
                    data={"text_override": TANGLISH})
    assert r.status_code == 200
    body = r.json()
    assert body["ocr"]["user_corrected"] is True
    assert body["risk_score"] >= 25


def test_qr_destination_is_shown_before_opening(client):
    qrcode = pytest.importorskip("qrcode")
    img = qrcode.make("http://sbi-kyc-verify.xyz/login")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    r = client.post("/api/analyze/qr", files={"file": ("qr.png", buf.getvalue(), "image/png")})
    assert r.status_code == 200
    body = r.json()
    if body.get("needs_input"):
        pytest.skip("no QR decoder available on this host")
    assert "sbi-kyc-verify.xyz" in " ".join(body["qr_destination_preview"])
    assert CORE <= set(body)


# --------------------------------------------------------------------------
# P0: security basics
# --------------------------------------------------------------------------
def test_input_validation(client):
    assert client.post("/api/analyze/text", json={"text": ""}).status_code == 422
    assert client.post("/api/analyze/text", json={"text": "x" * 20000}).status_code == 422
    assert client.post("/api/analyze/url", json={"url": "javascript:alert(1)"}).status_code == 422
    assert client.post("/api/analyze/url", json={"url": "notaurl"}).status_code == 422


def test_upload_rejects_non_image(client):
    r = client.post("/api/analyze/image",
                    files={"file": ("evil.png", b"MZ\x90\x00 executable", "image/png")})
    assert r.status_code == 400


def test_security_headers_and_correlation_id(client):
    r = client.get("/api/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers.get("X-Correlation-ID")


def test_health_reports_dependencies_without_secrets(client):
    body = client.get("/api/health").json()
    assert "checks" in body and "database" in body["checks"]
    assert "GEMINI" not in str(body).upper()
    # We must not claim a live feed we do not have.
    assert body["checks"]["external_threat_feeds"]["status"] == "local_only"


# --------------------------------------------------------------------------
# P0/P1: reporting, moderation, campaigns, pulse, evidence export
# --------------------------------------------------------------------------
def test_full_community_loop(client):
    a = client.post("/api/analyze/text", json={"text": TANGLISH}).json()

    r = client.post("/api/reports", json={
        "analysis_id": a["analysis_id"], "category": a["scam_category"],
        "channel": "sms", "narrative": TANGLISH, "locality": "Velachery",
        "consent": True, "visibility": "public",
    })
    assert r.status_code == 200
    report_id = r.json()["report"]["id"]
    assert r.json()["report"]["status"] == "pending"

    queue = client.get("/api/reports/queue").json()
    assert any(x["id"] == report_id for x in queue["reports"])

    approved = client.post(f"/api/reports/{report_id}/approve").json()
    assert approved["campaign"] is not None
    campaign_id = approved["campaign"]["id"]

    detail = client.get(f"/api/campaigns/{campaign_id}").json()
    assert detail["nodes"] and detail["timeline"]

    feed = client.get("/api/feed").json()
    assert feed["count"] >= 1
    assert "narrative" not in feed["reports"][0]      # private narrative never public

    pulse = client.get("/api/pulse?days=30").json()
    assert pulse["totals"]["campaigns"] >= 1

    bundle = client.get(f"/api/analysis/{a['analysis_id']}/evidence").json()
    assert bundle["indicators"] and bundle["official_reporting"]["helpline"].startswith("1930")

    status = client.post(f"/api/campaigns/{campaign_id}/status", json={"status": "closed"})
    assert status.json()["status"] == "closed"


def test_analysis_is_retrievable_by_id(client):
    a = client.post("/api/analyze/text", json={"text": TANGLISH}).json()
    again = client.get(f"/api/analysis/{a['analysis_id']}").json()
    assert again["analysis_id"] == a["analysis_id"]
    assert client.get("/api/analysis/does-not-exist").status_code == 404


def test_entity_lookup_does_not_accuse_anyone(client):
    res = client.get("/api/entities/domain/sbi-kyc-verify.xyz").json()
    if res.get("found"):
        assert "never" in res["note"].lower() or "not" in res["note"].lower()


def test_meta_exposes_enums_for_the_ui(client):
    body = client.get("/api/meta").json()
    assert body["scam_categories"] and body["risk_bands"] and body["channels"]
