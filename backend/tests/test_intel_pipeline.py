"""Acceptance tests for the NextGen AI Hacks 2026 implementation contract.

Each test names the P0 row it protects.
"""
import io
import os
import tempfile

import pytest

# conftest.py already redirects REDFLAG_DATABASE_URL to a throwaway database
# before any app import. This is a belt-and-braces guard for direct runs.
os.environ.setdefault("REDFLAG_DATABASE_URL", "sqlite:///" + os.path.join(
    tempfile.gettempdir(), "redflag_pytest.db"))

from app.intel import adapters, analyzer, entities, graph, language  # noqa: E402
from app.intel import db as m  # noqa: E402
from app.intel.intent import classify  # noqa: E402

TANGLISH = ("Dear SBI user, unga account KYC kaalavadhi mudinjiduchu. Udane "
            "http://sbi-kyc-verify.xyz/login la update pannunga illana account block aagidum.")
TAMIL = ("அன்புள்ள வாடிக்கையாளரே, உங்கள் KYC காலாவதி ஆகிவிட்டது. உடனே "
         "http://sbi-kyc-verify.xyz/login இல் புதுப்பிக்கவும், இல்லையெனில் கணக்கு முடக்கப்படும்.")
ENGLISH = ("Dear SBI customer, your KYC has expired. Update immediately at "
           "http://sbi-kyc-verify.xyz/login or your account will be blocked within 24 hours.")
LEGIT = ("Rs.2,340.00 debited from A/c XX4521 on 14-02-26 to VPA grocery@okicici. "
         "Not you? Call 18001234. Do not share your OTP with anyone.")


# --------------------------------------------------------------------------
# P0: Tamil / English / Tanglish
# --------------------------------------------------------------------------
def test_language_detection_three_forms():
    assert language.detect(ENGLISH).language == "en"
    assert language.detect(TAMIL).language in ("ta", "ta-en")
    assert language.detect(TANGLISH).language == "ta-en"


def test_tanglish_normalization_keeps_urls_and_numbers_intact():
    norm = language.normalize("Udane http://sbi-kyc-verify.xyz/login la Rs.75,000 anuppunga")
    assert "http://sbi-kyc-verify.xyz/login" in norm.normalized
    assert "75,000" in norm.normalized          # digits must never be collapsed
    assert any(r["to"] == "immediately" for r in norm.replacements)


def test_language_alone_is_not_a_verdict():
    """A benign Tamil message must not be flagged merely for being Tamil."""
    benign_tamil = "உங்கள் புத்தக ஆர்டர் அனுப்பப்பட்டது. நாளை வந்து சேரும். நன்றி."
    res = analyzer.analyze(benign_tamil, session=None, persist=False)
    assert res["risk_score"] < 25
    assert res["verdict"] == "LOW"


@pytest.mark.parametrize("text", [TANGLISH, TAMIL, ENGLISH])
def test_all_three_demo_forms_analyze_successfully(text):
    res = analyzer.analyze(text, session=None, persist=False)
    assert res["risk_score"] >= 25
    assert res["red_flags"], "a non-low verdict must carry evidence"


# --------------------------------------------------------------------------
# P0: Score + verdict + evidence on every result
# --------------------------------------------------------------------------
REQUIRED_KEYS = [
    "analysis_id", "input_type", "language", "verdict", "risk_score", "confidence",
    "scam_category", "summary", "red_flags", "risk_factors", "entities",
    "campaign_links", "recommended_actions", "model_version", "degraded_checks",
    "created_at",
]


@pytest.mark.parametrize("text", [TANGLISH, LEGIT, "hello there"])
def test_canonical_result_shape(text):
    res = analyzer.analyze(text, session=None, persist=False)
    for key in REQUIRED_KEYS:
        assert key in res, f"canonical result is missing {key}"
    assert 0 <= res["risk_score"] <= 100
    assert res["verdict"] in ("LOW", "CAUTION", "HIGH", "CRITICAL")
    assert res["recommended_actions"], "every result must end with an action"


def test_every_risk_factor_is_auditable():
    res = analyzer.analyze(TANGLISH, session=None, persist=False)
    assert res["risk_factors"]
    for f in res["risk_factors"]:
        assert set(("name", "family", "weight", "observed_value",
                    "evidence_span", "source")) <= set(f)


def test_score_never_exceeds_family_caps():
    res = analyzer.analyze(TANGLISH, session=None, persist=False)
    for b in res["score_breakdown"]:
        assert b["points"] <= b["cap"] + 1e-6


def test_legitimate_message_scores_low():
    res = analyzer.analyze(LEGIT, session=None, persist=False)
    assert res["risk_score"] < 25
    assert res["benign_adjustment"] <= 0


# --------------------------------------------------------------------------
# P0: Entities
# --------------------------------------------------------------------------
def test_entity_extraction_covers_contract_types():
    text = ("Pay Rs.4,999 to refund.help@ybl or call 9123456780. "
            "Mail support@sbi-kyc-verify.xyz, visit http://sbi-kyc-verify.xyz/login. "
            "Txn ID ABC123456. Follow @sbi_support. Velachery branch.")
    found = {e.type for e in entities.extract(text)}
    for t in ("phone", "url", "domain", "email", "upi", "handle", "amount",
              "txn_id", "locality", "brand"):
        assert t in found, f"{t} was not extracted"


def test_raw_value_is_preserved_for_evidence():
    ents = entities.extract("call +91 98765 43210 now")
    phone = next(e for e in ents if e.type == "phone")
    assert phone.canonical_value.startswith("+91")
    assert phone.raw_value in "call +91 98765 43210 now"


def test_brand_domain_conflict_is_context_not_proof():
    ents = entities.extract("SBI alert: login at http://sbi-kyc-verify.xyz/login")
    conflicts = entities.brand_domain_conflict(ents)
    assert conflicts and conflicts[0]["brand_key"] == "sbi"
    # The official domain must not be flagged.
    ok = entities.extract("SBI alert: login at https://www.onlinesbi.sbi/")
    assert entities.brand_domain_conflict(ok) == []


# --------------------------------------------------------------------------
# P0: URL engine contributes structural evidence
# --------------------------------------------------------------------------
def test_url_engine_evidence_is_attached():
    res = analyzer.analyze(ENGLISH, session=None, persist=False)
    url_factors = [f for f in res["risk_factors"] if f["family"] == "url_technical"]
    assert url_factors
    assert res["url_reports"], "the preserved URL engine must produce a report"


def test_https_alone_is_not_proof_of_legitimacy():
    a = analyzer.analyze("Verify your account now at https://sbi-kyc-verify.xyz/login "
                         "or it will be blocked immediately.", session=None, persist=False)
    assert a["risk_score"] >= 25


# --------------------------------------------------------------------------
# P0: OCR / QR degrade gracefully
# --------------------------------------------------------------------------
def test_upload_validation_rejects_bad_type_and_size():
    assert adapters.validate_upload("application/x-msdownload", 10) is not None
    assert adapters.validate_upload("image/png", 10**9) is not None
    assert adapters.validate_upload("image/png", 1024) is None


def test_magic_byte_sniffing():
    assert adapters.sniff_is_image(b"\x89PNG\r\n\x1a\n" + b"0" * 32)
    assert not adapters.sniff_is_image(b"MZ\x90\x00 fake exe")


def test_ocr_and_qr_never_raise_on_garbage():
    ocr = adapters.run_ocr(b"not an image")
    qr = adapters.decode_qr(b"not an image")
    assert ocr.available is False or ocr.text == ""
    assert qr.available is False
    assert qr.reason  # a reason is always given, never silence


def test_ocr_roundtrip_if_tesseract_present():
    pytest.importorskip("PIL")
    import shutil
    if shutil.which("tesseract") is None:
        pytest.skip("tesseract binary not installed on this host")
    from PIL import Image, ImageDraw
    img = Image.new("RGB", (640, 120), "white")
    ImageDraw.Draw(img).text((12, 40), "KYC expired click http://sbi-kyc-verify.xyz", fill="black")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    res = adapters.run_ocr(buf.getvalue())
    assert res.available
    assert "kyc" in res.text.lower()


# --------------------------------------------------------------------------
# P0: campaign graph & community loop
# --------------------------------------------------------------------------
@pytest.fixture()
def session():
    m.Base.metadata.drop_all(bind=m.engine)
    m.init_db()
    s = m.SessionLocal()
    yield s
    s.close()


def test_repeated_indicator_forms_a_campaign(session):
    from app.intel import reports as rep

    first = analyzer.analyze(ENGLISH, session=session, persist=True)
    rep.create_report(session, analysis_id=first["analysis_id"], category="kyc_account_freeze",
                      channel="sms", narrative=ENGLISH, locality="Adyar", occurred_at=None,
                      consent=True, visibility="public", reporter_id=None, auto_approve=True)

    second = analyzer.analyze(TANGLISH, session=session, persist=True)
    assert second["campaign_links"], "a shared domain must link the second sighting"
    assert any(r["relation"] == "same_indicator"
               for r in second["campaign_links"][0]["reasons"])

    # And the shared indicator must now carry reputation.
    assert any(r["type"] == "domain" for r in second["entity_reputation"])

    detail = graph.campaign_graph(session, second["campaign_links"][0]["campaign_id"])
    assert detail["nodes"] and detail["edges"]


def test_duplicate_detection_and_merge(session):
    from app.intel import reports as rep

    a = analyzer.analyze(ENGLISH, session=session, persist=True)
    r1 = rep.create_report(session, analysis_id=a["analysis_id"], category="kyc_account_freeze",
                           channel="sms", narrative=ENGLISH, locality="Adyar", occurred_at=None,
                           consent=True, visibility="public", reporter_id=None, auto_approve=True)
    b = analyzer.analyze(ENGLISH, session=session, persist=True)
    r2 = rep.create_report(session, analysis_id=b["analysis_id"], category="kyc_account_freeze",
                           channel="sms", narrative=ENGLISH, locality="Adyar", occurred_at=None,
                           consent=True, visibility="public", reporter_id=None, auto_approve=False)
    assert r2["duplicate_candidates"], "identical template must be flagged as a duplicate"

    merged = rep.merge(session, r2["report"]["id"], r1["report"]["id"])
    session.commit()
    assert merged.status == "merged"
    assert merged.duplicate_of == r1["report"]["id"]


def test_public_feed_masks_contact_details(session):
    from app.intel import reports as rep
    masked = rep.redact("call 9123456780 or mail scammer@example.com")
    assert "9123456780" not in masked
    assert "scammer@example.com" not in masked


def test_message_fingerprint_survives_url_and_amount_rotation():
    a = graph.message_fingerprint("Pay Rs.850 at http://a-one.site/pay or parcel returns")
    b = graph.message_fingerprint("Pay Rs.4,999 at http://b-two.club/pay or parcel returns")
    assert a == b


# --------------------------------------------------------------------------
# Explainability & honesty
# --------------------------------------------------------------------------
def test_intent_signals_always_carry_evidence_spans():
    norm = language.normalize(ENGLISH)
    res = classify(norm.normalized, norm.folded)
    assert res.signals
    for s in res.signals:
        assert s.evidence_span


def test_degraded_check_is_reported_when_there_is_no_session():
    res = analyzer.analyze(ENGLISH, session=None, persist=False)
    assert any(d["check"] == "campaign_correlation" for d in res["degraded_checks"])
    assert res["uncertainties"]


def test_disclaimer_is_always_present():
    res = analyzer.analyze(LEGIT, session=None, persist=False)
    assert "not" in res["disclaimer"].lower()
