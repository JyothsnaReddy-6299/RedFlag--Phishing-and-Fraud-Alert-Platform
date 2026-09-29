import pytest
from app.services.homograph_detector import homograph_detector
from app.services.url_normalizer import url_normalizer
from app.services.url_analyzer import url_analyzer
from app.services.risk_scorer import url_risk_scorer


def test_detect_punycode_prefix_xn():
    url = "http://xn--ggle-55da.com/login"
    norm = url_normalizer.normalize(url)

    assert norm.has_punycode is True
    assert norm.has_unicode is True
    assert norm.homograph_risk == "CRITICAL"
    assert norm.homograph_summary == "HOMOGRAPH RISK: Mixed/Confusable characters detected"
    assert norm.is_mixed_script is True
    assert "Cyrillic" in norm.detected_scripts
    assert "Latin" in norm.detected_scripts


def test_detect_unicode_hostname_with_confusables():
    # Cyrillic 'о' (U+043E) visually mimics Latin 'o'
    spoofed = "g\u043e\u043egle.com"
    res = homograph_detector.analyze(spoofed)

    assert res.has_unicode is True
    assert res.has_punycode is True
    assert res.homograph_risk == "CRITICAL"
    assert res.summary_message == "HOMOGRAPH RISK: Mixed/Confusable characters detected"
    assert len(res.confusables_detected) == 2
    assert res.confusables_detected[0]["char"] == "о"
    assert res.confusables_detected[0]["target_char"] == "o"
    assert res.confusables_detected[0]["script"] == "Cyrillic"
    assert res.confusables_detected[0]["codepoint"] == "U+043E"


def test_detect_mixed_scripts():
    # Latin 'g', Cyrillic 'о', Latin 'gle'
    spoofed = "g\u043e\u043egle.com"
    res = homograph_detector.analyze(spoofed)

    assert res.is_mixed_script is True
    assert "Latin" in res.detected_scripts
    assert "Cyrillic" in res.detected_scripts
    assert any("Mixed scripts detected" in s for s in res.signals)


def test_paypal_cyrillic_homoglyph():
    # Cyrillic 'р' (U+0440) replacing Latin 'p' in paypal.com
    spoofed = "\u0440aypal.com"
    norm = url_normalizer.normalize(spoofed)

    assert norm.has_homograph_attack is True
    assert norm.homograph_risk == "CRITICAL"
    assert norm.is_mixed_script is True
    assert any(c["target_char"] == "p" for c in norm.confusables_detected)


def test_legitimate_unicode_not_treated_as_malicious():
    # 'münchen.de' uses Latin script with umlaut - single script, no homoglyphs
    legit_idn = "https://münchen.de/portal"
    features = url_analyzer.analyze(legit_idn)

    # Unicode is acknowledged as a signal, NOT as a critical malicious threat
    assert features.homograph_analysis.has_unicode is True
    assert features.homograph_analysis.is_mixed_script is False
    assert len(features.homograph_analysis.confusables_detected) == 0
    assert features.homograph_risk == "LOW"
    assert features.has_homograph_attack is False
    # Score is low / safe
    assert features.base_risk_score < 20.0

    # Risk evaluation remains SAFE
    scan_res = url_risk_scorer.evaluate(features)
    assert scan_res.risk_level in ["SAFE_LOW", "SUSPICIOUS"]


def test_standard_ascii_domain():
    res = homograph_detector.analyze("google.com")

    assert res.has_punycode is False
    assert res.has_unicode is False
    assert res.is_mixed_script is False
    assert res.homograph_risk == "NONE"
    assert len(res.confusables_detected) == 0


def test_end_to_end_homograph_threat_signals():
    url = "http://g\u043e\u043egle.com/auth"
    features = url_analyzer.analyze(url)
    scan_res = url_risk_scorer.evaluate(features)

    assert scan_res.homograph_risk == "CRITICAL"
    assert scan_res.is_mixed_script is True
    assert len(scan_res.confusables_detected) >= 1
    assert any("HOMOGRAPH RISK: Mixed/Confusable characters detected" in sig for sig in scan_res.contributing_factors)
    assert any("Mixed scripts detected" in sig for sig in scan_res.contributing_factors)
    assert scan_res.risk_score >= 60
    assert scan_res.risk_level in ["HIGH_RISK", "CRITICAL"]
