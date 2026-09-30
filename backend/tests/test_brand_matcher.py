import pytest
from app.services.brand_matcher import (
    brand_matcher,
    damerau_levenshtein_distance,
    normalized_similarity,
    unmask_digits,
    unmask_char_substitutions,
    detect_character_differences,
)
from app.services.url_analyzer import url_analyzer


def test_damerau_levenshtein_distance():
    # Exact match
    assert damerau_levenshtein_distance("amazon", "amazon") == 0
    # Substitution
    assert damerau_levenshtein_distance("amaz0n", "amazon") == 1
    # Transposition of adjacent characters
    assert damerau_levenshtein_distance("sbi", "sib") == 1
    assert damerau_levenshtein_distance("amzaon", "amazon") == 1
    # Deletion / omission
    assert damerau_levenshtein_distance("amzon", "amazon") == 1
    # Insertion / extra character
    assert damerau_levenshtein_distance("amazonn", "amazon") == 1


def test_normalized_similarity():
    assert normalized_similarity("amazon", "amazon") == 1.0
    assert normalized_similarity("amaz0n", "amazon") == pytest.approx(0.833, 0.01)
    assert normalized_similarity("abc", "xyz") == 0.0


def test_digit_unmasking():
    unmasked, manips = unmask_digits("amaz0n")
    assert unmasked == "amazon"
    assert any("0" in m and "o" in m for m in manips)

    unmasked_pp, manips_pp = unmask_digits("paypa1")
    assert unmasked_pp == "paypal"
    assert any("1" in m and "l" in m for m in manips_pp)


def test_char_substitution_unmasking():
    unmasked, manips = unmask_char_substitutions("arnazon")
    assert unmasked == "amazon"
    assert any("rn" in m for m in manips)


def test_character_differences():
    diffs_omission = detect_character_differences("amzon", "amazon")
    assert any("omitted 'a'" in d for d in diffs_omission)

    diffs_addition = detect_character_differences("amazonn", "amazon")
    assert any("added 'n'" in d for d in diffs_addition)

    diffs_transposition = detect_character_differences("amzaon", "amazon")
    assert any("adjacent transposition" in d for d in diffs_transposition)


def test_candidate_amaz0n_security_login_xyz():
    """
    Candidate: amaz0n-security-login.xyz vs Official amazon.com
    Must recognize:
      - brand similarity = high
      - TLD mismatch (.xyz vs official amazon TLDs [.com, .in, ...])
      - additional deceptive tokens: ['security', 'login']
      - digit substitution ('0' -> 'o')
      - evaluated on registered domain stem ('amaz0n-security-login')
    """
    res = brand_matcher.analyze_domain("amaz0n-security-login.xyz", "xyz")

    assert res.is_official_domain is False
    assert res.brand_impersonated == "AMAZON"
    assert res.brand_similarity_rating == "HIGH"
    assert res.brand_similarity_score >= 0.85
    assert res.tld_mismatch is True
    assert "com" in res.official_tlds
    assert res.candidate_tld == "xyz"
    assert "security" in res.deceptive_tokens
    assert "login" in res.deceptive_tokens
    assert any("0" in m and "o" in m for m in res.manipulation_types)
    assert any("hyphen manipulation" in m for m in res.manipulation_types)

    # Check threat signals
    signals_str = " ".join(res.signals)
    assert "Brand similarity = high" in signals_str
    assert "TLD mismatch" in signals_str
    assert "Additional deceptive token(s)" in signals_str


def test_candidate_paypa1_support_cc():
    res = brand_matcher.analyze_domain("paypa1-support.cc", "cc")
    assert res.brand_impersonated == "PAYPAL"
    assert res.brand_similarity_rating == "HIGH"
    assert res.tld_mismatch is True
    assert "support" in res.deceptive_tokens
    assert any("1" in m and "l" in m for m in res.manipulation_types)


def test_candidate_sbi_kyc_portal_xyz():
    res = brand_matcher.analyze_domain("sbi-kyc-portal.xyz", "xyz")
    assert res.brand_impersonated == "SBI"
    assert res.brand_similarity_rating == "HIGH"
    assert res.tld_mismatch is True
    assert "kyc" in res.deceptive_tokens
    assert "portal" in res.deceptive_tokens


def test_candidate_arnazon_top():
    res = brand_matcher.analyze_domain("arnazon.top", "top")
    assert res.brand_impersonated == "AMAZON"
    assert res.brand_similarity_rating == "HIGH"
    assert res.tld_mismatch is True
    assert any("rn" in m and "m" in m for m in res.manipulation_types)


def test_official_amazon_domain():
    res = brand_matcher.analyze_domain("amazon.com", "com")
    assert res.is_official_domain is True
    assert res.tld_mismatch is False
    assert res.brand_similarity_rating == "NONE"


def test_official_amazon_in_domain():
    res = brand_matcher.analyze_domain("amazon.in", "in")
    assert res.is_official_domain is True
    assert res.tld_mismatch is False


def test_benign_non_brand_domain():
    res = brand_matcher.analyze_domain("example.com", "com")
    assert res.is_official_domain is False
    assert res.brand_impersonated is None
    assert res.brand_similarity_rating == "NONE"
    assert res.tld_mismatch is False
    assert len(res.deceptive_tokens) == 0


def test_url_analyzer_integration_amaz0n_security_login():
    """
    Verifies that the full URL analyzer pipeline processes candidate
    http://amaz0n-security-login.xyz/verify and populates:
      - brand_impersonated = 'AMAZON'
      - brand_similarity_rating = 'HIGH'
      - tld_mismatch = True
      - deceptive_tokens = ['security', 'login']
      - high risk score
    """
    analysis = url_analyzer.analyze("http://amaz0n-security-login.xyz/verify")

    assert analysis.registered_domain == "amaz0n-security-login.xyz"
    assert analysis.tld == "xyz"
    assert analysis.brand_impersonated == "AMAZON"
    assert analysis.brand_similarity_rating == "HIGH"
    assert analysis.tld_mismatch is True
    assert "security" in analysis.deceptive_tokens
    assert "login" in analysis.deceptive_tokens
    assert analysis.base_risk_score >= 80

    signals_text = " ".join(analysis.threat_signals)
    assert "Brand similarity = high" in signals_text
    assert "TLD mismatch" in signals_text
    assert "Additional deceptive token(s)" in signals_text
