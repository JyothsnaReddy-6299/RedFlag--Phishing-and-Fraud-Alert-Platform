import pytest
from app.services.lexical_analyzer import lexical_analyzer, LexicalFeatureVector, SemanticPatterns
from app.services.url_analyzer import url_analyzer
from app.services.risk_scorer import url_risk_scorer


def test_lexical_vector_feature_extraction():
    url = "http://secure-login.portal.bank-update.xyz:8080/kyc/verify/account?session_id=12345&claim=bonus&refund=0#frag"
    domain = "secure-login.portal.bank-update.xyz"
    subdomain = "secure-login.portal"
    path = "/kyc/verify/account"
    query = "session_id=12345&claim=bonus&refund=0"
    port = 8080

    vec = lexical_analyzer.extract_vector(
        full_url=url,
        domain=domain,
        subdomain=subdomain,
        path=path,
        query=query,
        port=port,
        is_ip_host=False
    )

    # 1. Lengths
    assert vec.url_length == len(url)
    assert vec.domain_length == len(domain)
    assert vec.path_length == len(path)
    assert vec.query_length == len(query)

    # 2. Subdomain and Path Depths
    assert vec.subdomain_count == 2  # 'secure-login' and 'portal'
    assert vec.subdomain_depth == 2
    assert vec.path_depth == 3  # 'kyc', 'verify', 'account'

    # 3. Query Parameter Count
    assert vec.query_parameter_count == 3  # 'session_id', 'claim', 'refund'

    # 4. Character counts
    assert vec.dot_count == url.count(".")
    assert vec.hyphen_count == url.count("-")
    assert vec.underscore_count == url.count("_")
    assert vec.digit_count == sum(1 for c in url if c.isdigit())
    assert vec.special_character_count > 0

    # 5. Ratios
    assert vec.digit_ratio == pytest.approx(vec.digit_count / len(url), 0.001)
    assert vec.special_character_ratio == pytest.approx(vec.special_character_count / len(url), 0.001)

    # 6. Boolean Flags
    assert vec.has_ip_host is False
    assert vec.has_port is True
    assert vec.has_at_symbol is False
    assert vec.has_punycode is False
    assert vec.has_percent_encoding is False

    # 7. Semantic Patterns
    assert vec.semantic_patterns.login is True
    assert vec.semantic_patterns.verify is True
    assert vec.semantic_patterns.secure is True
    assert vec.semantic_patterns.account is True
    assert vec.semantic_patterns.update is True
    assert vec.semantic_patterns.kyc is True
    assert vec.semantic_patterns.claim is True
    assert vec.semantic_patterns.bonus is True
    assert vec.semantic_patterns.refund is True
    assert vec.semantic_patterns.wallet is False
    assert vec.semantic_patterns.payment is False
    assert vec.semantic_patterns.support is False

    # 8. Principle Verification
    assert "evidence, not proof" in vec.evidence_summary
    assert "evidence, not proof" in vec.semantic_patterns.evidence_note


def test_ip_host_and_obfuscation_flags():
    url = "http://192.168.1.1:8000/path%20test/@target"
    vec = lexical_analyzer.extract_vector(
        full_url=url,
        domain="192.168.1.1",
        subdomain="",
        path="/path%20test/@target",
        query="",
        port=8000,
        is_ip_host=True,
        original_url=url
    )

    assert vec.has_ip_host is True
    assert vec.has_port is True
    assert vec.has_at_symbol is True
    assert vec.has_percent_encoding is True
    assert vec.has_punycode is False


def test_punycode_detection():
    url = "https://xn--e1afmkfd.xn--p1ai/login"
    vec = lexical_analyzer.extract_vector(
        full_url=url,
        domain="xn--e1afmkfd.xn--p1ai",
        subdomain="",
        path="/login",
        query="",
        port=None
    )

    assert vec.has_punycode is True
    assert vec.semantic_patterns.login is True


def test_all_twelve_semantic_patterns():
    semantic_url = "https://example.com/login/verify/secure/account/update/kyc/wallet/payment/refund/bonus/claim/support"
    patterns = lexical_analyzer.extract_semantic_patterns(semantic_url)

    expected = ["login", "verify", "secure", "account", "update", "kyc", "wallet", "payment", "refund", "bonus", "claim", "support"]
    for kw in expected:
        assert getattr(patterns, kw) is True, f"Keyword '{kw}' should be detected as True"
    assert patterns.keyword_count == 12
    assert "evidence, not proof" in patterns.evidence_note


def test_evidence_not_proof_on_official_domain():
    """
    On an official authentic domain (e.g. amazon.com/account/login),
    having 'account' and 'login' is normal user functionality.
    It MUST NOT cause the URL to be falsely flagged as phishing.
    """
    features = url_analyzer.analyze("https://www.amazon.com/gp/css/account/login")
    response = url_risk_scorer.evaluate(features)

    assert features.is_official_domain is True
    assert response.risk_score == 0
    assert response.risk_level.value == "SAFE_LOW"
    assert response.category.value == "LEGITIMATE"
    assert features.lexical_vector is not None
    assert features.lexical_vector.semantic_patterns.login is True
    assert features.lexical_vector.semantic_patterns.account is True


def test_evidence_not_proof_on_benign_blog():
    """
    On a standard benign website with a word like 'update' or 'support' in the path,
    the keyword is recorded as contextual evidence without causing an immediate phishing alert.
    """
    features = url_analyzer.analyze("https://github.blog/2026-01-15-security-update/")
    response = url_risk_scorer.evaluate(features)

    # Should remain safe/low risk or low suspicious, NOT critical phishing
    assert response.risk_score < 40
    assert features.lexical_vector is not None
    assert features.lexical_vector.semantic_patterns.update is True
    assert features.lexical_vector.semantic_patterns.secure is True
    assert any("evidence" in s.lower() for s in features.threat_signals if "semantic" in s.lower() or "keyword" in s.lower())


def test_lexical_vector_present_in_full_scan_pipeline():
    features = url_analyzer.analyze("http://amaz0n-security-login.xyz/portal/verify")
    assert features.lexical_vector is not None
    assert features.path_length == len("/portal/verify")
    assert features.path_depth == 2
    assert features.dot_count >= 1
    assert features.hyphen_count >= 2
    assert features.digit_count >= 1
    assert features.semantic_patterns.login is True
    assert features.semantic_patterns.verify is True
    assert features.semantic_patterns.secure is True
