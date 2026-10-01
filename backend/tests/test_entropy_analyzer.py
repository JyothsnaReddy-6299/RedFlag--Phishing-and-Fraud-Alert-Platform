import pytest
from app.services.entropy_analyzer import calculate_shannon_entropy, entropy_analyzer
from app.services.url_analyzer import url_analyzer
from app.services.risk_scorer import url_risk_scorer


def test_calculate_shannon_entropy_basics():
    # Empty and single char
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("a") == 0.0
    # Homogeneous string (zero information surprise)
    assert calculate_shannon_entropy("aaaaaaa") == 0.0
    # Two symbols equally distributed (1 bit per symbol)
    assert calculate_shannon_entropy("abababab") == 1.0
    # High randomness
    random_str = "x8j9q2m4l1z0k7"
    ent = calculate_shannon_entropy(random_str)
    assert ent > 3.0


def test_separate_component_entropy():
    # URL with normal domain but long random query token
    domain = "google.com"
    subdomain = "mail"
    path = "inbox"
    query = "session_token=8a7f4c2e1b9d0e5f6a8b7c4d3e2f1a0b"

    result = entropy_analyzer.analyze(
        domain=domain,
        subdomain=subdomain,
        path=path,
        query=query,
        is_untrusted_domain=False,
        is_suspicious_tld=False,
        brand_impersonated=None,
        is_official_domain=True
    )

    # Domain entropy should be moderate (~2.5 - 3.2)
    assert 2.0 <= result.domain_entropy <= 3.5
    # Query entropy should be calculated separately and elevated
    assert result.query_entropy >= 3.5
    # Official domain immunity: no compound risk
    assert result.has_compound_risk is False
    assert len(result.signals) == 0


def test_compound_threat_detection():
    # High entropy domain + high-abuse TLD + brand impersonation
    high_ent_domain = "amaz0n-xj84k92mql.xyz"
    result = entropy_analyzer.analyze(
        domain=high_ent_domain,
        subdomain=None,
        path=None,
        query=None,
        is_untrusted_domain=True,
        is_suspicious_tld=True,
        brand_impersonated="AMAZON",
        is_official_domain=False
    )

    assert result.has_compound_risk is True
    assert result.compound_explanation is not None
    assert "Compound threat detected" in result.compound_explanation
    assert "AMAZON" in result.compound_explanation
    assert len(result.signals) > 0


def test_isolated_query_entropy_does_not_trigger_compound_threat():
    # High query entropy on an untrusted domain without brand mimicry
    result = entropy_analyzer.analyze(
        domain="simple-blog.org",
        subdomain=None,
        path="article/123",
        query="hash=7f9a8b1c2d3e4f5a6b7c8d9e0f",
        is_untrusted_domain=True,
        is_suspicious_tld=False,
        brand_impersonated=None,
        is_official_domain=False
    )

    # High query entropy alone must not trigger compound risk
    assert result.has_compound_risk is False


def test_url_analyzer_produces_discrete_entropy_fields():
    test_url = "https://sub.amaz0n-xj84k92mql.xyz/verify/account?token=abcdef1234567890"
    analysis = url_analyzer.analyze(test_url)

    assert analysis.domain_entropy is not None
    assert analysis.subdomain_entropy is not None
    assert analysis.path_entropy is not None
    assert analysis.query_entropy is not None
    assert analysis.entropy_analysis is not None
    assert analysis.entropy_analysis.domain_entropy == analysis.domain_entropy
    assert analysis.entropy_analysis.has_compound_risk is True

    # Check lexical vector contains discrete entropy values
    assert analysis.lexical_vector is not None
    assert analysis.lexical_vector.domain_entropy == analysis.domain_entropy
    assert analysis.lexical_vector.path_entropy == analysis.path_entropy
    assert analysis.lexical_vector.query_entropy == analysis.query_entropy


def test_risk_scorer_includes_compound_entropy_advice():
    test_url = "https://amaz0n-xj84k92mql.xyz/login"
    analysis = url_analyzer.analyze(test_url)
    scan_response = url_risk_scorer.evaluate(analysis)

    assert scan_response.domain_entropy is not None
    assert scan_response.entropy_analysis is not None
    assert scan_response.entropy_analysis.has_compound_risk is True
    assert any("Compound threat" in f for f in scan_response.contributing_factors)
