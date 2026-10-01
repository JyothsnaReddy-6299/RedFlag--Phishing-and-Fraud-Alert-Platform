import pytest
from backend.app.services.url_expander import (
    url_expander,
    is_shortened_url_candidate,
    KNOWN_SHORTENER_DOMAINS
)
from backend.app.services.url_analyzer import url_analyzer
from backend.app.services.risk_scorer import url_risk_scorer


def test_is_shortened_url_candidate():
    # Known shortener domains
    assert is_shortened_url_candidate("http://bit.ly/3xY7zQ")[0] is True
    assert is_shortened_url_candidate("https://tinyurl.com/abc1234")[0] is True
    assert is_shortened_url_candidate("http://t.co/xyz123")[0] is True
    assert is_shortened_url_candidate("https://is.gd/test99")[0] is True

    # Standard benign domains (not shorteners)
    assert is_shortened_url_candidate("https://www.google.com/search?q=test")[0] is False
    assert is_shortened_url_candidate("https://amazon.com/dp/item123")[0] is False


def test_url_expander_non_shortened_url():
    raw_url = "https://example.com/standard-path"
    res = url_expander.expand(raw_url)

    assert res.is_shortened is False
    assert res.shortener_domain is None
    assert res.destination_url == raw_url
    assert res.destination_domain == "example.com"
    assert res.hop_count == 0


def test_url_expander_with_mock_resolution():
    short_url = "http://bit.ly/3xY7zQ"
    final_dest = "http://unknown-example.xyz/login"
    chain = [short_url, final_dest]

    res = url_expander.expand(
        short_url,
        override_destination=final_dest,
        override_chain=chain
    )

    assert res.is_shortened is True
    assert res.shortener_domain == "bit.ly"
    assert res.original_url == short_url
    assert res.destination_url == final_dest
    assert res.destination_domain == "unknown-example.xyz"
    assert res.hop_count == 1
    assert res.redirect_chain == chain
    assert any("Shortened URL detected" in s for s in res.signals)


def test_url_analyzer_analyzes_final_destination():
    # Short URL resolving to unknown-example.xyz
    short_url = "http://bit.ly/phish123"
    dest_url = "http://unknown-example.xyz/login"
    chain = [short_url, dest_url]

    analysis = url_analyzer.analyze(
        short_url,
        override_destination=dest_url,
        override_chain=chain
    )

    # 1. Keeps original + final in evidence
    assert analysis.original_url == short_url
    assert analysis.destination_url == dest_url
    assert analysis.destination_domain == "unknown-example.xyz"
    assert analysis.is_shortened_url is True
    assert analysis.shortener_domain == "bit.ly"
    assert analysis.redirect_chain == chain

    # 2. Analyzes final destination (domain is unknown-example.xyz, NOT bit.ly)
    assert analysis.domain == "unknown-example.xyz"
    assert analysis.tld == "xyz"

    # 3. Shortened URL signal emitted
    assert any("Shortened URL detected" in s for s in analysis.threat_signals)


def test_risk_scorer_incorporates_shortener_evidence():
    short_url = "https://tinyurl.com/amaz0n-deal"
    dest_url = "http://amaz0n-security-login.xyz/login"

    analysis = url_analyzer.analyze(
        short_url,
        override_destination=dest_url,
        override_chain=[short_url, dest_url]
    )

    response = url_risk_scorer.evaluate(analysis)

    assert response.is_shortened_url is True
    assert response.shortener_domain == "tinyurl.com"
    assert response.destination_url == dest_url
    assert response.destination_domain == "amaz0n-security-login.xyz"
    assert any("Shortened URL Masking" in f for f in response.contributing_factors)
    assert any("Shortened URL detected" in a for a in response.mitigation_advice)
