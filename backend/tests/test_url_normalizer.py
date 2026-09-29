import pytest
from app.services.url_normalizer import url_normalizer
from app.services.url_analyzer import url_analyzer
from app.services.risk_scorer import url_risk_scorer


def test_lowercase_hostname():
    url = "https://OnLiNeSbI.sBi.BaNk.In/portal"
    res = url_normalizer.normalize(url)
    assert res.hostname == "onlinesbi.sbi.bank.in"
    assert res.canonical_domain == "onlinesbi.sbi.bank.in"
    assert "https://onlinesbi.sbi.bank.in/portal" in res.normalized_url


def test_remove_unnecessary_default_ports():
    # Port 80 for HTTP should be removed
    res_http = url_normalizer.normalize("http://example.com:80/home")
    assert res_http.port is None
    assert res_http.normalized_url == "http://example.com/home"

    # Port 443 for HTTPS should be removed
    res_https = url_normalizer.normalize("https://example.com:443/secure")
    assert res_https.port is None
    assert res_https.normalized_url == "https://example.com/secure"

    # Non-default ports must be retained
    res_custom = url_normalizer.normalize("http://example.com:8080/api")
    assert res_custom.port == 8080
    assert res_custom.normalized_url == "http://example.com:8080/api"

    res_https_custom = url_normalizer.normalize("https://example.com:8443/api")
    assert res_https_custom.port == 8443
    assert res_https_custom.normalized_url == "https://example.com:8443/api"


def test_normalize_trailing_dots():
    url = "https://sbi.bank.in./login"
    res = url_normalizer.normalize(url)
    assert res.hostname == "sbi.bank.in"
    assert res.canonical_domain == "sbi.bank.in"
    assert res.normalized_url == "https://sbi.bank.in/login"


def test_decode_safe_percent_encoding():
    # %73%62%69 is 'sbi' (unreserved), %2D is '-', %2E is '.', %7E is '~'
    url = "https://example.com/%73%62%69/%2Etest%2Dpath%7E"
    res = url_normalizer.normalize(url)
    assert res.path == "/sbi/.test-path~"

    # Reserved characters like %2F or %20 should retain their encoding but uppercase hex
    url_reserved = "https://example.com/path%2fsub%20item"
    res_reserved = url_normalizer.normalize(url_reserved)
    assert "%2F" in res_reserved.path or "/path%2Fsub%20item" in res_reserved.path


def test_separate_components():
    url = "https://user:pass@sbi.co.in:8443/retail/login?view=web#summary"
    res = url_normalizer.normalize(url)
    assert res.scheme == "https"
    assert res.hostname == "sbi.co.in"
    assert res.canonical_domain == "sbi.co.in"
    assert res.port == 8443
    assert res.path == "/retail/login"
    assert res.query == "view=web"
    assert res.fragment == "summary"


def test_strip_irrelevant_tracking_parameters():
    url = "https://example.com/checkout?utm_source=newsletter&id=99281&fbclid=AQD123&action=buy&gclid=G456&ref=email"
    res = url_normalizer.normalize(url)
    assert "utm_source" in res.stripped_tracking_params
    assert "fbclid" in res.stripped_tracking_params
    assert "gclid" in res.stripped_tracking_params
    assert "ref" in res.stripped_tracking_params
    # Legitimate params preserved and sorted alphabetically
    assert res.query == "action=buy&id=99281"
    assert res.normalized_url == "https://example.com/checkout?action=buy&id=99281"


def test_normalize_www():
    url = "https://www.hdfcbank.com/personal"
    res = url_normalizer.normalize(url)
    assert res.canonical_domain == "hdfcbank.com"
    assert res.normalized_url == "https://hdfcbank.com/personal"

    # www.com should not strip www since it's the second-level domain
    res_www = url_normalizer.normalize("http://www.com/index")
    assert res_www.canonical_domain == "www.com"


def test_handle_mixed_case_schemes():
    url_https = "hTTps://secure.bank.in/auth"
    res_https = url_normalizer.normalize(url_https)
    assert res_https.scheme == "https"
    assert res_https.normalized_url.startswith("https://")

    url_http = "hTtp://insecure.site.com"
    res_http = url_normalizer.normalize(url_http)
    assert res_http.scheme == "http"
    assert res_http.normalized_url.startswith("http://")

    # Missing scheme should default gracefully
    url_no_scheme = "example.com/dashboard"
    res_no_scheme = url_normalizer.normalize(url_no_scheme)
    assert res_no_scheme.scheme == "http"
    assert res_no_scheme.normalized_url == "http://example.com/dashboard"


def test_idn_punycode_homograph_detection():
    # Cyrillic 'о' (U+043E) homoglyph spoofing 'google.com'
    spoofed_domain = "g\u043e\u043egle.com"
    url = f"http://{spoofed_domain}/login"
    res = url_normalizer.normalize(url)

    assert res.has_homograph_attack is True
    assert res.punycode_domain.startswith("xn--")
    assert res.normalized_url.startswith("http://xn--")

    # Standard ASCII domain should not trigger homograph flag
    legit_url = "https://google.com/search"
    res_legit = url_normalizer.normalize(legit_url)
    assert res_legit.has_homograph_attack is False
    assert res_legit.punycode_domain == "google.com"


def test_store_both_original_and_normalized_url():
    raw_input = "hTTps://OnLiNeSbI.sBi.BaNk.In.:443/%73%62%69/login//test?utm_source=email&action=verify&fbclid=1234#FragMent"
    res = url_normalizer.normalize(raw_input)

    assert res.original_url == raw_input
    assert res.normalized_url == "https://onlinesbi.sbi.bank.in/sbi/login/test?action=verify#FragMent"

    # End-to-end analyzer check
    features = url_analyzer.analyze(raw_input)
    assert features.original_url == raw_input
    assert features.normalized_url == "https://onlinesbi.sbi.bank.in/sbi/login/test?action=verify#FragMent"
    assert "utm_source" in features.stripped_tracking_params
    assert "fbclid" in features.stripped_tracking_params

    # Risk scorer check
    response = url_risk_scorer.evaluate(features)
    assert response.original_url == raw_input
    assert response.normalized_url == "https://onlinesbi.sbi.bank.in/sbi/login/test?action=verify#FragMent"
    assert "utm_source" in response.stripped_tracking_params
