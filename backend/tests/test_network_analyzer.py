import pytest
from backend.app.services.network_analyzer import (
    network_analyzer,
    check_is_ip_address,
    check_is_unusual_port,
    lookup_asn_info
)
from backend.app.services.url_analyzer import url_analyzer
from backend.app.services.risk_scorer import url_risk_scorer


def test_check_is_ip_address():
    # IPv4 public
    is_ip, ver, is_priv = check_is_ip_address("8.8.8.8")
    assert is_ip is True
    assert ver == "IPv4"
    assert is_priv is False

    # IPv4 private
    is_ip, ver, is_priv = check_is_ip_address("192.168.1.1")
    assert is_ip is True
    assert ver == "IPv4"
    assert is_priv is True

    # IPv6 bracketed
    is_ip, ver, is_priv = check_is_ip_address("[2001:db8::1]")
    assert is_ip is True
    assert ver == "IPv6"

    # Domain name (not IP)
    is_ip, ver, is_priv = check_is_ip_address("amazon.com")
    assert is_ip is False
    assert ver is None


def test_check_is_unusual_port():
    assert check_is_unusual_port(None) is False
    assert check_is_unusual_port(80) is False
    assert check_is_unusual_port(443) is False
    assert check_is_unusual_port(8080) is True
    assert check_is_unusual_port(8443) is True
    assert check_is_unusual_port(8888) is True
    assert check_is_unusual_port(21) is True


def test_asn_lookup_private_and_known():
    # Private IP
    asn, org, country = lookup_asn_info("10.0.0.1")
    assert asn == "Private"
    assert "Private Network" in org

    # Well-known fallback
    asn, org, country = lookup_asn_info("8.8.8.8")
    assert asn == "AS15169"
    assert "Google" in org


def test_network_analyzer_ip_host_signal():
    res = network_analyzer.analyze(
        hostname="185.220.101.5",
        port=8080,
        scheme="http"
    )

    assert res.is_ip_host is True
    assert res.ip_version == "IPv4"
    assert res.is_unusual_port is True
    assert "ip_based_url" in res.signal_flags
    assert "unusual_port" in res.signal_flags
    assert any("ip_based_url" in s for s in res.signals)
    assert any("unusual_port" in s for s in res.signals)


def test_network_analyzer_dns_failure_signal():
    # Simulated DNS failure
    res = network_analyzer.analyze(
        hostname="nonexistent-domain-test-12345.xyz",
        port=None,
        override_dns_res=(False, [], [], "NXDOMAIN / Name or service not known")
    )

    assert res.dns_resolved is False
    assert res.dns_failure is True
    assert "dns_failure" in res.signal_flags
    assert any("dns_failure" in s for s in res.signals)


def test_network_analyzer_multiple_ips_signal():
    # Simulated multi-IP / Fast-Flux resolution
    res = network_analyzer.analyze(
        hostname="cdn-target.example",
        port=443,
        override_dns_res=(True, ["104.16.1.1", "104.16.1.2"], ["2606:4700::1"], None)
    )

    assert res.dns_resolved is True
    assert res.has_multiple_ips is True
    assert res.ip_version == "Dual-Stack"
    assert "multiple_ips" in res.signal_flags
    assert any("multiple_ips" in s for s in res.signals)


def test_url_analyzer_integration_with_network_signals():
    # Raw IP URL with unusual port
    raw_url = "http://192.168.1.100:8888/login"
    features = url_analyzer.analyze(raw_url)

    assert features.network_analysis is not None
    assert features.is_ip_host is True
    assert features.is_unusual_port is True
    assert any("ip_based_url" in s for s in features.threat_signals)
    assert any("unusual_port" in s for s in features.threat_signals)

    # Risk score evaluation
    response = url_risk_scorer.evaluate(features)
    assert response.is_ip_host is True
    assert response.is_unusual_port is True
    assert response.network_analysis is not None
    assert any("Direct IP Host" in f for f in response.contributing_factors)
    assert any("Non-Standard Port" in f for f in response.contributing_factors)
