"""
Network & Infrastructure Intelligence Engine
---------------------------------------------
Moves beyond textual URL lexical patterns to evaluate network-layer signals:
  - Host is IP? (IPv4 / IPv6 / private bogon)
  - DNS resolution status (A / AAAA records) & DNS failure detection
  - IP protocol versioning (IPv4 / IPv6 / Dual-Stack)
  - Explicit port evaluation (standard 80/443 vs unusual ports)
  - Autonomous System Number (ASN) & Organization lookup
  - Fast-Flux / Multi-IP detection (multiple distinct IPs)

Signals Emitted:
  - ip_based_url: Host is a direct IP address bypassing domain reputation
  - unusual_port: URL targets non-standard network ports
  - dns_failure: Domain fails DNS resolution (disposable, sinkholed, unconfigured)
  - multiple_ips: Domain resolves to multiple distinct IPs (Fast-Flux / CDN)
"""

import socket
import ipaddress
import concurrent.futures
from typing import Optional, List, Tuple, Dict
import httpx

from backend.app.models.schemas import NetworkAnalysis


# In-memory local cache for ASN lookups to prevent duplicate network calls
_ASN_CACHE: Dict[str, Tuple[Optional[str], Optional[str], Optional[str]]] = {}

# Well-known ASN fallback ranges for offline/isolated test stability
_WELL_KNOWN_PREFIXES: Dict[str, Tuple[str, str, str]] = {
    "8.8.8.8": ("AS15169", "Google LLC", "US"),
    "8.8.4.4": ("AS15169", "Google LLC", "US"),
    "1.1.1.1": ("AS13335", "Cloudflare, Inc.", "US"),
    "1.0.0.1": ("AS13335", "Cloudflare, Inc.", "US"),
    "142.250": ("AS15169", "Google LLC", "US"),
    "172.217": ("AS15169", "Google LLC", "US"),
    "104.16": ("AS13335", "Cloudflare, Inc.", "US"),
    "104.17": ("AS13335", "Cloudflare, Inc.", "US"),
}


def check_is_ip_address(host: str) -> Tuple[bool, Optional[str], bool]:
    """
    Determines whether a host string is an IP address (IPv4 or IPv6),
    and whether it is private/loopback/reserved.
    Returns: (is_ip, ip_version, is_private)
    """
    if not host:
        return False, None, False

    clean = host.strip("[]").strip()
    try:
        ip = ipaddress.ip_address(clean)
        version = f"IPv{ip.version}"
        is_priv = bool(ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local)
        return True, version, is_priv
    except ValueError:
        return False, None, False


def check_is_unusual_port(port: Optional[int], scheme: str = "http") -> bool:
    """
    Checks if the URL port is unusual/non-standard.
    Standard web ports:
      - 80 (HTTP)
      - 443 (HTTPS)
      - None (defaults to 80/443 based on scheme)
    Any non-empty port other than 80 and 443 is flagged as unusual.
    """
    if port is None:
        return False
    return port not in (80, 443)


def perform_dns_resolution(
    hostname: str,
    timeout: float = 1.5
) -> Tuple[bool, List[str], List[str], Optional[str]]:
    """
    Performs DNS resolution on a hostname with timeout protection.
    Returns: (dns_resolved, resolved_ipv4, resolved_ipv6, error_message)
    """
    if not hostname:
        return False, [], [], "Empty hostname"

    clean_host = hostname.strip("[]").strip()

    def _resolve():
        return socket.getaddrinfo(
            clean_host,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_resolve)
        try:
            records = future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            return False, [], [], f"DNS resolution timed out after {timeout}s"
        except socket.gaierror as e:
            return False, [], [], f"DNS getaddrinfo failed: {e}"
        except Exception as e:
            return False, [], [], f"DNS resolution error: {e}"

    ipv4_addrs: List[str] = []
    ipv6_addrs: List[str] = []

    for item in records:
        family = item[0]
        sockaddr = item[4]
        if not sockaddr:
            continue
        ip_str = sockaddr[0]
        if family == socket.AF_INET and ip_str not in ipv4_addrs:
            ipv4_addrs.append(ip_str)
        elif family == socket.AF_INET6 and ip_str not in ipv6_addrs:
            ipv6_addrs.append(ip_str)

    resolved = len(ipv4_addrs) > 0 or len(ipv6_addrs) > 0
    return resolved, ipv4_addrs, ipv6_addrs, None if resolved else "No A or AAAA records found"


def lookup_asn_info(
    ip_str: str,
    timeout: float = 1.5
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Queries Autonomous System (ASN) and Organization info for an IP address.
    Returns: (asn, asn_org, asn_country)
    """
    if not ip_str:
        return None, None, None

    clean_ip = ip_str.strip("[]").strip()

    # 1. Check in-memory cache
    if clean_ip in _ASN_CACHE:
        return _ASN_CACHE[clean_ip]

    # 2. Check if private or loopback
    is_ip, _, is_priv = check_is_ip_address(clean_ip)
    if is_ip and is_priv:
        res = ("Private", "RFC1918 / Private Network", "Local")
        _ASN_CACHE[clean_ip] = res
        return res

    # 3. Check well-known prefix fallbacks (offline/fast match)
    for prefix, data in _WELL_KNOWN_PREFIXES.items():
        if clean_ip.startswith(prefix):
            _ASN_CACHE[clean_ip] = data
            return data

    # 4. Perform fast lookup via ip-api.com
    try:
        url = f"http://ip-api.com/json/{clean_ip}?fields=status,countryCode,as,asname"
        response = httpx.get(url, timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                as_full = data.get("as", "")
                country = data.get("countryCode")
                asn_num = None
                asn_name = data.get("asname")

                if as_full:
                    parts = as_full.split(" ", 1)
                    asn_num = parts[0] if parts[0].upper().startswith("AS") else None
                    if not asn_name and len(parts) > 1:
                        asn_name = parts[1]

                res = (asn_num or as_full or None, asn_name or None, country or None)
                _ASN_CACHE[clean_ip] = res
                return res
    except Exception:
        pass

    return None, None, None


class NetworkAnalyzer:
    def __init__(self, dns_timeout: float = 1.5, asn_timeout: float = 1.5):
        self.dns_timeout = dns_timeout
        self.asn_timeout = asn_timeout

    def analyze(
        self,
        hostname: str,
        port: Optional[int] = None,
        scheme: str = "http",
        override_dns_res: Optional[Tuple[bool, List[str], List[str], Optional[str]]] = None,
        override_asn: Optional[Tuple[Optional[str], Optional[str], Optional[str]]] = None
    ) -> NetworkAnalysis:
        """
        Performs network-level analysis:
          1. Host is IP?
          2. DNS resolution check (A/AAAA)
          3. IPv4 / IPv6 / Dual-Stack categorization
          4. Non-standard port detection
          5. ASN & Organization lookup
          6. Multi-IP / Fast-Flux signal generation
        """
        clean_host = (hostname or "").strip().lower()

        # 1. Host is IP check
        is_ip, ip_ver, is_priv = check_is_ip_address(clean_host)

        resolved_ips: List[str] = []
        resolved_ipv4: List[str] = []
        resolved_ipv6: List[str] = []
        dns_resolved = False
        dns_failure = False
        dns_err: Optional[str] = None
        ip_protocol_version: Optional[str] = None

        if is_ip:
            # Direct IP host — no DNS lookup needed
            dns_resolved = True
            dns_failure = False
            raw_ip = clean_host.strip("[]")
            resolved_ips = [raw_ip]
            if ip_ver == "IPv4":
                resolved_ipv4 = [raw_ip]
            else:
                resolved_ipv6 = [raw_ip]
            ip_protocol_version = ip_ver
        else:
            # 2. DNS Resolution for domain name
            if override_dns_res is not None:
                dns_resolved, resolved_ipv4, resolved_ipv6, dns_err = override_dns_res
            else:
                dns_resolved, resolved_ipv4, resolved_ipv6, dns_err = perform_dns_resolution(
                    clean_host,
                    timeout=self.dns_timeout
                )

            if dns_resolved:
                resolved_ips = resolved_ipv4 + resolved_ipv6
                if len(resolved_ipv4) > 0 and len(resolved_ipv6) > 0:
                    ip_protocol_version = "Dual-Stack"
                elif len(resolved_ipv4) > 0:
                    ip_protocol_version = "IPv4"
                elif len(resolved_ipv6) > 0:
                    ip_protocol_version = "IPv6"
                dns_failure = False
            else:
                dns_failure = True
                ip_protocol_version = None

        # 3. Multi-IP / Fast-Flux check
        has_multiple = len(resolved_ips) > 1

        # 4. Port analysis
        unusual_port = check_is_unusual_port(port, scheme)

        # 5. ASN Lookup
        asn_val: Optional[str] = None
        asn_org_val: Optional[str] = None
        asn_country_val: Optional[str] = None

        if override_asn is not None:
            asn_val, asn_org_val, asn_country_val = override_asn
        elif resolved_ips:
            primary_ip = resolved_ips[0]
            asn_val, asn_org_val, asn_country_val = lookup_asn_info(
                primary_ip,
                timeout=self.asn_timeout
            )

        # 6. Signals Generation
        signal_flags: List[str] = []
        signals: List[str] = []

        if is_ip:
            signal_flags.append("ip_based_url")
            signals.append(
                f"ip_based_url: Host uses raw IP address instead of domain hostname ({clean_host}, {ip_ver}) "
                f"disguising domain identity and bypassing domain-name reputation filters"
            )

        if unusual_port:
            signal_flags.append("unusual_port")
            signals.append(
                f"unusual_port: URL targets non-standard network port (:{port}) "
                f"often used to host malicious phishing kits on compromised residential or cloud proxies"
            )

        if dns_failure:
            signal_flags.append("dns_failure")
            signals.append(
                f"dns_failure: Domain fails DNS resolution ({dns_err or 'NXDOMAIN'}) "
                f"indicating disposable, sinkholed, or unconfigured phishing infrastructure"
            )

        if has_multiple:
            signal_flags.append("multiple_ips")
            signals.append(
                f"multiple_ips: Host resolves to {len(resolved_ips)} distinct IP addresses "
                f"({', '.join(resolved_ips[:3])}{'...' if len(resolved_ips) > 3 else ''}) "
                f"indicating multi-homed infrastructure, CDN, or Fast-Flux DNS routing"
            )

        return NetworkAnalysis(
            is_ip_host=is_ip,
            ip_version=ip_protocol_version,
            is_private_ip=is_priv,
            dns_resolved=dns_resolved,
            dns_failure=dns_failure,
            dns_error_message=dns_err,
            resolved_ips=resolved_ips,
            resolved_ipv4=resolved_ipv4,
            resolved_ipv6=resolved_ipv6,
            has_multiple_ips=has_multiple,
            port=port,
            is_unusual_port=unusual_port,
            asn=asn_val,
            asn_org=asn_org_val,
            asn_country=asn_country_val,
            signal_flags=signal_flags,
            signals=signals
        )


network_analyzer = NetworkAnalyzer()
