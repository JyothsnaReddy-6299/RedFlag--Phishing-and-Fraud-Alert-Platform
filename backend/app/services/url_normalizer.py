import re
import urllib.parse
import posixpath
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Set, Dict, Any

# RFC 3986 Section 2.3 - Unreserved characters (ALPHA / DIGIT / "-" / "." / "_" / "~")
UNRESERVED_ASCII: Set[int] = set(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~"
)

# Standard protocol default ports to strip during normalization
DEFAULT_PORTS: Dict[str, int] = {
    "http": 80,
    "https": 443,
    "ftp": 21,
    "ws": 80,
    "wss": 443,
}

# Tracking, telemetry, and affiliate marketing query parameters to strip
TRACKING_PARAMS: Set[str] = {
    # UTM tags (Google Analytics & general campaign tracking)
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_source_platform", "utm_creative_format", "utm_marketing_tactic",
    # Advertising Click IDs
    "fbclid", "gclid", "gclsrc", "dclid", "msclkid", "yclid", "twclid", "igshid",
    # Email / Marketing Automation trackers
    "mc_cid", "mc_eid", "_hsenc", "_hsmi", "wickedid",
    # Generic referral & sharing tags
    "ref", "ref_src", "ref_url", "source", "feature",
}

# Common second-level domain designations across national registries
COMMON_SECOND_LEVELS: Set[str] = {
    "co", "com", "org", "net", "gov", "edu", "ac", "bank", "nic", "res",
    "gen", "firm", "ind", "govt", "ne", "or", "go", "ltd", "plc", "me",
    "mil", "police", "asn", "id", "iwi", "geek", "sch", "ad", "gr", "lg",
    "art", "per", "idv", "pol", "bel", "pp"
}

# Explicit multi-part Public Suffix overrides
KNOWN_MULTI_PART_TLDS: Set[str] = {
    # India
    "co.in", "bank.in", "gov.in", "edu.in", "ac.in", "org.in", "net.in",
    "nic.in", "res.in", "gen.in", "firm.in", "ind.in", "mil.in",
    # United Kingdom
    "co.uk", "org.uk", "gov.uk", "ac.uk", "net.uk", "me.uk", "ltd.uk",
    "plc.uk", "sch.uk", "police.uk",
    # Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    # New Zealand
    "co.nz", "org.nz", "net.nz", "govt.nz", "edu.nz", "ac.nz", "iwi.nz", "geek.nz",
    # South Africa
    "co.za", "org.za", "gov.za", "ac.za", "net.za",
    # Japan
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ed.jp", "ad.jp", "gr.jp", "lg.jp",
    # Brazil
    "com.br", "gov.br", "org.br", "net.br", "edu.br", "mil.br", "art.br",
    # Singapore & Hong Kong
    "com.sg", "edu.sg", "gov.sg", "org.sg", "net.sg", "per.sg",
    "com.hk", "edu.hk", "gov.hk", "org.hk", "net.hk", "idv.hk",
    # Canada, Malaysia, Philippines, Taiwan, China, Turkey, Mexico, Argentina, Colombia
    "gc.ca", "com.my", "gov.my", "edu.my", "org.my",
    "com.ph", "gov.ph", "edu.ph", "org.ph",
    "com.tw", "gov.tw", "edu.tw", "org.tw",
    "com.cn", "gov.cn", "edu.cn", "org.cn",
    "com.tr", "gov.tr", "edu.tr", "org.tr",
    "com.mx", "gov.mx", "edu.mx", "org.mx",
    "com.ar", "gov.ar", "edu.ar", "org.ar",
    "com.co", "gov.co", "edu.co", "org.co",
}


def decode_safe_percent(text: str) -> str:
    """
    Decodes RFC 3986 unreserved percent-encoded characters:
    ALPHA (a-z, A-Z), DIGIT (0-9), hyphen (-), period (.), underscore (_), and tilde (~).
    Normalizes remaining reserved percent-encoded characters to uppercase hex (e.g., %2f -> %2F).
    """
    def _repl(match: re.Match) -> str:
        hex_val = match.group(1)
        byte_val = int(hex_val, 16)
        if byte_val in UNRESERVED_ASCII:
            return chr(byte_val)
        return f"%{hex_val.upper()}"

    return re.sub(r"%([0-9a-fA-F]{2})", _repl, text)


def normalize_path(path: str) -> str:
    """
    Normalizes URL path:
    1. Safe percent-decoding of unreserved characters.
    2. Collapses consecutive slashes (e.g., '//' -> '/').
    3. Resolves dot segments ('.' and '..') per RFC 3986.
    4. Preserves trailing slash semantics.
    """
    if not path or path == "/":
        return "/"

    ends_with_slash = path.endswith("/")
    decoded = decode_safe_percent(path)
    collapsed = re.sub(r"/+", "/", decoded)
    norm = posixpath.normpath(collapsed)

    if not norm.startswith("/"):
        norm = "/" + norm

    if ends_with_slash and not norm.endswith("/"):
        norm += "/"

    return norm


def decompose_domain(hostname: str) -> Tuple[str, str, str]:
    """
    Decomposes a normalized hostname into:
      (subdomain, registered_domain, tld)
    
    Correctly recognizes multi-part public suffixes (e.g. .bank.in, .co.uk, .com.au)
    so registered_domain represents the root domain (eTLD+1), not a TLD fragment.
    """
    if not hostname:
        return "", "", ""

    # Raw IPv4 or bracketed IPv6 addresses have no subdomain or TLD
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) or hostname.startswith("["):
        return "", hostname, ""

    parts = hostname.lower().split(".")
    if len(parts) <= 1:
        return "", hostname, ""

    # Check 2-part TLD:
    two_part = f"{parts[-2]}.{parts[-1]}"
    if len(parts) >= 3 and (
        two_part in KNOWN_MULTI_PART_TLDS
        or (len(parts[-1]) == 2 and parts[-2] in COMMON_SECOND_LEVELS)
    ):
        tld = two_part
        suffix_len = 2
    else:
        tld = parts[-1]
        suffix_len = 1

    if len(parts) > suffix_len:
        registered_domain = f"{parts[-(suffix_len + 1)]}.{tld}"
        subdomain = ".".join(parts[:-(suffix_len + 1)])
    else:
        registered_domain = hostname
        subdomain = ""

    return subdomain, registered_domain, tld


@dataclass
class URLComponents:
    """The 8 fundamental architectural components of a URL."""
    scheme: str
    subdomain: str
    registered_domain: str
    tld: str
    port: Optional[int]
    path: str
    query: str
    fragment: str

    @property
    def TLD(self) -> str:
        """Alias for uppercase TLD."""
        return self.tld

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scheme": self.scheme,
            "subdomain": self.subdomain,
            "registered_domain": self.registered_domain,
            "tld": self.tld,
            "TLD": self.tld,
            "port": self.port,
            "path": self.path,
            "query": self.query,
            "fragment": self.fragment,
        }


@dataclass
class NormalizedURLResult:
    """Structured result of the URL normalization layer."""
    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    canonical_domain: str
    subdomain: str
    registered_domain: str
    tld: str
    punycode_domain: str
    unicode_domain: str
    port: Optional[int]
    path: str
    query: str
    fragment: str
    components: URLComponents
    stripped_tracking_params: List[str] = field(default_factory=list)
    has_homograph_attack: bool = False
    is_ip_address: bool = False

    @property
    def TLD(self) -> str:
        """Alias for uppercase TLD."""
        return self.tld


class URLNormalizer:
    """
    Production-grade URL normalization and decomposition engine conforming to RFC 3986.
    
    Breaks any URL into its 8 structural components:
    - scheme
    - subdomain
    - registered_domain
    - TLD (multi-part aware)
    - port
    - path
    - query
    - fragment
    """

    def normalize(self, raw_url: str) -> NormalizedURLResult:
        original = raw_url.strip()

        # 1. Scheme handling & mixed-case normalization
        scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://(.*)$", original)
        if scheme_match:
            scheme = scheme_match.group(1).lower()
            remainder = scheme_match.group(2)
            url_to_parse = f"{scheme}://{remainder}"
        elif original.startswith("//"):
            scheme = "http"
            url_to_parse = f"http:{original}"
        else:
            scheme = "http"
            url_to_parse = f"http://{original}"

        parsed = urllib.parse.urlsplit(url_to_parse)
        netloc = parsed.netloc

        # Strip userinfo if present (e.g. user:pass@host)
        if "@" in netloc:
            _, netloc = netloc.split("@", 1)

        # Separate host and port
        if ":" in netloc:
            host_part, port_str = netloc.rsplit(":", 1)
            try:
                raw_port = int(port_str)
            except ValueError:
                host_part = netloc
                raw_port = None
        else:
            host_part = netloc
            raw_port = None

        # 2. Lowercase hostname & DNS trailing dot removal
        hostname = host_part.strip().rstrip(".").lower()

        # 3. Remove unnecessary default ports (:80 for HTTP, :443 for HTTPS)
        if raw_port and raw_port == DEFAULT_PORTS.get(scheme):
            port = None
        else:
            port = raw_port

        # 4. Decompose domain into subdomain, registered_domain, and TLD
        subdomain, registered_domain, tld = decompose_domain(hostname)

        # 5. Canonical domain (without leading www.)
        canonical_domain = hostname
        if hostname.startswith("www.") and len(hostname.split(".")) > 2:
            canonical_domain = hostname[4:]

        # 6. IDN / Punycode & Homoglyph detection
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))
        has_homograph = False
        punycode_domain = hostname
        unicode_domain = hostname

        if not is_ip and hostname:
            try:
                punycode_domain = hostname.encode("idna").decode("ascii")
                unicode_domain = punycode_domain.encode("ascii").decode("idna")

                if punycode_domain.startswith("xn--") or ".xn--" in punycode_domain:
                    has_homograph = True
                elif any(ord(c) > 127 for c in hostname):
                    has_homograph = True
            except Exception:
                punycode_domain = hostname
                unicode_domain = hostname

        # Also compute punycode for canonical domain if applicable
        puny_canonical = canonical_domain
        if not is_ip and canonical_domain:
            try:
                puny_canonical = canonical_domain.encode("idna").decode("ascii")
            except Exception:
                puny_canonical = canonical_domain

        # 7. Path normalization & safe percent-decoding
        path = normalize_path(parsed.path)

        # 8. Query parameter filtering, safe decoding & deterministic sorting
        query_str = parsed.query
        stripped_tracking: List[str] = []
        retained_params: List[Tuple[str, str]] = []

        if query_str:
            pairs = urllib.parse.parse_qsl(query_str, keep_blank_values=True)
            for k, v in pairs:
                k_dec = decode_safe_percent(k)
                v_dec = decode_safe_percent(v)
                k_lower = k_dec.lower()
                if k_lower in TRACKING_PARAMS or k_lower.startswith("utm_"):
                    stripped_tracking.append(k_dec)
                else:
                    retained_params.append((k_dec, v_dec))

            retained_params.sort(key=lambda item: item[0])
            clean_query = urllib.parse.urlencode(retained_params, doseq=True)
        else:
            clean_query = ""

        # 9. Fragment normalization
        fragment = decode_safe_percent(parsed.fragment) if parsed.fragment else ""

        # Reconstruct canonical normalized URL
        dest_host = puny_canonical if has_homograph else canonical_domain
        netloc_normalized = dest_host + (f":{port}" if port else "")

        query_part = f"?{clean_query}" if clean_query else ""
        frag_part = f"#{fragment}" if fragment else ""

        normalized_url = f"{scheme}://{netloc_normalized}{path}{query_part}{frag_part}"

        # 10. Package full 8-part URL decomposition components
        components = URLComponents(
            scheme=scheme,
            subdomain=subdomain,
            registered_domain=registered_domain,
            tld=tld,
            port=port,
            path=path,
            query=clean_query,
            fragment=fragment,
        )

        return NormalizedURLResult(
            original_url=original,
            normalized_url=normalized_url,
            scheme=scheme,
            hostname=hostname,
            canonical_domain=canonical_domain,
            subdomain=subdomain,
            registered_domain=registered_domain,
            tld=tld,
            punycode_domain=punycode_domain,
            unicode_domain=unicode_domain,
            port=port,
            path=path,
            query=clean_query,
            fragment=fragment,
            components=components,
            stripped_tracking_params=stripped_tracking,
            has_homograph_attack=has_homograph,
            is_ip_address=is_ip,
        )

    def decompose(self, raw_url: str) -> URLComponents:
        """
        Decomposes a URL string into its 8 discrete architectural components:
        (scheme, subdomain, registered_domain, tld, port, path, query, fragment).
        """
        return self.normalize(raw_url).components


url_normalizer = URLNormalizer()
