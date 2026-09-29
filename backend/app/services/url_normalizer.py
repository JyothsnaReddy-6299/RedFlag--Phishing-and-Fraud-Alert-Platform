import re
import urllib.parse
import posixpath
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Set

# RFC 3986 Section 2.3 - Unreserved characters (ALPHA / DIGIT / "-" / "." / "_" / "~")
UNRESERVED_ASCII: Set[int] = set(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~"
)

# Standard protocol default ports to strip during normalization
DEFAULT_PORTS = {
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


@dataclass
class NormalizedURLResult:
    """Structured result of the URL normalization layer."""
    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    canonical_domain: str
    punycode_domain: str
    unicode_domain: str
    port: Optional[int]
    path: str
    query: str
    fragment: str
    stripped_tracking_params: List[str] = field(default_factory=list)
    has_homograph_attack: bool = False
    is_ip_address: bool = False


class URLNormalizer:
    """
    Production-grade URL normalization engine conforming to RFC 3986.
    
    Performs:
    - Mixed-case scheme handling (e.g. hTTps:// -> https://)
    - Lowercase hostname & DNS trailing dot removal
    - Unnecessary default port removal (:80 for HTTP, :443 for HTTPS)
    - RFC 3986 safe unreserved percent-encoding decoding
    - Clean separation of scheme, hostname, port, path, query, fragment
    - Removal of advertising/analytics tracking parameters & query sorting
    - 'www.' normalization for canonical domain resolution
    - IDN / Punycode conversion & homoglyph spoofing detection
    - Deterministic storage of both original and normalized URLs
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

        # 2. Lowercase hostname & 3. Remove trailing dots (FQDN root dot)
        hostname = host_part.strip().rstrip(".").lower()

        # 4. Remove unnecessary default ports
        if raw_port and raw_port == DEFAULT_PORTS.get(scheme):
            port = None
        else:
            port = raw_port

        # 8. Normalize www prefix for canonical domain
        canonical_domain = hostname
        if hostname.startswith("www.") and len(hostname.split(".")) > 2:
            canonical_domain = hostname[4:]

        # 9. Normalize IDN / Punycode & Homoglyph detection
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))
        has_homograph = False
        punycode_domain = hostname
        unicode_domain = hostname

        if not is_ip and hostname:
            try:
                # Convert domain to ASCII Punycode
                punycode_domain = hostname.encode("idna").decode("ascii")
                # Convert back to Unicode for canonical representation
                unicode_domain = punycode_domain.encode("ascii").decode("idna")

                # Detect IDN homograph attack:
                # If punycode contains xn-- or if non-ASCII characters exist in domain
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

        # 5. Path normalization & safe percent-decoding
        path = normalize_path(parsed.path)

        # 6 & 7. Query parameter filtering, safe decoding & deterministic sorting
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

            # Sort retained params deterministically
            retained_params.sort(key=lambda item: item[0])
            clean_query = urllib.parse.urlencode(retained_params, doseq=True)
        else:
            clean_query = ""

        # Fragment normalization
        fragment = decode_safe_percent(parsed.fragment) if parsed.fragment else ""

        # Construct destination netloc for normalized URL:
        # Use punycode domain if IDN homograph attack is detected to reveal the actual DNS address
        dest_host = puny_canonical if has_homograph else canonical_domain
        netloc_normalized = dest_host + (f":{port}" if port else "")

        query_part = f"?{clean_query}" if clean_query else ""
        frag_part = f"#{fragment}" if fragment else ""

        normalized_url = f"{scheme}://{netloc_normalized}{path}{query_part}{frag_part}"

        return NormalizedURLResult(
            original_url=original,
            normalized_url=normalized_url,
            scheme=scheme,
            hostname=hostname,
            canonical_domain=canonical_domain,
            punycode_domain=punycode_domain,
            unicode_domain=unicode_domain,
            port=port,
            path=path,
            query=clean_query,
            fragment=fragment,
            stripped_tracking_params=stripped_tracking,
            has_homograph_attack=has_homograph,
            is_ip_address=is_ip,
        )


url_normalizer = URLNormalizer()
