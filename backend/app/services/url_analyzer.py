import math
import re
from urllib.parse import urlparse
from typing import List, Tuple, Optional, Dict
from app.models.schemas import URLFeatureAnalysis

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "work", "click", "buzz", "rest", "cam", "live",
    "loan", "tk", "ml", "ga", "cf", "gq", "site", "online", "cc", "fun",
    "bid", "racing", "win", "stream", "gdn", "date", "faith", "review",
    "zip", "link", "surf", "space", "icu", "monster", "cfd"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "update", "secure", "account", "banking",
    "kyc", "pan", "aadhaar", "otp", "password", "support", "confirm", "signin",
    "ebank", "netbanking", "wallet", "refund", "claim", "bonus", "reward", "free",
    "recharge", "suspend", "suspended", "restore", "reactivate", "alert", "notice"
]

# Official Domain Whitelist for Major Brands & Indian Financial Institutions
TARGET_BRANDS: Dict[str, List[str]] = {
    "sbi": [
        "onlinesbi.sbi", "sbi.co.in", "sbi.sbi", "bank.sbi",
        "statebankofindia.com", "sbi.bank.in", "onlinesbi.sbi.bank.in",
        "retail.sbi.bank.in", "corporate.sbi.bank.in", "sbi-card.com", "sbicard.com"
    ],
    "hdfc": [
        "hdfcbank.com", "hdfc.com", "hdfc.bank.in", "hdfcbank.bank.in",
        "hdfcbank.net", "hdfcsec.com"
    ],
    "icici": [
        "icicibank.com", "icici.com", "icici.bank.in", "icicidirect.com"
    ],
    "axis": [
        "axisbank.com", "axis.bank.in"
    ],
    "pnb": [
        "pnbindia.in", "pnb.bank.in"
    ],
    "canara": [
        "canarabank.com", "canara.bank.in"
    ],
    "bankofbaroda": [
        "bankofbaroda.in", "bankofbaroda.com", "bob.bank.in"
    ],
    "kotak": [
        "kotak.com", "kotak.bank.in", "kotakcherry.com"
    ],
    "rbi": [
        "rbi.org.in"
    ],
    "paytm": [
        "paytm.com", "paytmbank.com", "paytm.bank.in"
    ],
    "phonepe": [
        "phonepe.com"
    ],
    "gpay": [
        "google.com", "pay.google.com"
    ],
    "google": [
        "google.com", "google.co.in", "accounts.google.com", "myaccount.google.com"
    ],
    "apple": [
        "apple.com", "icloud.com", "appleid.apple.com"
    ],
    "microsoft": [
        "microsoft.com", "live.com", "office.com", "login.microsoftonline.com"
    ],
    "amazon": [
        "amazon.in", "amazon.com"
    ],
    "netflix": [
        "netflix.com"
    ],
    "paypal": [
        "paypal.com"
    ],
    "tneb": [
        "tnebltd.gov.in", "tangedco.gov.in", "tnebltd.com"
    ],
    "indiapost": [
        "indiapost.gov.in", "ippbonline.com", "ippb.bank.in"
    ]
}

# Seed list of known malicious threat intelligence feeds (URLhaus / PhishTank)
KNOWN_MALICIOUS_DOMAINS: Dict[str, Dict[str, str]] = {
    "sbi-kyc-update.xyz": {"category": "PHISHING", "source": "ThreatFeed_URLhaus"},
    "hdfc-rewards-claim.top": {"category": "PHISHING", "source": "ThreatFeed_PhishTank"},
    "icici-netbanking-verify.cc": {"category": "PHISHING", "source": "ThreatFeed_OpenPhish"},
    "paytm-cashback-bonus.live": {"category": "PHISHING", "source": "ThreatFeed_URLhaus"},
    "tneb-bill-payment.net": {"category": "PHISHING", "source": "ThreatFeed_Community"},
    "free-netflix-subscription.club": {"category": "PHISHING", "source": "ThreatFeed_PhishTank"},
    "paypal-account-recovery.top": {"category": "PHISHING", "source": "ThreatFeed_URLhaus"}
}

def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

class URLAnalyzer:
    def __init__(self):
        self.ip_pattern = re.compile(
            r'^(?:http[s]?://)?(?:www\.)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/.*)?$'
        )
        self.hex_encoding_pattern = re.compile(r'%[0-9a-fA-F]{2}')

    def check_official_domain(self, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Checks if a domain belongs to a verified official brand or protected banking/gov namespace.
        In India, '.bank.in' is exclusively allocated by IDRBT/RBI to licensed commercial banks.
        '.gov.in' and '.nic.in' are exclusively allocated to Indian government organizations.
        """
        domain_clean = domain.lower()

        # Check explicit brand whitelist
        for brand, official_domains in TARGET_BRANDS.items():
            for legit in official_domains:
                if domain_clean == legit or domain_clean.endswith("." + legit):
                    return True, brand.upper()

        # Check protected official namespaces
        if domain_clean.endswith(".bank.in"):
            bank_name = domain_clean.split(".bank.in")[0].split(".")[-1]
            return True, f"{bank_name.upper()} (Authorized .bank.in)"

        if domain_clean.endswith(".gov.in") or domain_clean.endswith(".nic.in"):
            return True, "Government of India (.gov.in)"

        return False, None

    def analyze(self, raw_url: str) -> URLFeatureAnalysis:
        raw_url = raw_url.strip()
        if not raw_url.startswith(("http://", "https://")):
            full_url = "http://" + raw_url
        else:
            full_url = raw_url

        parsed = urlparse(full_url)
        protocol = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        port = parsed.port

        # Strip port from netloc for domain analysis
        domain = netloc.split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]

        path = parsed.path.lower()
        query = parsed.query.lower()

        # Check official domain status FIRST
        is_official, official_brand = self.check_official_domain(domain)

        # 1. IP-based Host detection
        ip_based = bool(self.ip_pattern.match(full_url)) or bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))

        # 2. Subdomains
        parts = domain.split(".")
        subdomain_count = max(0, len(parts) - 2) if len(parts) >= 2 else 0

        # 3. TLD
        tld = parts[-1] if len(parts) > 1 else ""
        suspicious_tld = tld in SUSPICIOUS_TLDS

        # 4. Special Characters & Obfuscation
        special_chars = set("@-_~%&=?")
        special_char_count = sum(1 for c in full_url if c in special_chars)
        has_at_symbol = "@" in full_url
        has_double_slash = "//" in path
        has_hex_encoding = bool(self.hex_encoding_pattern.search(full_url))

        # 5. Shannon Entropy
        entropy = calculate_shannon_entropy(domain)

        # 6. Sensitive keywords
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url.lower()]

        # 7. Brand Impersonation check (Only if domain is NOT verified official)
        impersonated_brand = None
        similarity_score = 0.0

        if not is_official:
            impersonated_brand, similarity_score = self._check_brand_impersonation(domain, full_url)

        # 8. Threat Signal Aggregation
        signals = []
        score = 0.0

        # If verified official, grant trust immunity from structural false positives
        if is_official:
            signals.append(f"Verified Official Portal: Belongs to {official_brand} authorized domain registry")
            base_risk_score = 0.0
        else:
            if ip_based:
                signals.append("URL uses raw IP address instead of domain hostname (bypasses DNS reputation)")
                score += 35.0

            if has_at_symbol:
                signals.append("URL contains '@' symbol to mislead user about target destination")
                score += 30.0

            if has_double_slash:
                signals.append("URL contains embedded double slashes ('//') in path used for redirection evasion")
                score += 20.0

            if has_hex_encoding:
                signals.append("URL uses hex/percent encoding to obfuscate malicious path segments")
                score += 15.0

            if suspicious_tld:
                signals.append(f"Domain uses high-abuse top-level domain (.{tld}) commonly seen in throwaway phishing")
                score += 20.0

            if len(full_url) > 75:
                signals.append(f"Excessive URL length ({len(full_url)} characters) indicating token stuffing or cloaking")
                score += 15.0

            if subdomain_count >= 3:
                signals.append(f"Unusually deep subdomain nesting ({subdomain_count} subdomains)")
                score += 20.0

            if entropy > 4.2:
                signals.append(f"High Shannon entropy ({entropy}) indicating algorithmically generated domain name")
                score += 18.0

            if port and port not in [80, 443]:
                signals.append(f"URL uses non-standard network port (:{port})")
                score += 20.0

            if impersonated_brand:
                signals.append(f"Brand impersonation detected: deceptive lookalike of '{impersonated_brand}' without authorization")
                score += 40.0

            if len(found_keywords) >= 2:
                signals.append(f"Multiple social-engineering keywords in URL: {', '.join(found_keywords[:4])}")
                score += min(30.0, len(found_keywords) * 8.0)
            elif len(found_keywords) == 1:
                signals.append(f"Sensitive credential/banking keyword in URL: {found_keywords[0]}")
                score += 10.0

            if protocol == "http" and (impersonated_brand or len(found_keywords) > 0):
                signals.append("Insecure HTTP protocol used for sensitive banking or login interaction")
                score += 15.0

            base_risk_score = min(100.0, max(0.0, round(score, 1)))

        return URLFeatureAnalysis(
            url=full_url,
            domain=domain,
            protocol=protocol,
            port=port,
            ip_based=ip_based,
            url_length=len(full_url),
            domain_length=len(domain),
            subdomain_count=subdomain_count,
            special_char_count=special_char_count,
            entropy=entropy,
            suspicious_tld=suspicious_tld,
            detected_tld=tld,
            suspicious_keywords=found_keywords,
            brand_impersonated=impersonated_brand,
            brand_similarity_score=similarity_score,
            is_official_domain=is_official,
            official_brand_name=official_brand,
            has_at_symbol=has_at_symbol,
            has_double_slash=has_double_slash,
            has_hex_encoding=has_hex_encoding,
            threat_signals=signals,
            base_risk_score=base_risk_score
        )

    def check_threat_feeds(self, domain: str) -> Optional[Dict[str, str]]:
        domain_clean = domain.lower()
        if domain_clean in KNOWN_MALICIOUS_DOMAINS:
            return KNOWN_MALICIOUS_DOMAINS[domain_clean]
        return None

    def _check_brand_impersonation(self, domain: str, full_url: str) -> Tuple[Optional[str], float]:
        url_lower = full_url.lower()

        for brand, official_domains in TARGET_BRANDS.items():
            # If domain is already one of the official domains, it's NOT an impersonator
            if any(domain == legit or domain.endswith("." + legit) for legit in official_domains):
                continue

            # Substring match on foreign domain (e.g. sbi in sbi-update.xyz)
            if brand in domain:
                return (brand.upper(), 0.95)

            # Levenshtein distance on domain labels (e.g. 'sbii' or 'paytmm')
            parts = domain.split(".")
            for part in parts:
                if len(part) >= 3:
                    dist = levenshtein_distance(part, brand)
                    if dist == 1 and len(brand) >= 3:
                        return (brand.upper(), 0.90)

            # Brand in path/subdomain with sensitive keywords on unauthorized domain
            if brand in url_lower:
                if any(kw in url_lower for kw in ["login", "kyc", "update", "verify", "pay", "auth"]):
                    return (brand.upper(), 0.85)

        return (None, 0.0)

url_analyzer = URLAnalyzer()
