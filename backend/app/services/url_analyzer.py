import math
import re
from urllib.parse import urlparse
from typing import List, Tuple, Optional
from app.models.schemas import URLFeatureAnalysis

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "work", "click", "buzz", "rest", "cam", "live",
    "loan", "tk", "ml", "ga", "cf", "gq", "site", "online", "cc", "fun",
    "bid", "racing", "win", "stream", "gdn", "date", "faith", "review", "zip"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "update", "secure", "account", "banking",
    "kyc", "pan", "aadhaar", "otp", "password", "support", "confirm", "disconnection",
    "bill", "free", "reward", "prize", "gift", "bonus", "claim", "wallet", "refund",
    "suspend", "suspended", "reactivate", "restore", "alert", "notice", "emergency"
]

TARGET_BRANDS = {
    "sbi": ["onlinesbi.sbi", "sbi.co.in", "statebankofindia.com"],
    "hdfc": ["hdfcbank.com", "hdfc.com"],
    "icici": ["icicibank.com"],
    "axis": ["axisbank.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "gpay": ["google.com", "pay.google.com"],
    "tneb": ["tnebltd.gov.in", "tangedco.gov.in"],
    "indiapost": ["indiapost.gov.in"],
    "epfo": ["epfindia.gov.in"],
    "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"],
    "netflix": ["netflix.com"],
    "whatsapp": ["whatsapp.com"],
    "telegram": ["telegram.org", "t.me"]
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

    def analyze(self, raw_url: str) -> URLFeatureAnalysis:
        raw_url = raw_url.strip()
        if not raw_url.startswith(("http://", "https://")):
            full_url = "http://" + raw_url
        else:
            full_url = raw_url

        parsed = urlparse(full_url)
        netloc = parsed.netloc.split(":")[0].lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]

        domain = netloc
        path = parsed.path.lower()
        query = parsed.query.lower()

        # Check IP address host
        ip_based = bool(self.ip_pattern.match(full_url)) or bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))

        # Subdomains
        parts = domain.split(".")
        subdomain_count = max(0, len(parts) - 2) if len(parts) >= 2 else 0

        # TLD
        tld = parts[-1] if len(parts) > 1 else ""
        suspicious_tld = tld in SUSPICIOUS_TLDS

        # Special characters
        special_chars = set("@-_~%&=?")
        special_char_count = sum(1 for c in full_url if c in special_chars)

        # Entropy of domain name
        entropy = calculate_shannon_entropy(domain)

        # Suspicious keywords in URL
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url.lower()]

        # Brand impersonation check
        impersonated_brand, similarity_score = self._check_brand_impersonation(domain, full_url)

        # Threat signals and heuristic scoring
        signals = []
        score = 0.0

        if ip_based:
            signals.append("URL uses raw IP address instead of domain name")
            score += 35.0

        if "@" in full_url:
            signals.append("URL contains '@' symbol to obfuscate target host")
            score += 25.0

        if suspicious_tld:
            signals.append(f"Domain uses high-abuse top-level domain (.{tld})")
            score += 20.0

        if len(full_url) > 75:
            signals.append(f"Excessive URL length ({len(full_url)} characters)")
            score += 15.0

        if subdomain_count >= 3:
            signals.append(f"Unusually high number of subdomains ({subdomain_count})")
            score += 20.0

        if entropy > 4.2:
            signals.append(f"High domain entropy ({entropy}) indicating algorithmically generated name")
            score += 15.0

        if impersonated_brand:
            signals.append(f"Brand impersonation detected: mimics '{impersonated_brand}' without legitimate authorization")
            score += 40.0

        if len(found_keywords) >= 2:
            signals.append(f"Multiple social-engineering keywords in URL: {', '.join(found_keywords[:4])}")
            score += min(30.0, len(found_keywords) * 8.0)
        elif len(found_keywords) == 1:
            signals.append(f"Sensitive keyword in URL: {found_keywords[0]}")
            score += 10.0

        # Non-HTTPS penalty if sensitive keywords are present
        if full_url.startswith("http://") and (impersonated_brand or len(found_keywords) > 0):
            signals.append("Insecure HTTP protocol used for sensitive banking/login interaction")
            score += 15.0

        # Normalization
        base_risk_score = min(100.0, max(0.0, round(score, 1)))

        return URLFeatureAnalysis(
            url=full_url,
            domain=domain,
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
            threat_signals=signals,
            base_risk_score=base_risk_score
        )

    def _check_brand_impersonation(self, domain: str, full_url: str) -> Tuple[Optional[str], float]:
        domain_clean = domain.replace("-", "").replace(".", "")
        url_lower = full_url.lower()

        for brand, official_domains in TARGET_BRANDS.items():
            # If domain exactly matches official domain or is a subdomain of official domain, it is legit
            is_legit = any(domain == legit or domain.endswith("." + legit) for legit in official_domains)
            if is_legit:
                continue

            # Check if brand appears in the domain or path
            if brand in domain:
                return (brand.upper(), 0.95)

            # Check Levenshtein distance on domain chunks
            parts = domain.split(".")
            for part in parts:
                if len(part) >= 3:
                    dist = levenshtein_distance(part, brand)
                    if dist == 1 and len(brand) >= 3:  # 1 typo difference like 'sbii' or 'paytmm'
                        return (brand.upper(), 0.90)

            # Check if brand is in subdomain/path while domain is foreign
            if brand in url_lower and not is_legit:
                if any(kw in url_lower for kw in ["login", "kyc", "update", "verify", "pay"]):
                    return (brand.upper(), 0.85)

        return (None, 0.0)

url_analyzer = URLAnalyzer()
