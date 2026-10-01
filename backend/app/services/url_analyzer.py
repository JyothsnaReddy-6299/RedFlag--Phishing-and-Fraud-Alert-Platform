import math
import re
from typing import List, Tuple, Optional, Dict
from app.models.schemas import (
    URLFeatureAnalysis, URLComponents, HomographAnalysis, BrandAnalysisDetails,
    LexicalFeatureVector, SemanticPatterns, EntropyAnalysis
)
from app.services.url_normalizer import url_normalizer, URLComponents as URLComponentsData
from app.services.brand_matcher import brand_matcher, BrandMatchResult
from app.services.lexical_analyzer import lexical_analyzer
from app.services.entropy_analyzer import entropy_analyzer, calculate_shannon_entropy

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

# Strict registry of authorized Indian banks on the restricted .bank.in TLD
AUTHORIZED_BANK_IN_ENTITIES: Dict[str, str] = {
    "sbi": "State Bank of India (SBI)",
    "hdfc": "HDFC Bank",
    "hdfcbank": "HDFC Bank",
    "icici": "ICICI Bank",
    "axis": "Axis Bank",
    "pnb": "Punjab National Bank",
    "canara": "Canara Bank",
    "bob": "Bank of Baroda",
    "kotak": "Kotak Mahindra Bank",
    "unionbank": "Union Bank of India",
    "unionbankofindia": "Union Bank of India",
    "boi": "Bank of India",
    "indianbank": "Indian Bank",
    "centralbank": "Central Bank of India",
    "idbi": "IDBI Bank",
    "yesbank": "Yes Bank",
    "indusind": "IndusInd Bank",
    "federalbank": "Federal Bank",
    "rblbank": "RBL Bank",
    "ippb": "India Post Payments Bank (IPPB)",
}

# Brand aliases and service names targeted by typosquatters
BRAND_ALIASES: Dict[str, List[str]] = {
    "sbi": ["onlinesbi", "statebankofindia", "sbicard", "sbibank", "sbionline"],
    "hdfc": ["hdfcbank", "hdfcsec", "hdfcnetbanking"],
    "icici": ["icicibank", "icicidirect", "icicinetbanking"],
    "axis": ["axisbank", "axisnetbanking"],
    "pnb": ["pnbindia", "pnbnetbanking"],
    "kotak": ["kotakbank", "kotakcherry", "kotaknetbanking"],
    "paypal": ["paypalme"],
    "paytm": ["paytmbank", "paytmmall"],
    "google": ["googlepay", "gpay"],
}

BANKING_AFFIXES = [
    "online", "netbanking", "ebank", "bank", "banking", "portal",
    "corp", "corporate", "retail", "secure", "auth", "card", "pay"
]

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

def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """
    Computes Damerau-Levenshtein distance, handling insertions, deletions,
    substitutions, and transpositions of adjacent characters (e.g. 'sbi' <-> 'sib').
    """
    if s1 == s2:
        return 0
    len1, len2 = len(s1), len(s2)
    if abs(len1 - len2) > 3:
        return abs(len1 - len2)

    d = {}
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,       # deletion
                d[(i, j - 1)] + 1,       # insertion
                d[(i - 1, j - 1)] + cost # substitution
            )
            # Transposition check
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)

    return d[(len1 - 1, len2 - 1)]

class URLAnalyzer:
    def __init__(self):
        self.ip_pattern = re.compile(
            r'^(?:http[s]?://)?(?:www\.)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/.*)?$'
        )
        self.hex_encoding_pattern = re.compile(r'%[0-9a-fA-F]{2}')

    def check_official_domain(self, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Checks if a domain belongs to a verified official brand or authorized banking/gov registry.
        Does NOT grant wildcard trust to arbitrary .bank.in domains unless they are explicitly authorized.
        """
        domain_clean = domain.lower()

        # 1. Check explicit brand whitelist first
        for brand, official_domains in TARGET_BRANDS.items():
            for legit in official_domains:
                if domain_clean == legit or domain_clean.endswith("." + legit):
                    return True, brand.upper()

        # 2. Check restricted .bank.in registry against verified authorized entities
        if domain_clean.endswith(".bank.in"):
            before_tld = domain_clean[:-8]  # strip '.bank.in'
            parts = before_tld.split(".")
            root_bank = parts[-1]  # root registered organization under .bank.in

            if root_bank in AUTHORIZED_BANK_IN_ENTITIES:
                # If root entity is authorized (e.g. sbi), ensure subdomains aren't deceptive spoofing of another brand
                expected_brand = "sbi" if root_bank == "sbi" else root_bank
                has_subdomain_spoof = False
                for part in parts[:-1]:
                    # Check if subdomain typosquats a different brand
                    for other_brand, other_aliases in BRAND_ALIASES.items():
                        if other_brand == expected_brand:
                            continue
                        for target in [other_brand] + other_aliases:
                            if damerau_levenshtein_distance(part, target) <= 1:
                                has_subdomain_spoof = True
                                break
                if not has_subdomain_spoof:
                    return True, AUTHORIZED_BANK_IN_ENTITIES[root_bank]

        # 3. Check government domains (.gov.in / .nic.in)
        if domain_clean.endswith(".gov.in") or domain_clean.endswith(".nic.in"):
            return True, "Government of India (.gov.in)"

        return False, None

    def _check_brand_impersonation(self, domain: str, full_url: str) -> Tuple[Optional[str], float, List[str]]:
        """
        Advanced typosquatting and brand lookalike detection:
        Detects transpositions (e.g. 'sib' vs 'sbi', 'hfdc' vs 'hdfc'), compound typosquats
        ('onlinesib' vs 'onlinesbi'), character anagrams, and unauthorized brand keywords.
        """
        url_lower = full_url.lower()
        domain_clean = domain.lower()
        signals: List[str] = []

        for brand, official_domains in TARGET_BRANDS.items():
            # Skip if domain is verified official for this brand
            if any(domain_clean == legit or domain_clean.endswith("." + legit) for legit in official_domains):
                continue

            aliases = BRAND_ALIASES.get(brand, [])
            all_targets = [brand] + aliases

            # 1. Exact brand keyword in domain label (e.g. 'sbi-update.xyz', 'login-sbi.com')
            for part in domain_clean.split("."):
                if part in ["bank", "in", "com", "co", "org", "net"]:
                    continue

                if brand in part and part != brand:
                    signals.append(f"Brand impersonation detected: deceptive domain label '{part}' contains unauthorized brand keyword '{brand.upper()}'")
                    return (brand.upper(), 0.95, signals)

            # 2. Typosquatting / Lookalike / Anagram check across all domain labels
            parts = domain_clean.split(".")
            for part in parts:
                if part in ["bank", "in", "com", "co", "org", "net"]:
                    continue

                # A. Direct Damerau-Levenshtein distance == 1 against brand or aliases (e.g. 'sib' vs 'sbi', 'onlinesib' vs 'onlinesbi')
                for target in all_targets:
                    if part != target and damerau_levenshtein_distance(part, target) == 1:
                        signals.append(
                            f"Brand typosquatting detected: '{part}' is a deceptive lookalike/transposition of '{target}' ({brand.upper()})"
                        )
                        return (brand.upper(), 0.95, signals)

                # B. Anagram permutation for short acronyms (e.g. 'sib' vs 'sbi', 'pbn' vs 'pnb')
                for target in [brand] + [a for a in aliases if len(a) <= 4]:
                    if len(part) == len(target) and len(target) in (3, 4) and part != target and sorted(part) == sorted(target):
                        signals.append(
                            f"Deceptive anagram typosquatting: '{part}' is a character-swapped permutation of '{target.upper()}'"
                        )
                        return (brand.upper(), 0.95, signals)

                # C. Affix-stripped typosquatting (e.g. 'onlinesib' -> prefix 'online' + root 'sib' mimicking 'sbi')
                for affix in BANKING_AFFIXES:
                    root = None
                    if part.startswith(affix) and len(part) > len(affix):
                        root = part[len(affix):]
                    elif part.endswith(affix) and len(part) > len(affix):
                        root = part[:-len(affix)]

                    if root and len(root) >= 2:
                        for target in all_targets:
                            if root != target and damerau_levenshtein_distance(root, target) == 1:
                                signals.append(
                                    f"Deceptive compound typosquatting: '{part}' (root '{root}') mimics '{target}' ({brand.upper()})"
                                )
                                return (brand.upper(), 0.95, signals)
                            if len(root) == len(target) and len(target) in (3, 4) and root != target and sorted(root) == sorted(target):
                                signals.append(
                                    f"Deceptive compound typosquatting: '{part}' (root '{root}') is an anagram permutation of '{target.upper()}'"
                                )
                                return (brand.upper(), 0.95, signals)

            # 3. Brand in path or query with sensitive keywords on non-official domain
            if brand in url_lower:
                if any(kw in url_lower for kw in ["login", "kyc", "update", "verify", "pay", "auth"]):
                    signals.append(f"Unauthorized use of '{brand.upper()}' in URL path with sensitive action keywords")
                    return (brand.upper(), 0.85, signals)

        return (None, 0.0, [])

    def analyze(self, raw_url: str) -> URLFeatureAnalysis:
        # 0. RFC-compliant URL Normalization & 8-Part Decomposition Layer
        norm = url_normalizer.normalize(raw_url)
        full_url = norm.normalized_url
        domain = norm.canonical_domain
        subdomain = norm.subdomain
        registered_domain = norm.registered_domain
        tld = norm.tld
        protocol = norm.scheme
        scheme = norm.scheme
        port = norm.port
        path = norm.path.lower()
        query = norm.query
        fragment = norm.fragment

        # Check official domain status FIRST
        is_official, official_brand = self.check_official_domain(domain)
        if not is_official:
            is_off, off_name = brand_matcher.is_official_domain(registered_domain or domain)
            if is_off:
                is_official, official_brand = True, off_name
        if not is_official and registered_domain != domain:
            is_official, official_brand = self.check_official_domain(registered_domain)
        if not is_official and norm.hostname != domain:
            is_official, official_brand = self.check_official_domain(norm.hostname)

        # 1. Structured Lexical Feature Vector & Semantic Pattern Analysis
        lexical_vec = lexical_analyzer.extract_vector(
            full_url=full_url,
            domain=domain,
            subdomain=subdomain,
            path=norm.path,
            query=query,
            port=port,
            is_ip_host=norm.is_ip_address,
            original_url=norm.original_url
        )

        ip_based = lexical_vec.has_ip_host
        subdomain_count = lexical_vec.subdomain_count
        special_char_count = lexical_vec.special_character_count
        has_at_symbol = lexical_vec.has_at_symbol
        has_hex_encoding = lexical_vec.has_percent_encoding

        # Double slash detection in path
        orig_body = norm.original_url.split("://", 1)[-1] if "://" in norm.original_url else norm.original_url
        has_double_slash = "//" in orig_body

        # 2. TLD Analysis
        suspicious_tld = tld in SUSPICIOUS_TLDS or ("." in tld and tld.split(".")[-1] in SUSPICIOUS_TLDS)

        # 3. Shannon Entropy
        entropy = calculate_shannon_entropy(domain)

        # 4. Semantic Keywords (Evidence, not proof)
        found_keywords_set = set(lexical_vec.semantic_patterns.found_keywords)
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in full_url.lower() or (norm.original_url and kw in norm.original_url.lower()):
                found_keywords_set.add(kw)
        found_keywords = sorted(list(found_keywords_set))

        # 7. Advanced Brand Impersonation check on Registered Domain (stem/SLD)
        impersonated_brand = None
        similarity_score = 0.0
        similarity_rating = "NONE"
        tld_mismatch = False
        deceptive_tokens: List[str] = []
        manipulation_types: List[str] = []
        impersonation_signals: List[str] = []
        brand_details_model: Optional[BrandAnalysisDetails] = None

        if not is_official:
            brand_res = brand_matcher.analyze_domain(registered_domain, tld)
            if brand_res.brand_impersonated:
                impersonated_brand = brand_res.brand_impersonated
                similarity_score = brand_res.brand_similarity_score
                similarity_rating = brand_res.brand_similarity_rating
                tld_mismatch = brand_res.tld_mismatch
                deceptive_tokens = brand_res.deceptive_tokens
                manipulation_types = brand_res.manipulation_types
                impersonation_signals.extend(brand_res.signals)

            # Also check if subdomain impersonates a brand (e.g. amazon.phishing.xyz)
            if subdomain and not impersonated_brand:
                sub_res = brand_matcher.analyze_domain(subdomain, "")
                if sub_res.brand_impersonated:
                    impersonated_brand = sub_res.brand_impersonated
                    similarity_score = sub_res.brand_similarity_score
                    similarity_rating = sub_res.brand_similarity_rating
                    tld_mismatch = True
                    deceptive_tokens = sub_res.deceptive_tokens
                    manipulation_types = ["subdomain impersonation"] + sub_res.manipulation_types
                    impersonation_signals.append(f"Subdomain brand impersonation: Deceptive brand '{sub_res.brand_impersonated}' prepended as subdomain on untrusted domain '{registered_domain}'")
                    if sub_res.tld_mismatch:
                        impersonation_signals.append(f"TLD mismatch: Candidate domain uses '.{tld}'")

            # Fallback legacy checks if brand not yet found (e.g. brand in path)
            if not impersonated_brand:
                legacy_brand, legacy_sim, legacy_sigs = self._check_brand_impersonation(domain, full_url)
                if legacy_brand:
                    impersonated_brand = legacy_brand
                    similarity_score = legacy_sim
                    similarity_rating = "HIGH" if legacy_sim >= 0.85 else "MEDIUM"
                    impersonation_signals.extend(legacy_sigs)

            if impersonated_brand or brand_res.is_official_domain:
                brand_details_model = BrandAnalysisDetails(
                    is_official_domain=is_official or brand_res.is_official_domain,
                    official_brand_name=official_brand or brand_res.official_brand_name,
                    brand_impersonated=impersonated_brand,
                    brand_display_name=brand_res.brand_display_name or (official_brand if is_official else impersonated_brand),
                    brand_similarity_score=similarity_score,
                    brand_similarity_rating=similarity_rating,
                    matched_token=brand_res.matched_token,
                    target_brand=brand_res.target_brand,
                    candidate_stem=brand_res.candidate_stem,
                    candidate_tld=brand_res.candidate_tld,
                    official_tlds=brand_res.official_tlds,
                    tld_mismatch=tld_mismatch,
                    deceptive_tokens=deceptive_tokens,
                    manipulation_types=manipulation_types,
                    signals=impersonation_signals,
                    summary=brand_res.summary
                )

        # 8. Separate Shannon Entropy (Domain, Subdomain, Path, Query) & Compound Vector Evaluation
        entropy_res = entropy_analyzer.analyze(
            domain=domain,
            subdomain=subdomain,
            path=norm.path,
            query=query,
            is_untrusted_domain=(not is_official),
            is_suspicious_tld=suspicious_tld,
            brand_impersonated=impersonated_brand,
            is_official_domain=is_official
        )
        entropy = entropy_res.overall_entropy

        # 9. Threat Signal Aggregation
        signals: List[str] = []
        score = 0.0

        # If verified official, grant trust immunity from structural false positives
        if is_official:
            signals.append(f"Verified Official Portal: Belongs to {official_brand} authorized domain registry")
            base_risk_score = 0.0
        else:
            # Check IDN Homograph attack & Confusable characters
            if norm.homograph_analysis:
                signals.extend(norm.homograph_analysis.signals)
                if norm.homograph_risk in ["SUSPICIOUS", "CRITICAL"]:
                    score += norm.homograph_analysis.base_risk_penalty
                    if not impersonated_brand and norm.confusables_detected:
                        for b in TARGET_BRANDS:
                            if b in norm.unicode_domain.lower():
                                impersonated_brand = b.upper()
                                similarity_score = 0.98
                                break
                elif norm.homograph_risk == "LOW":
                    score += norm.homograph_analysis.base_risk_penalty
            elif norm.has_homograph_attack:
                signals.append(f"IDN Homograph attack detected (Punycode spoofing: '{norm.punycode_domain}' disguising as '{norm.unicode_domain}')")
                score += 55.0

            # Subdomain brand spoofing check
            if subdomain and not is_official:
                sub_lower = subdomain.lower()
                for brand, aliases in BRAND_ALIASES.items():
                    if brand in sub_lower or any(alias in sub_lower for alias in aliases):
                        signals.append(f"Subdomain brand impersonation: Deceptive brand '{brand.upper()}' prepended on untrusted domain '{registered_domain}'")
                        score += 45.0
                        if not impersonated_brand:
                            impersonated_brand = brand.upper()
                            similarity_score = max(similarity_score, 0.95)
                        break

            # Check unauthorized .bank.in usage
            if domain.endswith(".bank.in"):
                signals.append("Unauthorized or unregistered entity claiming '.bank.in' namespace")
                score += 40.0

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

            if len(norm.original_url) > 75:
                signals.append(f"Excessive URL length ({len(norm.original_url)} characters) indicating token stuffing or cloaking")
                score += 15.0

            if subdomain_count >= 3:
                signals.append(f"Unusually deep subdomain nesting ({subdomain_count} subdomains)")
                score += 20.0

            # Compound Threat Vector: High Entropy + Untrusted Domain + Brand Impersonation
            if entropy_res.has_compound_risk:
                signals.extend(entropy_res.signals)
                score += 25.0
            elif entropy_res.signals:
                signals.extend(entropy_res.signals)
                if entropy_res.is_high_domain_entropy and suspicious_tld:
                    score += 18.0
                elif entropy_res.is_high_domain_entropy:
                    score += 10.0

            if port and port not in [80, 443]:
                signals.append(f"URL uses non-standard network port (:{port})")
                score += 20.0

            # Add brand impersonation and typosquatting signals
            if impersonated_brand:
                signals.extend(impersonation_signals)
                score += 50.0
                if tld_mismatch:
                    score += 15.0
                if deceptive_tokens:
                    score += min(20.0, len(deceptive_tokens) * 8.0)

            if len(found_keywords) >= 2:
                signals.append(f"Multiple social-engineering keywords in URL: {', '.join(found_keywords[:4])} (Evidence only — suspicious keywords are not standalone proof)")
                score += min(25.0, len(found_keywords) * 6.0)
            elif len(found_keywords) == 1:
                signals.append(f"Sensitive credential/banking keyword in URL: {found_keywords[0]} (Evidence only — evaluated in context with domain reputation)")
                score += 8.0

            if protocol == "http" and (impersonated_brand or len(found_keywords) > 0):
                signals.append("Insecure HTTP protocol used for sensitive banking or login interaction")
                score += 15.0

            base_risk_score = min(100.0, max(0.0, round(score, 1)))

        components_model = URLComponents(
            scheme=scheme,
            subdomain=subdomain,
            registered_domain=registered_domain,
            tld=tld,
            port=port,
            path=norm.path,
            query=query,
            fragment=fragment,
        )

        homograph_model = HomographAnalysis(
            has_punycode=norm.has_punycode,
            has_unicode=norm.has_unicode,
            is_mixed_script=norm.is_mixed_script,
            detected_scripts=norm.detected_scripts,
            confusables_detected=norm.confusables_detected,
            homograph_risk=norm.homograph_risk,
            summary_message=norm.homograph_summary,
        ) if norm.homograph_analysis else None

        return URLFeatureAnalysis(
            url=norm.normalized_url,
            original_url=norm.original_url,
            normalized_url=norm.normalized_url,
            domain=norm.canonical_domain,
            canonical_domain=norm.canonical_domain,
            hostname=norm.hostname,
            subdomain=subdomain,
            registered_domain=registered_domain,
            tld=tld,
            punycode_domain=norm.punycode_domain,
            unicode_domain=norm.unicode_domain,
            protocol=norm.scheme,
            scheme=scheme,
            port=norm.port,
            path=norm.path,
            query=query,
            fragment=fragment,
            components=components_model,
            homograph_risk=norm.homograph_risk,
            is_mixed_script=norm.is_mixed_script,
            confusables_detected=norm.confusables_detected,
            detected_scripts=norm.detected_scripts,
            homograph_summary=norm.homograph_summary,
            homograph_analysis=homograph_model,
            ip_based=norm.is_ip_address,
            url_length=len(norm.normalized_url),
            domain_length=len(norm.canonical_domain),
            subdomain_count=subdomain_count,
            special_char_count=special_char_count,
            path_length=lexical_vec.path_length,
            query_length=lexical_vec.query_length,
            dot_count=lexical_vec.dot_count,
            hyphen_count=lexical_vec.hyphen_count,
            underscore_count=lexical_vec.underscore_count,
            digit_count=lexical_vec.digit_count,
            digit_ratio=lexical_vec.digit_ratio,
            special_character_ratio=lexical_vec.special_character_ratio,
            subdomain_depth=lexical_vec.subdomain_depth,
            path_depth=lexical_vec.path_depth,
            query_parameter_count=lexical_vec.query_parameter_count,
            has_ip_host=lexical_vec.has_ip_host,
            has_port=lexical_vec.has_port,
            has_punycode=lexical_vec.has_punycode,
            has_percent_encoding=lexical_vec.has_percent_encoding,
            entropy=entropy_res.overall_entropy,
            domain_entropy=entropy_res.domain_entropy,
            subdomain_entropy=entropy_res.subdomain_entropy,
            path_entropy=entropy_res.path_entropy,
            query_entropy=entropy_res.query_entropy,
            entropy_analysis=entropy_res,
            suspicious_tld=suspicious_tld,
            detected_tld=tld,
            suspicious_keywords=found_keywords,
            semantic_patterns=lexical_vec.semantic_patterns,
            lexical_vector=lexical_vec,
            brand_impersonated=impersonated_brand,
            brand_similarity_score=similarity_score,
            brand_similarity_rating=similarity_rating,
            tld_mismatch=tld_mismatch,
            deceptive_tokens=deceptive_tokens,
            manipulation_types=manipulation_types,
            brand_analysis=brand_details_model,
            is_official_domain=is_official,
            official_brand_name=official_brand,
            has_at_symbol=has_at_symbol,
            has_double_slash=has_double_slash,
            has_hex_encoding=has_hex_encoding,
            has_homograph_attack=norm.has_homograph_attack,
            stripped_tracking_params=norm.stripped_tracking_params,
            threat_signals=signals,
            base_risk_score=base_risk_score
        )

    def check_threat_feeds(self, domain: str) -> Optional[Dict[str, str]]:
        domain_clean = domain.lower()
        if domain_clean in KNOWN_MALICIOUS_DOMAINS:
            return KNOWN_MALICIOUS_DOMAINS[domain_clean]
        return None

url_analyzer = URLAnalyzer()
