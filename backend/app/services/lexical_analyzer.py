"""
Lexical Feature Vector Engine
-----------------------------
Extracts a comprehensive, structured lexical and syntactic feature vector
from normalized URL components, along with semantic social-engineering keyword patterns.

Architectural Guiding Principle:
  "A suspicious keyword is evidence, not proof."
  Keywords are correlated indicators that require contextual validation
  against domain authentication, brand similarity, and structural anomalies.
"""

import re
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import parse_qsl
from pydantic import BaseModel, Field, ConfigDict


# Target Semantic Patterns specified for phishing / social-engineering detection
SEMANTIC_TARGET_KEYWORDS: List[str] = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "kyc",
    "wallet",
    "payment",
    "refund",
    "bonus",
    "claim",
    "support"
]

SPECIAL_CHARACTER_SET: Set[str] = set("@-_~%&=?+#$!*;:,.")


class SemanticPatterns(BaseModel):
    login: bool = False
    verify: bool = False
    secure: bool = False
    account: bool = False
    update: bool = False
    kyc: bool = False
    wallet: bool = False
    payment: bool = False
    refund: bool = False
    bonus: bool = False
    claim: bool = False
    support: bool = False
    found_keywords: List[str] = Field(default_factory=list)
    keyword_count: int = 0
    keyword_evidence_weight: float = 0.0
    evidence_note: str = "A suspicious keyword is evidence, not proof"

    model_config = ConfigDict(from_attributes=True)


from backend.app.services.entropy_analyzer import calculate_shannon_entropy


class LexicalFeatureVector(BaseModel):
    url_length: int
    domain_length: int
    subdomain_count: int
    path_length: int
    query_length: int
    dot_count: int
    hyphen_count: int
    underscore_count: int
    digit_count: int
    special_character_count: int
    digit_ratio: float
    special_character_ratio: float
    subdomain_depth: int
    path_depth: int
    query_parameter_count: int
    has_ip_host: bool
    has_port: bool
    has_at_symbol: bool
    has_punycode: bool
    has_percent_encoding: bool
    semantic_patterns: SemanticPatterns
    domain_entropy: float = 0.0
    path_entropy: float = 0.0
    query_entropy: float = 0.0
    evidence_summary: str = "A suspicious keyword is evidence, not proof"

    model_config = ConfigDict(from_attributes=True)


SEMANTIC_PATTERNS_MAP: Dict[str, List[str]] = {
    "login": ["login", "signin", "log-in", "sign-in"],
    "verify": ["verify", "verification", "verified"],
    "secure": ["secure", "security", "secured"],
    "account": ["account", "accounts"],
    "update": ["update", "updates", "updated"],
    "kyc": ["kyc"],
    "wallet": ["wallet", "wallets"],
    "payment": ["payment", "payments", "pay"],
    "refund": ["refund", "refunds"],
    "bonus": ["bonus", "bonuses"],
    "claim": ["claim", "claims", "claimed"],
    "support": ["support", "supports", "helpdesk"],
}


class LexicalAnalyzer:
    def __init__(self):
        self.keywords = SEMANTIC_TARGET_KEYWORDS
        self.patterns_map = SEMANTIC_PATTERNS_MAP
        self.percent_pattern = re.compile(r'%[0-9a-fA-F]{2}')
        self.ip_pattern = re.compile(
            r'^(?:http[s]?://)?(?:www\.)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/.*)?$'
        )

    def extract_semantic_patterns(self, url: str) -> SemanticPatterns:
        """
        Detects target semantic keywords in URL path, query, and hostname.
        Treats occurrences as contextual evidence, not definitive proof.
        """
        url_lower = url.lower()
        found: List[str] = []
        flags: Dict[str, bool] = {}

        # Tokenize by common URL separators for accurate matching
        tokens = set(re.split(r'[/_.\-?&=%+#:]+', url_lower))

        for category, variants in self.patterns_map.items():
            is_present = any(
                (v in tokens) or (v in url_lower)
                for v in variants
            )
            flags[category] = is_present
            if is_present:
                # Find matching variant
                matched_var = next((v for v in variants if (v in tokens) or (v in url_lower)), category)
                found.append(matched_var)

        # Evidence weight (scaled 0.0 - 1.0)
        # Note: A single keyword is mild evidence (~0.15), multiple keywords scale up to ~0.75 max
        evidence_weight = round(min(0.75, len(found) * 0.15), 2)

        return SemanticPatterns(
            login=flags.get("login", False),
            verify=flags.get("verify", False),
            secure=flags.get("secure", False),
            account=flags.get("account", False),
            update=flags.get("update", False),
            kyc=flags.get("kyc", False),
            wallet=flags.get("wallet", False),
            payment=flags.get("payment", False),
            refund=flags.get("refund", False),
            bonus=flags.get("bonus", False),
            claim=flags.get("claim", False),
            support=flags.get("support", False),
            found_keywords=found,
            keyword_count=len(found),
            keyword_evidence_weight=evidence_weight,
            evidence_note="A suspicious keyword is evidence, not proof"
        )

    def extract_vector(
        self,
        full_url: str,
        domain: str,
        subdomain: Optional[str] = None,
        path: Optional[str] = None,
        query: Optional[str] = None,
        port: Optional[int] = None,
        is_ip_host: bool = False,
        original_url: Optional[str] = None
    ) -> LexicalFeatureVector:
        """
        Extracts the full 20+ lexical and syntactic feature vector plus semantic patterns.
        """
        url_target = full_url.strip()
        url_len = len(url_target)
        dom_clean = (domain or "").strip().lower()
        dom_len = len(dom_clean)

        # Subdomains
        sub_str = (subdomain or "").strip()
        if sub_str:
            sub_labels = [p for p in sub_str.split(".") if p]
            subdomain_count = len(sub_labels)
            subdomain_depth = len(sub_labels)
        else:
            subdomain_count = 0
            subdomain_depth = 0

        # Path
        path_str = path or ""
        path_len = len(path_str)
        path_segments = [s for s in path_str.strip("/").split("/") if s]
        path_depth = len(path_segments)

        # Query
        query_str = query or ""
        query_len = len(query_str)
        try:
            query_params = parse_qsl(query_str, keep_blank_values=True)
            query_parameter_count = len(query_params)
        except Exception:
            query_parameter_count = len([p for p in query_str.split("&") if p])

        # Syntactic character counts
        dot_count = url_target.count(".")
        hyphen_count = url_target.count("-")
        underscore_count = url_target.count("_")
        digit_count = sum(1 for c in url_target if c.isdigit())

        # Special characters count (non-alphanumeric, excluding standard URL protocol and path separators '/' and ':')
        special_character_count = sum(1 for c in url_target if not c.isalnum() and c not in ['/', ':'])

        # Ratios (normalized to URL length)
        denom = max(url_len, 1)
        digit_ratio = round(digit_count / denom, 4)
        special_character_ratio = round(special_character_count / denom, 4)

        # Host and Protocol Flags
        has_ip = bool(is_ip_host or bool(self.ip_pattern.match(url_target)) or bool(self.ip_pattern.match(dom_clean)))
        has_port_flag = bool(port is not None and port not in (80, 443))
        has_at_symbol = bool("@" in url_target or (original_url is not None and "@" in original_url))
        has_punycode = bool("xn--" in dom_clean or "xn--" in url_target.lower())
        has_percent = bool(self.percent_pattern.search(url_target) or (original_url is not None and self.percent_pattern.search(original_url)))

        # Semantic patterns
        semantic_patterns = self.extract_semantic_patterns(url_target)

        # Discrete Shannon entropy calculations
        dom_entropy = calculate_shannon_entropy(dom_clean)
        path_clean_str = path_str.strip("/")
        path_entropy = calculate_shannon_entropy(path_clean_str) if len(path_clean_str) > 3 else 0.0
        query_clean_str = query_str.lstrip("?")
        query_entropy = calculate_shannon_entropy(query_clean_str) if len(query_clean_str) > 3 else 0.0

        return LexicalFeatureVector(
            url_length=url_len,
            domain_length=dom_len,
            subdomain_count=subdomain_count,
            path_length=path_len,
            query_length=query_len,
            dot_count=dot_count,
            hyphen_count=hyphen_count,
            underscore_count=underscore_count,
            digit_count=digit_count,
            special_character_count=special_character_count,
            digit_ratio=digit_ratio,
            special_character_ratio=special_character_ratio,
            subdomain_depth=subdomain_depth,
            path_depth=path_depth,
            query_parameter_count=query_parameter_count,
            has_ip_host=has_ip,
            has_port=has_port_flag,
            has_at_symbol=has_at_symbol,
            has_punycode=has_punycode,
            has_percent_encoding=has_percent,
            semantic_patterns=semantic_patterns,
            domain_entropy=dom_entropy,
            path_entropy=path_entropy,
            query_entropy=query_entropy,
            evidence_summary="A suspicious keyword is evidence, not proof"
        )


lexical_analyzer = LexicalAnalyzer()
