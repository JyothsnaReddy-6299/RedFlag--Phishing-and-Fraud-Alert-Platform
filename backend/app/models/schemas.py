from enum import Enum
from typing import List, Optional, Dict
from pydantic import BaseModel, Field, ConfigDict

class RiskLevel(str, Enum):
    SAFE_LOW = "SAFE_LOW"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"

class URLCategory(str, Enum):
    LEGITIMATE = "LEGITIMATE"
    SUSPICIOUS_STRUCTURE = "SUSPICIOUS_STRUCTURE"
    BRAND_IMPERSONATION = "BRAND_IMPERSONATION"
    KNOWN_PHISHING = "KNOWN_PHISHING"
    IP_BASED_ATTACK = "IP_BASED_ATTACK"
    HIGH_ABUSE_TLD = "HIGH_ABUSE_TLD"

class URLComponents(BaseModel):
    scheme: str
    subdomain: str
    registered_domain: str
    tld: str
    port: Optional[int] = None
    path: str
    query: str
    fragment: str

    model_config = ConfigDict(from_attributes=True)

class HomographAnalysis(BaseModel):
    has_punycode: bool
    has_unicode: bool
    is_mixed_script: bool
    detected_scripts: List[str] = Field(default_factory=list)
    confusables_detected: List[Dict[str, str]] = Field(default_factory=list)
    homograph_risk: str
    summary_message: str

    model_config = ConfigDict(from_attributes=True)

class BrandAnalysisDetails(BaseModel):
    is_official_domain: bool = False
    official_brand_name: Optional[str] = None
    brand_impersonated: Optional[str] = None
    brand_display_name: Optional[str] = None
    brand_similarity_score: float = 0.0
    brand_similarity_rating: str = "NONE"
    matched_token: Optional[str] = None
    target_brand: Optional[str] = None
    candidate_stem: str = ""
    candidate_tld: str = ""
    official_tlds: List[str] = Field(default_factory=list)
    tld_mismatch: bool = False
    deceptive_tokens: List[str] = Field(default_factory=list)
    manipulation_types: List[str] = Field(default_factory=list)
    signals: List[str] = Field(default_factory=list)
    summary: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

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
    evidence_summary: str = "A suspicious keyword is evidence, not proof"

    model_config = ConfigDict(from_attributes=True)

class URLFeatureAnalysis(BaseModel):
    url: str
    original_url: Optional[str] = None
    normalized_url: Optional[str] = None
    domain: str
    canonical_domain: Optional[str] = None
    hostname: Optional[str] = None
    subdomain: Optional[str] = None
    registered_domain: Optional[str] = None
    tld: Optional[str] = None
    punycode_domain: Optional[str] = None
    unicode_domain: Optional[str] = None
    protocol: str
    scheme: Optional[str] = None
    port: Optional[int] = None
    path: Optional[str] = None
    query: Optional[str] = None
    fragment: Optional[str] = None
    components: Optional[URLComponents] = None
    homograph_risk: Optional[str] = None
    is_mixed_script: bool = False
    confusables_detected: List[Dict[str, str]] = Field(default_factory=list)
    detected_scripts: List[str] = Field(default_factory=list)
    homograph_summary: Optional[str] = None
    homograph_analysis: Optional[HomographAnalysis] = None
    ip_based: bool
    url_length: int
    domain_length: int
    subdomain_count: int
    special_char_count: int
    path_length: int = 0
    query_length: int = 0
    dot_count: int = 0
    hyphen_count: int = 0
    underscore_count: int = 0
    digit_count: int = 0
    digit_ratio: float = 0.0
    special_character_ratio: float = 0.0
    subdomain_depth: int = 0
    path_depth: int = 0
    query_parameter_count: int = 0
    has_ip_host: bool = False
    has_port: bool = False
    has_punycode: bool = False
    has_percent_encoding: bool = False
    entropy: float
    suspicious_tld: bool
    detected_tld: str
    suspicious_keywords: List[str] = Field(default_factory=list)
    semantic_patterns: Optional[SemanticPatterns] = None
    lexical_vector: Optional[LexicalFeatureVector] = None
    brand_impersonated: Optional[str] = None
    brand_similarity_score: float = 0.0
    brand_similarity_rating: str = "NONE"
    tld_mismatch: bool = False
    deceptive_tokens: List[str] = Field(default_factory=list)
    manipulation_types: List[str] = Field(default_factory=list)
    brand_analysis: Optional[BrandAnalysisDetails] = None
    is_official_domain: bool = False
    official_brand_name: Optional[str] = None
    has_at_symbol: bool = False
    has_double_slash: bool = False
    has_hex_encoding: bool = False
    has_homograph_attack: bool = False
    stripped_tracking_params: List[str] = Field(default_factory=list)
    threat_signals: List[str] = Field(default_factory=list)
    base_risk_score: float = 0.0

    model_config = ConfigDict(from_attributes=True)

class URLScanRequest(BaseModel):
    url: str = Field(..., json_schema_extra={"example": "http://sbi-kyc-update-portal.xyz/login"})

class URLScanResponse(BaseModel):
    url: str
    original_url: Optional[str] = None
    normalized_url: Optional[str] = None
    domain: str
    canonical_domain: Optional[str] = None
    subdomain: Optional[str] = None
    registered_domain: Optional[str] = None
    tld: Optional[str] = None
    scheme: Optional[str] = None
    port: Optional[int] = None
    path: Optional[str] = None
    query: Optional[str] = None
    fragment: Optional[str] = None
    components: Optional[URLComponents] = None
    punycode_domain: Optional[str] = None
    homograph_risk: Optional[str] = None
    is_mixed_script: bool = False
    confusables_detected: List[Dict[str, str]] = Field(default_factory=list)
    detected_scripts: List[str] = Field(default_factory=list)
    homograph_summary: Optional[str] = None
    homograph_analysis: Optional[HomographAnalysis] = None
    lexical_vector: Optional[LexicalFeatureVector] = None
    brand_impersonated: Optional[str] = None
    brand_similarity_score: float = 0.0
    brand_similarity_rating: str = "NONE"
    tld_mismatch: bool = False
    deceptive_tokens: List[str] = Field(default_factory=list)
    manipulation_types: List[str] = Field(default_factory=list)
    brand_analysis: Optional[BrandAnalysisDetails] = None
    stripped_tracking_params: List[str] = Field(default_factory=list)
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    category: URLCategory
    confidence: float
    url_features: URLFeatureAnalysis
    threat_intel_match: bool
    threat_sources: List[str] = Field(default_factory=list)
    contributing_factors: List[str] = Field(default_factory=list)
    mitigation_advice: List[str] = Field(default_factory=list)
    explanation: str

    model_config = ConfigDict(from_attributes=True)

class SMSScanRequest(BaseModel):
    text: str = Field(..., json_schema_extra={"example": "Dear SBI user, your KYC is expired. Click http://sbi-kyc.xyz/login to avoid account block."})
    sender_id: Optional[str] = Field(None, json_schema_extra={"example": "+919876543210"})

class SMSScanResponse(BaseModel):
    text: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    scam_category: str
    confidence: float
    detected_entities: Dict[str, List[str]] = Field(default_factory=dict)
    urgency_indicators: List[str] = Field(default_factory=list)
    extracted_urls: List[URLScanResponse] = Field(default_factory=list)
    threat_signals: List[str] = Field(default_factory=list)
    mitigation_advice: List[str] = Field(default_factory=list)
    explanation: str

    model_config = ConfigDict(from_attributes=True)
