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

class URLFeatureAnalysis(BaseModel):
    url: str
    original_url: Optional[str] = None
    normalized_url: Optional[str] = None
    domain: str
    canonical_domain: Optional[str] = None
    hostname: Optional[str] = None
    punycode_domain: Optional[str] = None
    unicode_domain: Optional[str] = None
    protocol: str
    port: Optional[int] = None
    ip_based: bool
    url_length: int
    domain_length: int
    subdomain_count: int
    special_char_count: int
    entropy: float
    suspicious_tld: bool
    detected_tld: str
    suspicious_keywords: List[str] = Field(default_factory=list)
    brand_impersonated: Optional[str] = None
    brand_similarity_score: float = 0.0
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
    punycode_domain: Optional[str] = None
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
