from enum import Enum
from typing import List, Optional
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
    domain: str
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
    has_at_symbol: bool = False
    has_double_slash: bool = False
    has_hex_encoding: bool = False
    threat_signals: List[str] = Field(default_factory=list)
    base_risk_score: float = 0.0

    model_config = ConfigDict(from_attributes=True)

class URLScanRequest(BaseModel):
    url: str = Field(..., json_schema_extra={"example": "http://sbi-kyc-update-portal.xyz/login"})

class URLScanResponse(BaseModel):
    url: str
    domain: str
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
