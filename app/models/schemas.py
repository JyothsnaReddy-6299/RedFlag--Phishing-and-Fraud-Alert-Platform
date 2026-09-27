from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class RiskLevel(str, Enum):
    SAFE_LOW = "SAFE_LOW"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"

class ScamCategory(str, Enum):
    BANKING_FRAUD = "BANKING_FRAUD"
    KYC_EXPIRY = "KYC_EXPIRY"
    UPI_FRAUD = "UPI_FRAUD"
    ELECTRICITY_BILL = "ELECTRICITY_BILL"
    LOTTERY_PRIZE = "LOTTERY_PRIZE"
    JOB_SCAM = "JOB_SCAM"
    OTP_THEFT = "OTP_THEFT"
    IMPERSONATION = "IMPERSONATION"
    MALICIOUS_URL = "MALICIOUS_URL"
    LEGITIMATE = "LEGITIMATE"
    UNKNOWN = "UNKNOWN"

class DetectedLanguage(str, Enum):
    ENGLISH = "ENGLISH"
    TAMIL = "TAMIL"
    TANGLISH = "TANGLISH"
    MIXED = "MIXED"

class ExtractedEntities(BaseModel):
    phone_numbers: List[str] = Field(default_factory=list)
    upi_ids: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    organizations: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)

class URLFeatureAnalysis(BaseModel):
    url: str
    domain: str
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
    threat_signals: List[str] = Field(default_factory=list)
    base_risk_score: float = 0.0

class SocialEngineeringSignals(BaseModel):
    urgency_detected: bool = False
    fear_or_threat_detected: bool = False
    financial_incentive_detected: bool = False
    credential_or_otp_demand: bool = False
    impersonation_detected: bool = False
    action_requested: bool = False
    detected_patterns: List[str] = Field(default_factory=list)

class MessageAnalysisResult(BaseModel):
    original_text: str
    detected_language: DetectedLanguage
    scam_category: ScamCategory
    confidence: float
    social_engineering: SocialEngineeringSignals
    extracted_entities: ExtractedEntities
    threat_signals: List[str] = Field(default_factory=list)
    base_risk_score: float = 0.0

class RiskAssessment(BaseModel):
    risk_score: int = Field(..., ge=0, le=100, description="Score from 0 to 100")
    risk_level: RiskLevel
    primary_category: ScamCategory
    confidence: float
    contributing_factors: List[str] = Field(default_factory=list)
    mitigation_advice: List[str] = Field(default_factory=list)
    explanation: str

# Requests
class URLScanRequest(BaseModel):
    url: str = Field(..., json_schema_extra={"example": "http://sbi-kyc-update-portal.xyz/login"})

class MessageScanRequest(BaseModel):
    message: str = Field(..., json_schema_extra={"example": "Dear customer, your TNEB power will be disconnected tonight. Pay immediately via 9840123456@paytm"})

class UnifiedScanRequest(BaseModel):
    text: Optional[str] = Field(None, json_schema_extra={"example": "Your account is suspended. Click http://verify-bank.com to restore."})
    url: Optional[str] = Field(None, json_schema_extra={"example": "http://verify-bank.com"})

# Responses
class URLScanResponse(BaseModel):
    url_analysis: URLFeatureAnalysis
    extracted_entities: ExtractedEntities
    risk_assessment: RiskAssessment

class MessageScanResponse(BaseModel):
    message_analysis: MessageAnalysisResult
    risk_assessment: RiskAssessment

class UnifiedScanResponse(BaseModel):
    input_type: str
    url_analysis: Optional[URLFeatureAnalysis] = None
    message_analysis: Optional[MessageAnalysisResult] = None
    extracted_entities: ExtractedEntities
    risk_assessment: RiskAssessment
