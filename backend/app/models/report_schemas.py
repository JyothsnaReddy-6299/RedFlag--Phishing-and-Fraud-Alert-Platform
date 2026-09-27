from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict

class ReportCreateRequest(BaseModel):
    scam_category: Optional[str] = Field(None, json_schema_extra={"example": "ELECTRICITY_BILL"})
    description: Optional[str] = Field(None, json_schema_extra={"example": "Received SMS claiming power will be cut tonight."})
    raw_message: Optional[str] = Field(None, json_schema_extra={"example": "TNEB bill unpaid, power cut tonight. Send to 9840123456@paytm"})
    raw_url: Optional[str] = Field(None, json_schema_extra={"example": "http://tneb-bill-pay.xyz"})
    phone_number: Optional[str] = Field(None, json_schema_extra={"example": "9840123456"})
    upi_id: Optional[str] = Field(None, json_schema_extra={"example": "9840123456@paytm"})
    organization: Optional[str] = Field(None, json_schema_extra={"example": "TNEB"})
    location_city: Optional[str] = Field(None, json_schema_extra={"example": "Chennai"})
    location_area: Optional[str] = Field(None, json_schema_extra={"example": "Adyar"})

class ReportVerifyRequest(BaseModel):
    status: str = Field(..., json_schema_extra={"example": "VERIFIED"}, description="'VERIFIED', 'REJECTED', or 'UNDER_REVIEW'")
    analyst_id: str = Field(..., json_schema_extra={"example": "ANALYST_01"})
    notes: Optional[str] = Field(None, json_schema_extra={"example": "Confirmed impersonation scam targeting local residents."})

class ReportPublicResponse(BaseModel):
    report_id: str
    scam_category: str
    description: Optional[str] = None
    masked_phone: Optional[str] = None
    masked_upi: Optional[str] = None
    defanged_url: Optional[str] = None
    organization: Optional[str] = None
    location_city: Optional[str] = None
    location_area: Optional[str] = None
    status: str
    initial_risk_score: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ReportDetailResponse(BaseModel):
    id: int
    report_id: str
    scam_category: str
    description: Optional[str] = None
    raw_message: Optional[str] = None
    raw_url: Optional[str] = None
    phone_number: Optional[str] = None
    upi_id: Optional[str] = None
    organization: Optional[str] = None
    location_city: Optional[str] = None
    location_area: Optional[str] = None
    status: str
    initial_risk_score: int
    verified_by: Optional[str] = None
    verification_notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class IndicatorSummary(BaseModel):
    indicator_type: str
    indicator_value: str
    category: Optional[str] = None
    status: str
    report_count: int
    last_seen: datetime

    model_config = ConfigDict(from_attributes=True)
