export type RiskLevel = 'SAFE_LOW' | 'SUSPICIOUS' | 'HIGH_RISK' | 'CRITICAL';

export type URLCategory =
  | 'LEGITIMATE'
  | 'SUSPICIOUS_STRUCTURE'
  | 'BRAND_IMPERSONATION'
  | 'KNOWN_PHISHING'
  | 'IP_BASED_ATTACK'
  | 'HIGH_ABUSE_TLD';

export interface URLFeatureAnalysis {
  url: string;
  original_url?: string;
  normalized_url?: string;
  domain: string;
  canonical_domain?: string;
  hostname?: string;
  punycode_domain?: string;
  unicode_domain?: string;
  protocol: string;
  port: number | null;
  ip_based: boolean;
  url_length: number;
  domain_length: number;
  subdomain_count: number;
  special_char_count: number;
  entropy: number;
  suspicious_tld: boolean;
  detected_tld: string;
  suspicious_keywords: string[];
  brand_impersonated?: string | null;
  brand_similarity_score: number;
  is_official_domain: boolean;
  official_brand_name?: string | null;
  has_at_symbol: boolean;
  has_double_slash: boolean;
  has_hex_encoding: boolean;
  has_homograph_attack?: boolean;
  stripped_tracking_params?: string[];
  threat_signals: string[];
  base_risk_score: number;
}

export interface URLScanResponse {
  url: string;
  original_url?: string;
  normalized_url?: string;
  domain: string;
  canonical_domain?: string;
  punycode_domain?: string;
  stripped_tracking_params?: string[];
  risk_score: number;
  risk_level: RiskLevel;
  category: URLCategory;
  confidence: number;
  url_features: URLFeatureAnalysis;
  threat_intel_match: boolean;
  threat_sources: string[];
  contributing_factors: string[];
  mitigation_advice: string[];
  explanation: string;
}

export interface SMSScanResponse {
  text: string;
  risk_score: number;
  risk_level: RiskLevel;
  scam_category: string;
  confidence: number;
  detected_entities: {
    urls?: string[];
    phone_numbers?: string[];
    urgency_keywords?: string[];
  };
  urgency_indicators: string[];
  extracted_urls: URLScanResponse[];
  threat_signals: string[];
  mitigation_advice: string[];
  explanation: string;
}

export interface ThreatDomainItem {
  domain: string;
  category: string;
  source: string;
}

export interface KnownThreatsResponse {
  count: number;
  threats: ThreatDomainItem[];
}
