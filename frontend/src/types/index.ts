export type RiskLevel = 'SAFE_LOW' | 'SUSPICIOUS' | 'HIGH_RISK' | 'CRITICAL';

export type URLCategory =
  | 'LEGITIMATE'
  | 'SUSPICIOUS_STRUCTURE'
  | 'BRAND_IMPERSONATION'
  | 'KNOWN_PHISHING'
  | 'IP_BASED_ATTACK'
  | 'HIGH_ABUSE_TLD';

export interface URLComponents {
  scheme: string;
  subdomain: string;
  registered_domain: string;
  tld: string;
  TLD?: string;
  port: number | null;
  path: string;
  query: string;
  fragment: string;
}

export interface ConfusableDetail {
  char: string;
  codepoint: string;
  script: string;
  target_char: string;
  name: string;
}

export interface HomographAnalysis {
  has_punycode: boolean;
  has_unicode: boolean;
  is_mixed_script: boolean;
  detected_scripts: string[];
  confusables_detected: ConfusableDetail[];
  homograph_risk: 'NONE' | 'LOW' | 'SUSPICIOUS' | 'CRITICAL';
  summary_message: string;
}

export interface BrandAnalysisDetails {
  is_official_domain: boolean;
  official_brand_name?: string | null;
  brand_impersonated?: string | null;
  brand_display_name?: string | null;
  brand_similarity_score: number;
  brand_similarity_rating: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  matched_token?: string | null;
  target_brand?: string | null;
  candidate_stem: string;
  candidate_tld: string;
  official_tlds: string[];
  tld_mismatch: boolean;
  deceptive_tokens: string[];
  manipulation_types: string[];
  signals: string[];
  summary?: string | null;
}

export interface SemanticPatterns {
  login: boolean;
  verify: boolean;
  secure: boolean;
  account: boolean;
  update: boolean;
  kyc: boolean;
  wallet: boolean;
  payment: boolean;
  refund: boolean;
  bonus: boolean;
  claim: boolean;
  support: boolean;
  found_keywords: string[];
  keyword_count: number;
  keyword_evidence_weight: number;
  evidence_note: string;
}

export interface LexicalFeatureVector {
  url_length: number;
  domain_length: number;
  subdomain_count: number;
  path_length: number;
  query_length: number;
  dot_count: number;
  hyphen_count: number;
  underscore_count: number;
  digit_count: number;
  special_character_count: number;
  digit_ratio: number;
  special_character_ratio: number;
  subdomain_depth: number;
  path_depth: number;
  query_parameter_count: number;
  has_ip_host: boolean;
  has_port: boolean;
  has_at_symbol: boolean;
  has_punycode: boolean;
  has_percent_encoding: boolean;
  semantic_patterns: SemanticPatterns;
  evidence_summary: string;
}

export interface URLFeatureAnalysis {
  url: string;
  original_url?: string;
  normalized_url?: string;
  domain: string;
  canonical_domain?: string;
  hostname?: string;
  subdomain?: string;
  registered_domain?: string;
  tld?: string;
  scheme?: string;
  path?: string;
  query?: string;
  fragment?: string;
  components?: URLComponents;
  punycode_domain?: string;
  unicode_domain?: string;
  homograph_risk?: 'NONE' | 'LOW' | 'SUSPICIOUS' | 'CRITICAL';
  is_mixed_script?: boolean;
  confusables_detected?: ConfusableDetail[];
  detected_scripts?: string[];
  homograph_summary?: string;
  homograph_analysis?: HomographAnalysis;
  protocol: string;
  port: number | null;
  ip_based: boolean;
  url_length: number;
  domain_length: number;
  subdomain_count: number;
  special_char_count: number;
  path_length?: number;
  query_length?: number;
  dot_count?: number;
  hyphen_count?: number;
  underscore_count?: number;
  digit_count?: number;
  digit_ratio?: number;
  special_character_ratio?: number;
  subdomain_depth?: number;
  path_depth?: number;
  query_parameter_count?: number;
  has_ip_host?: boolean;
  has_port?: boolean;
  has_punycode?: boolean;
  has_percent_encoding?: boolean;
  entropy: number;
  suspicious_tld: boolean;
  detected_tld: string;
  suspicious_keywords: string[];
  semantic_patterns?: SemanticPatterns | null;
  lexical_vector?: LexicalFeatureVector | null;
  brand_impersonated?: string | null;
  brand_display_name?: string | null;
  brand_similarity_score: number;
  brand_similarity_rating?: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  tld_mismatch?: boolean;
  deceptive_tokens?: string[];
  manipulation_types?: string[];
  brand_analysis?: BrandAnalysisDetails | null;
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
  subdomain?: string;
  registered_domain?: string;
  tld?: string;
  scheme?: string;
  port?: number | null;
  path?: string;
  query?: string;
  fragment?: string;
  components?: URLComponents;
  punycode_domain?: string;
  homograph_risk?: 'NONE' | 'LOW' | 'SUSPICIOUS' | 'CRITICAL';
  is_mixed_script?: boolean;
  confusables_detected?: ConfusableDetail[];
  detected_scripts?: string[];
  homograph_summary?: string;
  homograph_analysis?: HomographAnalysis;
  lexical_vector?: LexicalFeatureVector | null;
  brand_impersonated?: string | null;
  brand_display_name?: string | null;
  brand_similarity_score?: number;
  brand_similarity_rating?: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  tld_mismatch?: boolean;
  deceptive_tokens?: string[];
  manipulation_types?: string[];
  brand_analysis?: BrandAnalysisDetails | null;
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
