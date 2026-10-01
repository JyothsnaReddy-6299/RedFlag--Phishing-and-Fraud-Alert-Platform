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

export interface EntropyAnalysis {
  domain_entropy: number;
  subdomain_entropy: number;
  path_entropy: number;
  query_entropy: number;
  overall_entropy: number;
  is_high_domain_entropy: boolean;
  is_high_subdomain_entropy: boolean;
  is_high_path_entropy: boolean;
  is_high_query_entropy: boolean;
  has_compound_risk: boolean;
  compound_explanation?: string | null;
  signals: string[];
  evaluation_note?: string;
}

export interface NetworkAnalysis {
  is_ip_host: boolean;
  ip_version?: 'IPv4' | 'IPv6' | 'Dual-Stack' | null;
  is_private_ip: boolean;
  dns_resolved: boolean;
  dns_failure: boolean;
  dns_error_message?: string | null;
  resolved_ips: string[];
  resolved_ipv4: string[];
  resolved_ipv6: string[];
  has_multiple_ips: boolean;
  port?: number | null;
  is_unusual_port: boolean;
  asn?: string | null;
  asn_org?: string | null;
  asn_country?: string | null;
  signal_flags: string[];
  signals: string[];
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
  domain_entropy?: number;
  path_entropy?: number;
  query_entropy?: number;
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
  domain_entropy?: number;
  subdomain_entropy?: number;
  path_entropy?: number;
  query_entropy?: number;
  entropy_analysis?: EntropyAnalysis | null;
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
  network_analysis?: NetworkAnalysis | null;
  is_ip_host?: boolean;
  dns_resolved?: boolean;
  dns_failure?: boolean;
  ip_version?: 'IPv4' | 'IPv6' | 'Dual-Stack' | null;
  resolved_ips?: string[];
  has_multiple_ips?: boolean;
  is_unusual_port?: boolean;
  asn?: string | null;
  asn_org?: string | null;
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
  domain_entropy?: number;
  subdomain_entropy?: number;
  path_entropy?: number;
  query_entropy?: number;
  entropy_analysis?: EntropyAnalysis | null;
  network_analysis?: NetworkAnalysis | null;
  is_ip_host?: boolean;
  dns_resolved?: boolean;
  dns_failure?: boolean;
  ip_version?: 'IPv4' | 'IPv6' | 'Dual-Stack' | null;
  resolved_ips?: string[];
  has_multiple_ips?: boolean;
  is_unusual_port?: boolean;
  asn?: string | null;
  asn_org?: string | null;
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
