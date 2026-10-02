// Canonical AnalysisResult contract (spec p.15) mirrored in TypeScript.

export type Verdict = 'LOW' | 'CAUTION' | 'HIGH' | 'CRITICAL';

export interface RiskFactor {
  name: string;
  family: string;
  weight: number;
  observed_value: string;
  evidence_span: string;
  source: string;
}

export interface RedFlag {
  title: string;
  detail: string;
  evidence_span: string;
  family: string;
  kind: string;
  weight: number | null;
}

export interface EntityItem {
  type: string;
  raw_value: string;
  display_value: string;
  canonical_value: string;
  canonical_hash: string;
  start: number;
  end: number;
  confidence: number;
  evidence_span: string;
  attributes?: Record<string, unknown>;
}

export interface CampaignLinkReason {
  relation: string;
  indicator_type: string;
  indicator: string;
  evidence_span?: string;
  similarity?: number;
}

export interface CampaignLink {
  campaign_id: string;
  label: string;
  status: string;
  strength: number;
  report_count: number;
  primary_category: string | null;
  reasons: CampaignLinkReason[];
  first_seen: string | null;
  last_seen: string | null;
}

export interface RecommendedAction {
  priority: 'critical' | 'high' | 'medium' | 'low';
  action: string;
  why: string;
}

export interface DegradedCheck {
  check: string;
  status: string;
  reason?: string;
  target?: string;
}

export interface LanguageDetail {
  language: string;
  label: string;
  scripts: string[];
  is_code_switched: boolean;
  tamil_char_ratio: number;
  latin_char_ratio: number;
  tanglish_tokens: { token: string; maps_to: string }[];
  confidence: number;
}

export interface OcrPayload {
  available: boolean;
  text: string;
  mean_confidence: number;
  word_count: number;
  languages_used: string[];
  boxes: { text: string; conf: number; x: number; y: number; w: number; h: number }[];
  reason: string | null;
  warning: string;
  user_corrected?: boolean;
}

export interface QrPayload {
  available: boolean;
  payloads: { data: string; format: string; decoder: string; looks_like_url?: boolean; looks_like_upi?: boolean }[];
  reason: string | null;
  note: string;
}

export interface ScoreBreakdown {
  family: string;
  points: number;
  cap: number;
}

export interface AnalysisResult {
  analysis_id: string;
  input_type: string;
  language: string;
  language_detail: LanguageDetail;
  verdict: Verdict;
  verdict_label: string;
  risk_score: number;
  confidence: number;
  scam_category: string;
  scam_category_label: string;
  summary: string;
  red_flags: RedFlag[];
  risk_factors: RiskFactor[];
  score_breakdown: ScoreBreakdown[];
  benign_adjustment: number;
  entities: EntityItem[];
  entity_reputation: {
    type: string; display_value: string; report_count: number;
    first_seen: string | null; last_seen: string | null; campaign_id: string | null;
  }[];
  campaign_links: CampaignLink[];
  recommended_actions: RecommendedAction[];
  uncertainties: string[];
  model_version: string;
  degraded_checks: DegradedCheck[];
  created_at: string;
  latency_ms: number;
  input_preview: string;
  normalization: {
    normalized_text: string;
    analysis_text: string;
    replacements: { from: string; to: string; kind: string }[];
  };
  intent: {
    intent_families: string[];
    signals: { name: string; family: string; evidence_span: string; source: string }[];
    benign_signals: { evidence_span: string }[];
    scam_category: string;
    scam_label: string;
    category_scores: Record<string, number>;
    classifier_used: boolean;
    classifier_category: string | null;
    classifier_confidence: number;
  };
  url_reports: Record<string, unknown>[];
  ocr?: OcrPayload | null;
  qr?: QrPayload | null;
  qr_destination_preview?: string[];
  message_fingerprint: string;
  evidence_hash: string;
  disclaimer: string;
  needs_input?: boolean;
  message?: string;
}

export interface Campaign {
  id: string;
  label: string;
  description: string | null;
  status: string;
  score: number;
  primary_category: string | null;
  primary_category_label?: string;
  languages: string[];
  report_count: number;
  sighting_count: number;
  first_seen: string | null;
  last_seen: string | null;
}

export interface GraphNode {
  id: string; type: string; label: string; size: number;
  shared_by?: number; report_count?: number; status?: string;
  category?: string; locality?: string; created_at?: string;
  first_seen?: string; last_seen?: string;
}

export interface GraphEdge { source: string; target: string; relation: string; note?: string }

export interface CampaignDetail {
  campaign: Campaign;
  nodes: GraphNode[];
  edges: GraphEdge[];
  timeline: { report_id: string; at: string | null; category: string; channel: string; locality: string | null }[];
  shared_indicators: GraphNode[];
  infrastructure_rotation: { distinct_domains: number; detected: boolean; note: string };
}

export interface ReportRow {
  id: string;
  analysis_id: string | null;
  category: string;
  channel: string;
  locality: string | null;
  status: string;
  visibility: string;
  campaign_id: string | null;
  duplicate_of: string | null;
  message_fingerprint: string;
  occurred_at: string | null;
  created_at: string | null;
  narrative?: string;
  narrative_excerpt?: string;
  moderation_state?: Record<string, unknown> & {
    duplicate_candidates?: { report_id: string; reason: string; relation: string; status: string }[];
  };
}

export interface Pulse {
  window_days: number;
  totals: Record<string, number>;
  reports_by_day: { date: string; count: number }[];
  by_category: { key: string; label: string; count: number }[];
  by_language: { key: string; count: number }[];
  by_locality: { key: string; count: number }[];
  by_verdict: { key: string; count: number }[];
  top_indicators: {
    type: string; display_value: string; report_count: number; sighting_count: number;
    first_seen: string | null; last_seen: string | null; campaign_id: string | null;
  }[];
  emerging_campaigns: Campaign[];
}

export interface HealthState {
  status: string;
  service: string;
  model_version: string;
  checks: Record<string, { status: string; reason?: string; note?: string; engine?: string; impact?: string }>;
  degraded: string[];
}
