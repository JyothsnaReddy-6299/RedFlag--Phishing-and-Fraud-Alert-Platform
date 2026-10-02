import type {
  AnalysisResult, Campaign, CampaignDetail, HealthState, Pulse, ReportRow,
} from './types';

const BASE = '/api';

async function j<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed (HTTP ${res.status})`);
  }
  return res.json() as Promise<T>;
}

const jsonPost = (path: string, body: unknown) =>
  fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

export const analyzeText = (text: string, senderId?: string) =>
  jsonPost('/analyze/text', { text, sender_id: senderId || undefined }).then(j<AnalysisResult>);

export const analyzeUrl = (url: string, context?: string) =>
  jsonPost('/analyze/url', { url, context: context || undefined }).then(j<AnalysisResult>);

export async function analyzeImage(file: File, textOverride?: string, senderId?: string) {
  const fd = new FormData();
  fd.append('file', file);
  if (textOverride) fd.append('text_override', textOverride);
  if (senderId) fd.append('sender_id', senderId);
  return j<AnalysisResult>(await fetch(`${BASE}/analyze/image`, { method: 'POST', body: fd }));
}

export async function analyzeQr(file: File) {
  const fd = new FormData();
  fd.append('file', file);
  return j<AnalysisResult>(await fetch(`${BASE}/analyze/qr`, { method: 'POST', body: fd }));
}

export const getAnalysis = (id: string) =>
  fetch(`${BASE}/analysis/${id}`).then(j<AnalysisResult>);

export const getEvidenceBundle = (id: string) =>
  fetch(`${BASE}/analysis/${id}/evidence`).then(j<Record<string, unknown>>);

export interface SubmitReportInput {
  analysis_id?: string | null;
  category: string;
  channel: string;
  narrative: string;
  locality?: string;
  consent: boolean;
  visibility: 'private' | 'public';
}

export const submitReport = (input: SubmitReportInput, autoApprove = false) =>
  jsonPost(`/reports?auto_approve=${autoApprove}`, input)
    .then(j<{ report: ReportRow; duplicate_candidates: { report_id: string; reason: string }[]; campaign: { id: string; label: string } | null; note: string }>);

export const moderationQueue = (status = 'pending') =>
  fetch(`${BASE}/reports/queue?status=${status}`).then(j<{ count: number; reports: ReportRow[] }>);

export const approveReport = (id: string) =>
  jsonPost(`/reports/${id}/approve`, {}).then(j<{ report: ReportRow; campaign: Campaign | null }>);

export const rejectReport = (id: string, reason: string) =>
  jsonPost(`/reports/${id}/reject`, { reason }).then(j<{ report: ReportRow }>);

export const mergeReport = (id: string, into: string) =>
  jsonPost(`/reports/${id}/merge`, { into_report_id: into }).then(j<{ report: ReportRow }>);

export const communityFeed = (limit = 40) =>
  fetch(`${BASE}/feed?limit=${limit}`).then(j<{ count: number; reports: ReportRow[]; note: string }>);

export const listCampaigns = () =>
  fetch(`${BASE}/campaigns`).then(j<{ count: number; campaigns: Campaign[] }>);

export const campaignDetail = (id: string) =>
  fetch(`${BASE}/campaigns/${id}`).then(j<CampaignDetail>);

export const setCampaignStatus = (id: string, status: string) =>
  jsonPost(`/campaigns/${id}/status`, { status }).then(j<{ id: string; status: string }>);

export const getPulse = (days = 30) =>
  fetch(`${BASE}/pulse?days=${days}`).then(j<Pulse>);

export const getHealth = () => fetch(`${BASE}/health`).then(j<HealthState>);

export const searchEntities = (q: string, type?: string) =>
  fetch(`${BASE}/entities?q=${encodeURIComponent(q)}${type ? `&type=${type}` : ''}`)
    .then(j<{ count: number; entities: Pulse['top_indicators'] }>);

export const lookupEntity = (type: string, value: string) =>
  fetch(`${BASE}/entities/${type}/${encodeURIComponent(value)}`)
    .then(j<Record<string, unknown>>);
