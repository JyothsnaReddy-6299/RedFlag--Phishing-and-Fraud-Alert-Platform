import type { URLScanResponse, SMSScanResponse, KnownThreatsResponse } from '../types';

const API_BASE = '/api/v1';

export async function scanUrl(url: string): Promise<URLScanResponse> {
  const response = await fetch(`${API_BASE}/scan/url`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Scan request failed with HTTP ${response.status}`);
  }

  return response.json();
}

export async function scanSms(text: string, senderId?: string): Promise<SMSScanResponse> {
  const response = await fetch(`${API_BASE}/scan/sms`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ text, sender_id: senderId || undefined }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `SMS scan request failed with HTTP ${response.status}`);
  }

  return response.json();
}

export async function fetchKnownThreats(): Promise<KnownThreatsResponse> {
  const response = await fetch(`${API_BASE}/threats/known`);
  if (!response.ok) {
    throw new Error(`Failed to fetch threat intel database`);
  }
  return response.json();
}

export async function checkBackendHealth(): Promise<boolean> {
  try {
    const response = await fetch('/health');
    return response.ok;
  } catch {
    return false;
  }
}
