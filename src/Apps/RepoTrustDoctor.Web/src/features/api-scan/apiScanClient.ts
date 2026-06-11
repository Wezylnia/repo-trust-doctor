import type { RepositoryScan } from '../../domain/report';

export interface ApiScanRequest {
  apiBaseUrl: string;
  target: string;
  depth: string;
  trustProfile: string;
}

export interface StartScanResponse {
  scanId: string;
  status: string;
  statusUrl: string;
}

export interface ScanStatusResponse {
  scanId: string;
  target: string;
  depth: string;
  trustProfile: string;
  state: string;
  statusMessage?: string | null;
  moduleCount?: number | null;
  findingCount?: number | null;
  overallScore?: number | null;
  decision?: string | null;
}

export function normalizeApiBaseUrl(value: string): string {
  return value.trim().replace(/\/+$/, '');
}

export async function startScan(request: ApiScanRequest): Promise<StartScanResponse> {
  const baseUrl = normalizeApiBaseUrl(request.apiBaseUrl);
  const response = await fetch(`${baseUrl}/api/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target: request.target.trim(),
      depth: request.depth,
      trustProfile: request.trustProfile
    })
  });

  if (!response.ok) {
    throw new Error(await readApiError(response));
  }

  return await response.json() as StartScanResponse;
}

export async function getScanStatus(apiBaseUrl: string, scanId: string): Promise<ScanStatusResponse> {
  const response = await fetch(`${normalizeApiBaseUrl(apiBaseUrl)}/api/scans/${scanId}`);
  if (!response.ok) {
    throw new Error(await readApiError(response));
  }

  return await response.json() as ScanStatusResponse;
}

export async function getScanReport(apiBaseUrl: string, scanId: string): Promise<RepositoryScan> {
  const response = await fetch(`${normalizeApiBaseUrl(apiBaseUrl)}/api/scans/${scanId}/report?format=json`);
  if (!response.ok) {
    throw new Error(await readApiError(response));
  }

  return await response.json() as RepositoryScan;
}

export async function cancelScan(apiBaseUrl: string, scanId: string): Promise<void> {
  const response = await fetch(`${normalizeApiBaseUrl(apiBaseUrl)}/api/scans/${scanId}/cancel`, {
    method: 'POST'
  });
  if (!response.ok) {
    throw new Error(await readApiError(response));
  }
}

export function isTerminalScanState(state: string): boolean {
  return state === 'Completed' || state === 'Failed' || state === 'Cancelled';
}

async function readApiError(response: Response): Promise<string> {
  const fallback = `API request failed with ${response.status}.`;
  const text = await response.text();
  if (!text) {
    return fallback;
  }

  try {
    const parsed = JSON.parse(text) as { error?: string };
    return parsed.error ?? fallback;
  } catch {
    return text;
  }
}
