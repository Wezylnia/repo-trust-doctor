import type { RepositoryScan } from '../../domain/report';

export interface ApiScanRequest {
  apiBaseUrl: string;
  repository: string;
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
  reportJsonUrl?: string | null;
  reportMarkdownUrl?: string | null;
  reportSarifUrl?: string | null;
}

export interface HealthResponse {
  product: string;
  version: string;
  apiCompatibilityVersion: string;
  status: string;
  allowedWebOrigins: string[];
}

export interface ScanProgressResponse {
  scanId: string;
  state: string;
  updatedAt: string;
  modules: Array<{
    moduleId: string;
    displayName: string;
    category: string;
    status: string;
    findingsCount: number;
    statusMessage?: string | null;
  }>;
  completedModuleCount: number;
  totalModuleCount: number;
  statusMessage?: string | null;
  completionRatio: number;
}

export async function checkHealth(apiBaseUrl: string): Promise<HealthResponse> {
  const response = await fetch(`${normalizeApiBaseUrl(apiBaseUrl)}/health`);
  if (!response.ok) {
    throw new Error(`Health check failed with ${response.status}.`);
  }
  return await response.json() as HealthResponse;
}

export function normalizeApiBaseUrl(value: string): string {
  return value.trim().replace(/\/+$/, '');
}

export function normalizeGitHubRepositoryInput(value: string): string {
  return value
    .trim()
    .replace(/^https?:\/\/github\.com\//i, '')
    .replace(/^github\.com\//i, '')
    .replace(/^\/+/, '')
    .replace(/\.git$/i, '')
    .replace(/\/+$/, '');
}

export function buildGitHubRepositoryUrl(value: string): string {
  const repository = normalizeGitHubRepositoryInput(value);
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) {
    throw new Error('Enter a GitHub repository as owner/repo.');
  }

  return `https://github.com/${repository}`;
}

export async function startScan(request: ApiScanRequest): Promise<StartScanResponse> {
  const baseUrl = normalizeApiBaseUrl(request.apiBaseUrl);
  const target = buildGitHubRepositoryUrl(request.repository);
  const response = await fetch(`${baseUrl}/api/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target,
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

export async function getScanProgress(apiBaseUrl: string, scanId: string): Promise<ScanProgressResponse> {
  const response = await fetch(`${normalizeApiBaseUrl(apiBaseUrl)}/api/scans/${scanId}/progress`);
  if (!response.ok) {
    throw new Error(await readApiError(response));
  }

  return await response.json() as ScanProgressResponse;
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
