import { describe, expect, it } from 'vitest';
import {
  buildGitHubRepositoryUrl,
  isTerminalScanState,
  normalizeApiBaseUrl,
  normalizeGitHubRepositoryInput,
  type ScanStatusResponse
} from './apiScanClient';

describe('api scan client helpers', () => {
  it('normalizes API base URLs for endpoint composition', () => {
    expect(normalizeApiBaseUrl(' http://localhost:5000/// ')).toBe('http://localhost:5000');
  });

  it('identifies terminal scan states', () => {
    expect(isTerminalScanState('Completed')).toBe(true);
    expect(isTerminalScanState('Failed')).toBe(true);
    expect(isTerminalScanState('Cancelled')).toBe(true);
    expect(isTerminalScanState('RunningFastModules')).toBe(false);
  });

  it('normalizes pasted GitHub repository URLs into owner/repo form', () => {
    expect(normalizeGitHubRepositoryInput('https://github.com/owner/repo.git')).toBe('owner/repo');
    expect(normalizeGitHubRepositoryInput('github.com/owner/repo/')).toBe('owner/repo');
  });

  it('builds GitHub repository URLs from owner/repo input', () => {
    expect(buildGitHubRepositoryUrl('owner/repo')).toBe('https://github.com/owner/repo');
    expect(() => buildGitHubRepositoryUrl('owner')).toThrow('owner/repo');
  });
});

describe('scan status response', () => {
  it('includes report export URLs when available', () => {
    const status: ScanStatusResponse = {
      scanId: 'abc-123',
      target: 'https://github.com/test/repo',
      depth: 'Fast',
      trustProfile: 'ProductionDependency',
      state: 'Completed',
      overallScore: 85,
      moduleCount: 12,
      findingCount: 5,
      decision: 'SafeToTry',
      reportJsonUrl: '/api/scans/abc-123/report?format=json',
      reportMarkdownUrl: '/api/scans/abc-123/report?format=markdown',
      reportSarifUrl: '/api/scans/abc-123/report?format=sarif'
    };

    expect(status.reportJsonUrl).toBe('/api/scans/abc-123/report?format=json');
    expect(status.reportMarkdownUrl).toBe('/api/scans/abc-123/report?format=markdown');
    expect(status.reportSarifUrl).toBe('/api/scans/abc-123/report?format=sarif');
  });

  it('has null export URLs when scan is not completed', () => {
    const status: ScanStatusResponse = {
      scanId: 'abc-123',
      target: 'https://github.com/test/repo',
      depth: 'Fast',
      trustProfile: 'ProductionDependency',
      state: 'RunningFastModules',
      reportJsonUrl: null,
      reportMarkdownUrl: null,
      reportSarifUrl: null
    };

    expect(status.reportJsonUrl).toBeNull();
    expect(status.state).toBe('RunningFastModules');
    expect(isTerminalScanState(status.state)).toBe(false);
  });
});
