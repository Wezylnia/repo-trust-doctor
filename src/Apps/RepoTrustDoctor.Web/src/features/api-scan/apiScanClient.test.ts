import { describe, expect, it } from 'vitest';
import {
  buildGitHubRepositoryUrl,
  isTerminalScanState,
  normalizeApiBaseUrl,
  normalizeGitHubRepositoryInput
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
