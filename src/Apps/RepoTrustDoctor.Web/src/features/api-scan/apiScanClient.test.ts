import { describe, expect, it } from 'vitest';
import { isTerminalScanState, normalizeApiBaseUrl } from './apiScanClient';

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
});
