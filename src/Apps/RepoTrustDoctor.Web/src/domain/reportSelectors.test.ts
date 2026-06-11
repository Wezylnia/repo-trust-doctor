import { describe, expect, it } from 'vitest';
import type { Finding, RepositoryScan } from './report';
import { getDependencyInventory, recommendationText, summarizeFindings } from './reportSelectors';

describe('report selectors', () => {
  it('summarizes findings by severity and blocking state', () => {
    const findings: Finding[] = [
      finding('TRUST-1', 'Critical', true),
      finding('TRUST-2', 'High', false),
      finding('TRUST-3', 'Medium', false),
      finding('TRUST-4', 'Low', false),
      finding('TRUST-5', 'Info', false)
    ];

    expect(summarizeFindings(findings)).toEqual({
      total: 5,
      critical: 1,
      high: 1,
      medium: 1,
      low: 1,
      info: 1,
      blocking: 1
    });
  });

  it('reads recommendation text from object and string shapes', () => {
    expect(recommendationText(finding('TRUST-1', 'Low', false, 'Pin it.'))).toBe('Pin it.');
    expect(recommendationText({ ...finding('TRUST-2', 'Low', false), recommendation: 'Review it.' })).toBe('Review it.');
  });

  it('returns dependency inventory artifact when present', () => {
    const report: RepositoryScan = {
      target: '.',
      depth: 'Fast',
      trustProfile: 'ProductionDependency',
      toolVersion: '1.0.5',
      status: 'Completed',
      modules: [],
      findings: [],
      score: {
        overall: 100,
        categories: [],
        decision: {
          kind: 'SafeToTry',
          reasons: []
        }
      },
      artifacts: {
        'dependency.inventory': {
          manifests: [{ path: 'package.json' }],
          packages: [{ name: 'react' }]
        }
      }
    };

    expect(getDependencyInventory(report)?.packages).toHaveLength(1);
  });
});

function finding(ruleId: string, severity: string, isBlocking: boolean, recommendation = 'Review.'): Finding {
  return {
    ruleId,
    title: ruleId,
    category: 'Test',
    severity,
    confidence: 'High',
    message: 'message',
    evidence: [],
    recommendation: { message: recommendation },
    isBlocking
  };
}
