import { describe, expect, it } from 'vitest';
import type { Finding, RepositoryScan } from './report';
import {
  buildAreaScores,
  buildScanCoverage,
  explainFinding,
  formatCategory,
  formatDecision,
  formatEvidenceKind,
  formatTrustProfile,
  getDependencyInventory,
  recommendationText,
  scoreTone,
  summarizeFindings
} from './reportSelectors';

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
      toolVersion: '1.0.6',
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

  it('maps overall scores to visual tones', () => {
    expect(scoreTone(95)).toBe('excellent');
    expect(scoreTone(84)).toBe('good');
    expect(scoreTone(72)).toBe('warning');
    expect(scoreTone(40)).toBe('danger');
  });

  it('formats report enum values for display', () => {
    expect(formatDecision('NeedsManualReview')).toBe('Needs manual review');
    expect(formatTrustProfile('SecuritySensitiveDependency')).toBe('Enterprise or security-sensitive');
    expect(formatCategory('RepositoryHealth')).toBe('Repository health');
    expect(formatEvidenceKind('file-missing')).toBe('File missing');
  });

  it('builds area scores from explicit scores and completed module categories', () => {
    const report: RepositoryScan = {
      target: '.',
      depth: 'Fast',
      trustProfile: 'ProductionDependency',
      toolVersion: '1.0.7',
      status: 'Completed',
      modules: [
        { moduleId: 'repo', displayName: 'Repository Health', category: 'RepositoryHealth', status: 'Completed', findingsCount: 2 },
        { moduleId: 'secrets', displayName: 'Secret Quick Scan', category: 'Security', status: 'Completed', findingsCount: 0 },
        { moduleId: 'docker', displayName: 'Docker Basic Checks', category: 'Containers', status: 'Completed', findingsCount: 1 }
      ],
      findings: [],
      score: {
        overall: 72,
        categories: [
          { category: 'RepositoryHealth', score: 56 },
          { category: 'Containers', score: 70 }
        ],
        decision: {
          kind: 'UseWithCaution',
          reasons: []
        }
      }
    };

    const areas = buildAreaScores(report);

    expect(areas.find((area) => area.id === 'repository-health')?.score).toBe(56);
    expect(areas.find((area) => area.id === 'security')?.score).toBe(100);
    expect(areas.find((area) => area.id === 'containers')?.score).toBe(70);
  });

  it('summarizes dependency and secret scan coverage without exposing raw metric keys', () => {
    const coverage = buildScanCoverage([
      {
        moduleId: 'dependency-vulnerability',
        displayName: 'Dependency vulnerabilities',
        category: 'Dependencies',
        status: 'CompletedWithWarnings',
        findingsCount: 0,
        metrics: {
          'dependency.vulnerability.supported.count': '120',
          'dependency.vulnerability.lookup.completed.count': '100',
          'dependency.vulnerability.lookup.incomplete.count': '20',
          'dependency.vulnerability.unpinned.count': '8',
          'dependency.vulnerability.unsupported.count': '2'
        }
      },
      {
        moduleId: 'secrets',
        displayName: 'Secret scan',
        category: 'Security',
        status: 'Completed',
        findingsCount: 0,
        metrics: {
          'secret.source.content.coverage.percent': '64.25',
          'secret.configuration.content.coverage.percent': '100'
        }
      }
    ]);

    expect(coverage).toEqual([
      expect.objectContaining({
        label: 'Known vulnerabilities',
        status: 'partial',
        detail: expect.stringContaining('100 of 120 exact-version packages')
      }),
      expect.objectContaining({
        label: 'Secret content scan',
        status: 'partial',
        detail: 'Source files 64.25%. Configuration files 100%'
      })
    ]);
    expect(coverage[0].detail).toContain('8 dependencies had no exact version');
    expect(coverage[0].detail).not.toContain('dependency.vulnerability');
  });

  it('surfaces failed analyzers even when they have no coverage metrics', () => {
    const coverage = buildScanCoverage([{
      moduleId: 'codebase',
      displayName: 'Codebase analysis',
      category: 'Codebase',
      status: 'Failed',
      findingsCount: 0,
      errorMessage: 'Parser failed.'
    }]);

    expect(coverage).toEqual([{
      id: 'codebase',
      label: 'Codebase analysis',
      detail: 'Parser failed.',
      status: 'failed',
      warning: undefined
    }]);
  });

  it('adds richer finding explanations by rule family', () => {
    expect(explainFinding(finding('TRUST-VULN001', 'High', false))).toContain('vulnerability risk');
    expect(explainFinding(finding('TRUST-GHA005', 'Medium', false))).toContain('workflow safety');
  });

  it('explains v1.6 hardening rules specifically', () => {
    expect(explainFinding(finding('TRUST-COMP006', 'Critical', true))).toContain('Docker socket');
    expect(explainFinding(finding('TRUST-K8S006', 'High', false))).toContain('hostPath');
    expect(explainFinding(finding('TRUST-EVI004', 'Medium', false))).toContain('parsed as valid JSON');
    expect(explainFinding(finding('TRUST-DEP050', 'Medium', false))).toContain('dynamic version');
  });

  it('explains v1.7 codebase rules specifically', () => {
    expect(explainFinding(finding('TRUST-CODE012', 'Medium', false))).toContain('authentication');
    expect(explainFinding(finding('TRUST-CODE015', 'High', false))).toContain('command execution');
    expect(explainFinding(finding('TRUST-CODE019', 'Medium', false))).toContain('observability gap');
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
