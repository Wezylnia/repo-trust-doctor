import type { DependencyInventoryArtifact, Finding, FindingSummary, RepositoryScan } from './report';

export const severityOrder: Record<string, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Info: 1
};

export const severities = ['All', 'Critical', 'High', 'Medium', 'Low', 'Info'];

export function recommendationText(finding: Finding): string {
  return typeof finding.recommendation === 'string'
    ? finding.recommendation
    : finding.recommendation?.message ?? '';
}

export function summarizeFindings(findings: Finding[]): FindingSummary {
  return findings.reduce(
    (summary, finding) => {
      const severity = finding.severity.toLowerCase();
      summary.total += 1;
      if (severity === 'critical') summary.critical += 1;
      if (severity === 'high') summary.high += 1;
      if (severity === 'medium') summary.medium += 1;
      if (severity === 'low') summary.low += 1;
      if (severity === 'info') summary.info += 1;
      if (finding.isBlocking) summary.blocking += 1;
      return summary;
    },
    { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, blocking: 0 }
  );
}

export function getDependencyInventory(report: RepositoryScan): DependencyInventoryArtifact | null {
  const raw = report.artifacts?.['dependency.inventory'];
  if (!raw || typeof raw !== 'object') {
    return null;
  }

  return raw as DependencyInventoryArtifact;
}
