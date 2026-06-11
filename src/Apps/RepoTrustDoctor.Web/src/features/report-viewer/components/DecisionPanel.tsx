import { AlertTriangle, CheckCircle2 } from 'lucide-react';
import type { RepositoryScan } from '../../../domain/report';
import { formatDecision, scoreTone } from '../../../domain/reportSelectors';

export function DecisionPanel({ report }: { report: RepositoryScan }) {
  const hasBlockingReason = report.score.decision.reasons.length > 0;

  return (
    <section className="decision-panel" aria-label="Decision">
      <div className="overall-score-row">
        <div className={`overall-score ${scoreTone(report.score.overall)}`}>
          <strong>{report.score.overall}</strong>
          <span>/100</span>
        </div>
        <div>
          <div className="decision-heading">
            {report.score.decision.kind === 'SafeToTry'
              ? <CheckCircle2 size={18} aria-hidden="true" />
              : <AlertTriangle size={18} aria-hidden="true" />}
            <h2>{formatDecision(report.score.decision.kind)}</h2>
          </div>
          <span className="score-caption">Overall trust score</span>
        </div>
      </div>
      {hasBlockingReason ? (
        <ul className="decision-reasons">
          {report.score.decision.reasons.map((reason) => (
            <li key={reason}>{formatDecisionReason(reason)}</li>
          ))}
        </ul>
      ) : (
        <p className="muted-copy">No decision reasons were recorded.</p>
      )}
    </section>
  );
}

function formatDecisionReason(reason: string): string {
  return reason
    .replace('The selected policy requires SECURITY.md.', 'The selected profile expects a SECURITY.md file so users know how to report vulnerabilities.')
    .replace('POLICY-SECURITY-MD:', 'Security policy:')
    .replace('POLICY-GHA-PINNING:', 'Workflow pinning:')
    .replace('POLICY-VULN:', 'Vulnerability policy:')
    .replace('POLICY-LICENSE-UNKNOWN:', 'License review:')
    .replace('POLICY-LICENSE-SENSITIVE:', 'License policy:')
    .replace('POLICY-BLOCKING-FINDING:', 'Blocking finding:');
}
