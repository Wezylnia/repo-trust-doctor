import { AlertTriangle, CheckCircle2 } from 'lucide-react';
import type { RepositoryScan } from '../../../domain/report';
import { scoreTone } from '../../../domain/reportSelectors';

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
            <h2>{report.score.decision.kind}</h2>
          </div>
          <span className="score-caption">Overall trust score</span>
        </div>
      </div>
      {hasBlockingReason ? (
        <ul className="decision-reasons">
          {report.score.decision.reasons.map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
      ) : (
        <p className="muted-copy">No decision reasons were recorded.</p>
      )}
    </section>
  );
}
