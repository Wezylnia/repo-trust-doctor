import { ArrowRight, CheckCircle2, CircleAlert, ShieldCheck } from 'lucide-react';
import type { RepositoryScan } from '../../../domain/report';
import { formatDecision } from '../../../domain/reportSelectors';

function plainReason(reason: string): string {
  return reason
    .replace(/^[A-Z0-9-]+:\s*/, '')
    .replace('The selected policy requires SECURITY.md.', 'Add a SECURITY.md so security researchers know how to report vulnerabilities.')
    .replace('Unknown dependency license requires policy review.', 'Verify unknown dependency licenses before approving this repository.')
    .replace(' exceeds policy maximum vulnerability severity High.', ' exceeds the vulnerability threshold for this profile.');
}

export function NextStepsPanel({ report }: { report: RepositoryScan }) {
  const reasons = report.score.decision.reasons.slice(0, 3);
  const isApproved = report.score.decision.kind === 'SafeToTry';

  return (
    <section className="next-steps-panel" aria-label="Recommended next steps">
      <div className="next-steps-heading">
        {isApproved ? <CheckCircle2 size={19} aria-hidden="true" /> : <CircleAlert size={19} aria-hidden="true" />}
        <div>
          <span>Start here</span>
          <h2>{isApproved ? 'Why this is ready to try' : `What to resolve before you ${formatDecision(report.score.decision.kind).toLowerCase()}`}</h2>
        </div>
      </div>
      {reasons.length > 0 ? (
        <ol className="next-steps-list">
          {reasons.map((reason) => <li key={reason}>{plainReason(reason)}</li>)}
        </ol>
      ) : (
        <p>Review the highest-severity findings and the scan coverage before making an adoption decision.</p>
      )}
      <div className="next-steps-footnote">
        <ShieldCheck size={15} aria-hidden="true" /> Evidence and recommended fixes are available in each finding below.
        <ArrowRight size={15} aria-hidden="true" />
      </div>
    </section>
  );
}
