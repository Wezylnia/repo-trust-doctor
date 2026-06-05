import { SeverityBadge } from '../../../components/SeverityBadge';
import type { Finding } from '../../../domain/report';

interface FindingListProps {
  findings: Finding[];
  selectedFinding: Finding | null;
  onSelectFinding: (finding: Finding) => void;
}

export function FindingList({ findings, selectedFinding, onSelectFinding }: FindingListProps) {
  return (
    <section className="finding-list" aria-label="Findings">
      <div className="list-heading">
        <h2>Findings</h2>
        <span>{findings.length} shown</span>
      </div>
      {findings.length > 0 ? (
        findings.map((finding) => (
          <button
            type="button"
            className={`finding-row ${selectedFinding === finding ? 'selected' : ''}`}
            key={finding.fingerprint ?? `${finding.ruleId}-${finding.title}`}
            onClick={() => onSelectFinding(finding)}
          >
            <span className={`severity-dot ${finding.severity.toLowerCase()}`} />
            <span>
              <strong>{finding.ruleId}</strong>
              <span>{finding.title}</span>
            </span>
            <SeverityBadge severity={finding.severity} />
          </button>
        ))
      ) : (
        <div className="empty-list">No findings match the current filters.</div>
      )}
    </section>
  );
}
