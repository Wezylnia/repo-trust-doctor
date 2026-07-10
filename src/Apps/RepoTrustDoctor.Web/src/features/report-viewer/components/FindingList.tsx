import { SeverityBadge } from '../../../components/SeverityBadge';
import type { Finding } from '../../../domain/report';

interface FindingListProps {
  findings: Finding[];
  selectedFinding: Finding | null;
  onSelectFinding: (finding: Finding) => void;
  groupRepeated?: boolean;
}

export function FindingList({ findings, selectedFinding, onSelectFinding, groupRepeated = false }: FindingListProps) {
  const visibleFindings = groupRepeated
    ? Array.from(findings.reduce((groups, finding) => {
        const key = `${finding.ruleId}\u0000${finding.title}`;
        const existing = groups.get(key);
        if (existing) existing.count += 1;
        else groups.set(key, { finding, count: 1 });
        return groups;
      }, new Map<string, { finding: Finding; count: number }>()).values())
    : findings.map((finding) => ({ finding, count: 1 }));

  return (
    <section className="finding-list" aria-label="Findings">
      <div className="list-heading">
        <h2>Findings</h2>
        <span>{visibleFindings.length} shown{visibleFindings.length !== findings.length ? ` · ${findings.length} total` : ''}</span>
      </div>
      {findings.length > 0 ? (
        visibleFindings.map(({ finding, count }, index) => (
          <button
            type="button"
            className={`finding-row ${selectedFinding === finding ? 'selected' : ''}`}
            key={finding.fingerprint ?? `${finding.ruleId}-${finding.title}-${index}`}
            onClick={() => onSelectFinding(finding)}
          >
            <span className={`severity-dot ${finding.severity.toLowerCase()}`} />
            <span>
              <strong>{finding.ruleId}</strong>
              <span>{finding.title}</span>
            </span>
            <SeverityBadge severity={finding.severity} />
            {count > 1 ? <span className="repeat-count">×{count}</span> : null}
          </button>
        ))
      ) : (
        <div className="empty-list">No findings match the current filters.</div>
      )}
    </section>
  );
}
