import { SeverityBadge } from '../../../components/SeverityBadge';
import type { Finding } from '../../../domain/report';
import { recommendationText } from '../../../domain/reportSelectors';

export function FindingDetail({ finding }: { finding: Finding | null }) {
  if (!finding) {
    return <section className="detail-panel empty-list">Select a finding to inspect its evidence.</section>;
  }

  return (
    <section className="detail-panel" aria-label="Finding detail">
      <div className="detail-title">
        <div>
          <span>{finding.ruleId}</span>
          <h2>{finding.title}</h2>
        </div>
        <SeverityBadge severity={finding.severity} />
      </div>
      <dl className="detail-meta">
        <div>
          <dt>Category</dt>
          <dd>{finding.category}</dd>
        </div>
        <div>
          <dt>Confidence</dt>
          <dd>{finding.confidence}</dd>
        </div>
        <div>
          <dt>Blocking</dt>
          <dd>{finding.isBlocking ? 'Yes' : 'No'}</dd>
        </div>
      </dl>
      <p className="finding-message">{finding.message}</p>
      <section className="detail-section">
        <h3>Recommendation</h3>
        <p>{recommendationText(finding)}</p>
      </section>
      <section className="detail-section">
        <h3>Evidence</h3>
        <div className="evidence-list">
          {finding.evidence.map((evidence, index) => (
            <div className="evidence-row" key={`${evidence.kind}-${index}`}>
              <strong>{evidence.kind}</strong>
              <span>{evidence.message}</span>
              {evidence.filePath ? (
                <code>
                  {evidence.filePath}
                  {evidence.lineNumber ? `:${evidence.lineNumber}` : ''}
                </code>
              ) : null}
              {evidence.value ? <code>{evidence.value}</code> : null}
            </div>
          ))}
        </div>
      </section>
      {finding.tags?.length ? (
        <div className="tag-row">
          {finding.tags.map((tag) => (
            <span key={tag}>{tag}</span>
          ))}
        </div>
      ) : null}
    </section>
  );
}
