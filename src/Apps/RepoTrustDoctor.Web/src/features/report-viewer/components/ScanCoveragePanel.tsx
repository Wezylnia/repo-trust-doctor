import { CheckCircle2, CircleAlert, ScanSearch, TriangleAlert } from 'lucide-react';
import type { ScanCoverageSummary } from '../../../domain/reportSelectors';

export function ScanCoveragePanel({ coverage }: { coverage: ScanCoverageSummary[] }) {
  if (coverage.length === 0) {
    return null;
  }

  return (
    <section className="coverage-panel" aria-label="Scan coverage">
      <div className="coverage-heading">
        <ScanSearch size={18} aria-hidden="true" />
        <div>
          <h2>Scan coverage</h2>
          <span>Checks that depend on file limits, exact package versions, or external services.</span>
        </div>
      </div>
      <div className="coverage-list">
        {coverage.map((item) => (
          <div className={`coverage-row ${item.status}`} key={item.id}>
            <span className="coverage-icon" aria-hidden="true">
              {item.status === 'complete' ? <CheckCircle2 size={17} /> : null}
              {item.status === 'partial' ? <CircleAlert size={17} /> : null}
              {item.status === 'failed' ? <TriangleAlert size={17} /> : null}
            </span>
            <div>
              <strong>{item.label}</strong>
              <span>{item.detail}</span>
              {item.warning ? <small>{item.warning}</small> : null}
            </div>
            <b>{item.status === 'complete' ? 'Complete' : item.status === 'partial' ? 'Partial' : 'Failed'}</b>
          </div>
        ))}
      </div>
    </section>
  );
}
