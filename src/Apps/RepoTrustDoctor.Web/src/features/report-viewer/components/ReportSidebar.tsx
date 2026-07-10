import { FolderGit2 } from 'lucide-react';
import { Metric } from '../../../components/Metric';
import type { FindingSummary, RepositoryScan } from '../../../domain/report';
import { formatRepositoryTarget, formatStatus, formatTrustProfile } from '../../../domain/reportSelectors';

interface ReportSidebarProps {
  report: RepositoryScan;
  summary: FindingSummary;
}

export function ReportSidebar({ report, summary }: ReportSidebarProps) {
  return (
    <aside className="sidebar">
      <section className="summary-panel" aria-label="Report summary">
        <div className="report-context-heading">
          <FolderGit2 size={18} aria-hidden="true" />
          <span>Repository review</span>
        </div>
        <h2 className="repository-name">{formatRepositoryTarget(report.target)}</h2>
        <dl className="metadata-grid">
          <div>
            <dt>Decision context</dt>
            <dd>{formatTrustProfile(report.trustProfile)}</dd>
          </div>
          <div>
            <dt>Evidence depth</dt>
            <dd>{formatStatus(report.depth)}</dd>
          </div>
          <div>
            <dt>Scan coverage</dt>
            <dd>{formatStatus(report.status)}</dd>
          </div>
        </dl>
      </section>

      <section className="summary-panel" aria-label="Finding counts">
        <div className="metric-grid">
          <Metric label="Critical" value={summary.critical} tone="critical" />
          <Metric label="High" value={summary.high} tone="high" />
          <Metric label="Medium" value={summary.medium} tone="medium" />
          <Metric label="Low" value={summary.low} tone="low" />
          <Metric label="Info" value={summary.info} tone="info" />
          <Metric label="Blocking" value={summary.blocking} tone="blocking" />
        </div>
      </section>

    </aside>
  );
}
