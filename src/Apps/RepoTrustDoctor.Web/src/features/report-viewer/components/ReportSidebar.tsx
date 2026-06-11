import { ShieldCheck } from 'lucide-react';
import { Metric } from '../../../components/Metric';
import { StatusPill } from '../../../components/StatusPill';
import type { DependencyInventoryArtifact, FindingSummary, RepositoryScan } from '../../../domain/report';

interface ReportSidebarProps {
  report: RepositoryScan;
  summary: FindingSummary;
  dependencyInventory: DependencyInventoryArtifact | null;
}

export function ReportSidebar({ report, summary, dependencyInventory }: ReportSidebarProps) {
  return (
    <aside className="sidebar">
      <section className="summary-panel" aria-label="Report summary">
        <div className={`summary-heading ${report.score.decision.kind.toLowerCase()}`}>
          <ShieldCheck size={18} aria-hidden="true" />
          <span>{report.score.decision.kind}</span>
        </div>
        <div className="score-row">
          <span className="score">{report.score.overall}</span>
          <span className="score-label">/ 100</span>
        </div>
        <dl className="metadata-grid">
          <div>
            <dt>Target</dt>
            <dd>{report.target}</dd>
          </div>
          <div>
            <dt>Profile</dt>
            <dd>{report.trustProfile}</dd>
          </div>
          <div>
            <dt>Depth</dt>
            <dd>{report.depth}</dd>
          </div>
          <div>
            <dt>Version</dt>
            <dd>{report.toolVersion}</dd>
          </div>
          <div>
            <dt>Status</dt>
            <dd>{report.status}</dd>
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

      <section className="summary-panel" aria-label="Modules">
        <h2>Modules</h2>
        <div className="module-list">
          {report.modules.map((module) => (
            <div className="module-row" key={module.moduleId}>
              <div>
                <strong>{module.displayName}</strong>
                <span>{module.category}</span>
              </div>
              <StatusPill status={module.status} count={module.findingsCount} />
            </div>
          ))}
        </div>
      </section>

      {dependencyInventory ? (
        <section className="summary-panel" aria-label="Dependency inventory">
          <h2>Dependencies</h2>
          <div className="inventory-grid">
            <Metric label="Manifests" value={dependencyInventory.manifests?.length ?? 0} />
            <Metric label="Lockfiles" value={dependencyInventory.lockfiles?.length ?? 0} />
            <Metric label="Packages" value={dependencyInventory.packages?.length ?? 0} />
            <Metric label="Sources" value={dependencyInventory.packageSources?.length ?? 0} />
          </div>
        </section>
      ) : null}
    </aside>
  );
}
