import { ChevronDown, Cpu, PackageSearch } from 'lucide-react';
import { StatusPill } from '../../../components/StatusPill';
import type { DependencyInventoryArtifact, RepositoryScan } from '../../../domain/report';
import { formatCategory, formatStatus } from '../../../domain/reportSelectors';

export function TechnicalDetailsPanel({
  report,
  dependencyInventory
}: {
  report: RepositoryScan;
  dependencyInventory: DependencyInventoryArtifact | null;
}) {
  return (
    <details className="technical-details-panel">
      <summary>
        <span><Cpu size={17} aria-hidden="true" /> Technical details</span>
        <small>Module coverage, report metadata, and dependency inventory</small>
        <ChevronDown size={17} className="details-chevron" aria-hidden="true" />
      </summary>
      <div className="technical-details-content">
        <dl className="technical-metadata">
          <div><dt>Scan ID</dt><dd>{report.id ?? 'Not recorded'}</dd></div>
          <div><dt>Engine version</dt><dd>{report.toolVersion}</dd></div>
          <div><dt>Started</dt><dd>{formatTimestamp(report.startedAt)}</dd></div>
          <div><dt>Completed</dt><dd>{formatTimestamp(report.completedAt)}</dd></div>
        </dl>

        {dependencyInventory ? (
          <section className="technical-inventory">
            <h3><PackageSearch size={16} aria-hidden="true" /> Dependency inventory</h3>
            <div>
              <span>{dependencyInventory.manifests?.length ?? 0} manifests</span>
              <span>{dependencyInventory.lockfiles?.length ?? 0} lockfiles</span>
              <span>{dependencyInventory.packages?.length ?? 0} packages</span>
              <span>{dependencyInventory.packageSources?.length ?? 0} sources</span>
            </div>
          </section>
        ) : null}

        <section>
          <h3>Analyzer modules ({report.modules.length})</h3>
          <div className="technical-module-grid">
            {report.modules.map((module) => (
              <div className="technical-module" key={module.moduleId}>
                <div>
                  <strong>{module.displayName}</strong>
                  <span>{formatCategory(module.category)} · {formatStatus(module.status)}</span>
                </div>
                <StatusPill status={module.status} count={module.findingsCount} />
              </div>
            ))}
          </div>
        </section>
      </div>
    </details>
  );
}

function formatTimestamp(value?: string): string {
  if (!value) return 'Not recorded';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}
