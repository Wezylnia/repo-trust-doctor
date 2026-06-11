import { useMemo, useState } from 'react';
import type { RepositoryScan } from '../../domain/report';
import { getDependencyInventory, summarizeFindings } from '../../domain/reportSelectors';
import { FilterToolbar } from './components/FilterToolbar';
import { CategoryScoreTable } from './components/CategoryScoreTable';
import { DecisionPanel } from './components/DecisionPanel';
import { FindingDetail } from './components/FindingDetail';
import { FindingList } from './components/FindingList';
import { ReportSidebar } from './components/ReportSidebar';
import { useFindingFilters } from './useFindingFilters';

export function ReportViewer({ report }: { report: RepositoryScan }) {
  const [selectedId, setSelectedId] = useState<string | null>(
    report.findings[0]?.fingerprint ?? report.findings[0]?.ruleId ?? null
  );
  const filters = useFindingFilters(report.findings);
  const summary = useMemo(() => report.summary ?? summarizeFindings(report.findings), [report]);
  const dependencyInventory = useMemo(() => getDependencyInventory(report), [report]);

  const selectedFinding = useMemo(() => {
    return filters.filteredFindings.find((finding) => finding.fingerprint === selectedId || finding.ruleId === selectedId)
      ?? filters.filteredFindings[0]
      ?? null;
  }, [filters.filteredFindings, selectedId]);

  return (
    <section className="workspace" aria-label="Loaded report">
      <ReportSidebar report={report} summary={summary} dependencyInventory={dependencyInventory} />
      <section className="content">
        <div className="report-overview">
          <DecisionPanel report={report} />
          <CategoryScoreTable report={report} />
        </div>
        <FilterToolbar
          categories={filters.categories}
          category={filters.category}
          query={filters.query}
          severity={filters.severity}
          onCategoryChange={filters.setCategory}
          onClear={filters.clearFilters}
          onQueryChange={filters.setQuery}
          onSeverityChange={filters.setSeverity}
        />
        <div className="finding-layout">
          <FindingList
            findings={filters.filteredFindings}
            selectedFinding={selectedFinding}
            onSelectFinding={(finding) => setSelectedId(finding.fingerprint ?? finding.ruleId)}
          />
          <FindingDetail finding={selectedFinding} />
        </div>
      </section>
    </section>
  );
}
