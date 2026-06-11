import { useMemo, useState } from 'react';
import type { RepositoryScan } from '../../domain/report';
import { getDependencyInventory, summarizeFindings, buildAreaScores, formatCategory } from '../../domain/reportSelectors';
import { FilterToolbar } from './components/FilterToolbar';
import { CategoryScoreTable } from './components/CategoryScoreTable';
import { DecisionPanel } from './components/DecisionPanel';
import { FindingDetail } from './components/FindingDetail';
import { FindingList } from './components/FindingList';
import { ReportSidebar } from './components/ReportSidebar';
import { useFindingFilters } from './useFindingFilters';

type ViewMode = 'overview' | 'category';

export function ReportViewer({ report }: { report: RepositoryScan }) {
  const [viewMode, setViewMode] = useState<ViewMode>('overview');
  const [drillCategory, setDrillCategory] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const filters = useFindingFilters(report.findings);
  const summary = useMemo(() => report.summary ?? summarizeFindings(report.findings), [report]);
  const dependencyInventory = useMemo(() => getDependencyInventory(report), [report]);
  const areaScores = useMemo(() => buildAreaScores(report), [report]);

  const categoryFindings = useMemo(() => {
    if (!drillCategory) return report.findings;
    return report.findings.filter((f) => f.category === drillCategory);
  }, [report.findings, drillCategory]);

  const selectedFinding = useMemo(() => {
    const pool = viewMode === 'category' ? categoryFindings : filters.filteredFindings;
    return pool.find((f) => f.fingerprint === selectedId || f.ruleId === selectedId)
      ?? (pool.length > 0 ? pool[0] : null);
  }, [viewMode, categoryFindings, filters.filteredFindings, selectedId]);

  const handleCategoryClick = (areaLabel: string, categories: string[]) => {
    if (categories.length === 1) {
      setDrillCategory(categories[0]);
    } else {
      setDrillCategory(categories[0]);
    }
    setViewMode('category');
    setSelectedId(null);
  };

  const handleBackToOverview = () => {
    setViewMode('overview');
    setDrillCategory(null);
    setSelectedId(null);
  };

  return (
    <section className="workspace" aria-label="Loaded report">
      <ReportSidebar report={report} summary={summary} dependencyInventory={dependencyInventory} />
      <section className="content">
        {viewMode === 'overview' ? (
          <>
            <div className="report-overview">
              <DecisionPanel report={report} />
              <CategoryScoreTable
                report={report}
                onCategoryClick={handleCategoryClick}
              />
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
          </>
        ) : (
          <>
            <div className="drilldown-header">
              <button className="back-button" onClick={handleBackToOverview}>
                ← Back to overview
              </button>
              <h2>{drillCategory ? formatCategory(drillCategory) : 'Category'} findings ({categoryFindings.length})</h2>
            </div>
            <div className="finding-layout">
              <FindingList
                findings={categoryFindings}
                selectedFinding={selectedFinding}
                onSelectFinding={(finding) => setSelectedId(finding.fingerprint ?? finding.ruleId)}
              />
              <FindingDetail finding={selectedFinding} />
            </div>
          </>
        )}
      </section>
    </section>
  );
}
