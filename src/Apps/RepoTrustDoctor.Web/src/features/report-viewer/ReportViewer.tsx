import { useMemo, useState } from 'react';
import { ArrowLeft } from 'lucide-react';
import type { RepositoryScan } from '../../domain/report';
import {
  getDependencyInventory,
  summarizeFindings,
  buildAreaScores,
  buildScanCoverage,
  formatCategory
} from '../../domain/reportSelectors';
import { FilterToolbar } from './components/FilterToolbar';
import { CategoryScoreTable } from './components/CategoryScoreTable';
import { DecisionPanel } from './components/DecisionPanel';
import { FindingDetail } from './components/FindingDetail';
import { FindingList } from './components/FindingList';
import { ReportSidebar } from './components/ReportSidebar';
import { ScanCoveragePanel } from './components/ScanCoveragePanel';
import { NextStepsPanel } from './components/NextStepsPanel';
import { TechnicalDetailsPanel } from './components/TechnicalDetailsPanel';
import { useFindingFilters } from './useFindingFilters';

type ViewMode = 'overview' | 'category';

export function ReportViewer({ report }: { report: RepositoryScan }) {
  const [viewMode, setViewMode] = useState<ViewMode>('overview');
  const [drilldown, setDrilldown] = useState<{ label: string; categories: string[] } | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const filters = useFindingFilters(report.findings);
  const summary = useMemo(() => report.summary ?? summarizeFindings(report.findings), [report]);
  const dependencyInventory = useMemo(() => getDependencyInventory(report), [report]);
  const areaScores = useMemo(() => buildAreaScores(report), [report]);
  const scanCoverage = useMemo(() => buildScanCoverage(report.modules), [report.modules]);

  const categoryFindings = useMemo(() => {
    if (!drilldown) return report.findings;
    return report.findings.filter((f) => drilldown.categories.includes(f.category));
  }, [report.findings, drilldown]);

  const selectedFinding = useMemo(() => {
    const pool = viewMode === 'category' ? categoryFindings : filters.filteredFindings;
    return pool.find((f) => f.fingerprint === selectedId || f.ruleId === selectedId)
      ?? (pool.length > 0 ? pool[0] : null);
  }, [viewMode, categoryFindings, filters.filteredFindings, selectedId]);

  const handleCategoryClick = (areaLabel: string, categories: string[]) => {
    setDrilldown({ label: areaLabel, categories });
    setViewMode('category');
    setSelectedId(null);
  };

  const handleBackToOverview = () => {
    setViewMode('overview');
    setDrilldown(null);
    setSelectedId(null);
  };

  return (
    <section className="workspace" aria-label="Loaded report">
      <div className="report-header-grid">
        <ReportSidebar report={report} summary={summary} />
        <DecisionPanel report={report} />
        <NextStepsPanel report={report} />
      </div>
      <section className="content">
        {viewMode === 'overview' ? (
          <>
            <CategoryScoreTable report={report} onCategoryClick={handleCategoryClick} />
            <ScanCoveragePanel coverage={scanCoverage} />
            <TechnicalDetailsPanel report={report} dependencyInventory={dependencyInventory} />
            <FilterToolbar
              categories={filters.categories}
              category={filters.category}
              query={filters.query}
              severity={filters.severity}
              actionableOnly={filters.actionableOnly}
              groupRepeated={filters.groupRepeated}
              onCategoryChange={filters.setCategory}
              onClear={filters.clearFilters}
              onQueryChange={filters.setQuery}
              onSeverityChange={filters.setSeverity}
              onActionableOnlyChange={filters.setActionableOnly}
              onGroupRepeatedChange={filters.setGroupRepeated}
            />
            <div className="finding-layout">
              <FindingList
                findings={filters.filteredFindings}
                selectedFinding={selectedFinding}
                onSelectFinding={(finding) => setSelectedId(finding.fingerprint ?? finding.ruleId)}
                groupRepeated={filters.groupRepeated}
              />
              <FindingDetail finding={selectedFinding} />
            </div>
          </>
        ) : (
          <>
            <div className="drilldown-header">
              <button className="back-button" onClick={handleBackToOverview}>
                <ArrowLeft size={15} aria-hidden="true" />
                Back to overview
              </button>
              <h2>{drilldown ? drilldown.label : 'Category'} findings ({categoryFindings.length})</h2>
              {drilldown && drilldown.categories.length > 1 ? (
                <span>{drilldown.categories.map(formatCategory).join(', ')}</span>
              ) : null}
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
