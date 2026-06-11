import { useState } from 'react';
import { Header } from '../components/Header';
import { ApiScanPanel } from '../features/api-scan/ApiScanPanel';
import { ReportViewer } from '../features/report-viewer/ReportViewer';
import type { RepositoryScan } from '../domain/report';

type WorkspaceMode = 'report' | 'scan';

function App() {
  const [report, setReport] = useState<RepositoryScan | null>(null);
  const [mode, setMode] = useState<WorkspaceMode>('scan');

  const loadReport = (nextReport: RepositoryScan) => {
    setReport(nextReport);
    setMode('report');
  };

  return (
    <main className="app-shell">
      <Header
        hasReport={report !== null}
        mode={mode}
        onOpenReport={() => setMode(report ? 'report' : 'scan')}
        onOpenScan={() => setMode('scan')}
      />

      {mode === 'scan' ? (
        <section className="single-workspace" aria-label="Scan workspace">
          <ApiScanPanel onReportLoaded={loadReport} />
        </section>
      ) : report && mode === 'report' ? (
        <ReportViewer report={report} />
      ) : (
        <section className="single-workspace" aria-label="No report">
          <ApiScanPanel onReportLoaded={loadReport} />
        </section>
      )}
    </main>
  );
}

export default App;
