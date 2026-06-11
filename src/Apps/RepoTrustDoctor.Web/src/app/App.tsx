import { useState } from 'react';
import { Header } from '../components/Header';
import { ApiScanPanel } from '../features/api-scan/ApiScanPanel';
import { ScanIntro } from '../features/api-scan/ScanIntro';
import { ScanGuide } from '../features/api-scan/ScanGuide';
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
        <section className="scan-workspace" aria-label="Scan workspace">
          <ScanIntro />
          <ApiScanPanel onReportLoaded={loadReport} />
          <ScanGuide />
        </section>
      ) : report && mode === 'report' ? (
        <ReportViewer report={report} />
      ) : (
        <section className="scan-workspace" aria-label="Scan workspace">
          <ScanIntro />
          <ApiScanPanel onReportLoaded={loadReport} />
          <ScanGuide />
        </section>
      )}
    </main>
  );
}

export default App;
