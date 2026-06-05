import { useMemo, useRef, useState } from 'react';
import { Header } from '../components/Header';
import { sampleReport } from '../data/sampleReport';
import { ReportImport } from '../features/report-import/ReportImport';
import { ReportViewer } from '../features/report-viewer/ReportViewer';
import type { RepositoryScan } from '../domain/report';

function App() {
  const [report, setReport] = useState<RepositoryScan | null>(null);
  const [pasteValue, setPasteValue] = useState('');
  const [importError, setImportError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const hasReport = useMemo(() => report !== null, [report]);

  const loadReport = (nextReport: RepositoryScan) => {
    setReport(nextReport);
    setImportError(null);
    setPasteValue('');
  };

  const parseReport = (raw: string) => {
    try {
      const parsed = JSON.parse(raw) as RepositoryScan;
      if (!parsed || !Array.isArray(parsed.findings) || !parsed.score || !Array.isArray(parsed.modules)) {
        throw new Error('This does not look like a repo-trust-doctor JSON report.');
      }

      loadReport(parsed);
    } catch (error) {
      setImportError(error instanceof Error ? error.message : 'Could not parse the JSON report.');
    }
  };

  return (
    <main className="app-shell">
      <Header
        fileInputRef={fileInputRef}
        showActions={hasReport}
        onLoadSample={() => loadReport(sampleReport)}
      />
      <input
        ref={fileInputRef}
        className="visually-hidden"
        type="file"
        accept="application/json,.json"
        onChange={async (event) => {
          const file = event.target.files?.[0];
          if (!file) return;
          parseReport(await file.text());
          event.target.value = '';
        }}
      />

      {report ? (
        <ReportViewer report={report} />
      ) : (
        <ReportImport
          importError={importError}
          pasteValue={pasteValue}
          onLoadSample={() => loadReport(sampleReport)}
          onOpenFile={() => fileInputRef.current?.click()}
          onPasteValueChange={setPasteValue}
          onParseReport={parseReport}
        />
      )}
    </main>
  );
}

export default App;
