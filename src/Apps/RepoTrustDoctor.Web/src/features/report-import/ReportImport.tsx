import { Clipboard, FileJson, FileText, Upload } from 'lucide-react';

interface ReportImportProps {
  importError: string | null;
  pasteValue: string;
  onLoadSample: () => void;
  onOpenFile: () => void;
  onPasteValueChange: (value: string) => void;
  onParseReport: (raw: string) => void;
}

export function ReportImport({
  importError,
  pasteValue,
  onLoadSample,
  onOpenFile,
  onPasteValueChange,
  onParseReport
}: ReportImportProps) {
  return (
    <section className="import-layout">
      <div className="import-panel">
        <FileJson size={24} aria-hidden="true" />
        <h2>Saved report</h2>
        <div className="import-actions">
          <button type="button" className="button" onClick={onOpenFile}>
            <Upload size={16} aria-hidden="true" />
            Open file
          </button>
          <button type="button" className="button secondary" onClick={onLoadSample}>
            <FileText size={16} aria-hidden="true" />
            Load sample
          </button>
        </div>
      </div>
      <form
        className="paste-panel"
        onSubmit={(event) => {
          event.preventDefault();
          onParseReport(pasteValue);
        }}
      >
        <label htmlFor="paste-report">Paste saved JSON</label>
        <textarea
          id="paste-report"
          value={pasteValue}
          onChange={(event) => onPasteValueChange(event.target.value)}
          spellCheck={false}
        />
        {importError ? <div className="error-message">{importError}</div> : null}
        <button type="submit" className="button" disabled={!pasteValue.trim()}>
          <Clipboard size={16} aria-hidden="true" />
          Open saved report
        </button>
      </form>
    </section>
  );
}
