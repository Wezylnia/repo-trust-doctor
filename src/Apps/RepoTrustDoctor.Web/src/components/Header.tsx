import { FileText, FolderOpen, Radar, Upload } from 'lucide-react';
import type { RefObject } from 'react';

interface HeaderProps {
  fileInputRef: RefObject<HTMLInputElement | null>;
  showActions: boolean;
  mode: 'report' | 'import' | 'scan';
  onLoadSample: () => void;
  onOpenImport: () => void;
  onOpenReport: () => void;
  onOpenScan: () => void;
}

export function Header({
  fileInputRef,
  showActions,
  mode,
  onLoadSample,
  onOpenImport,
  onOpenReport,
  onOpenScan
}: HeaderProps) {
  return (
    <header className="topbar">
      <div>
        <div className="eyebrow">repo-trust-doctor</div>
        <h1>Trust workbench</h1>
      </div>
      <div className="topbar-actions">
        <button
          type="button"
          className={`button quiet ${mode === 'scan' ? 'active' : ''}`}
          onClick={onOpenScan}
        >
          <Radar size={16} aria-hidden="true" />
          Scan
        </button>
        <button
          type="button"
          className={`button quiet ${mode === 'report' ? 'active' : ''}`}
          onClick={onOpenReport}
          disabled={!showActions}
        >
          <FileText size={16} aria-hidden="true" />
          Report
        </button>
        <button
          type="button"
          className={`button quiet ${mode === 'import' ? 'active' : ''}`}
          onClick={onOpenImport}
        >
          <FolderOpen size={16} aria-hidden="true" />
          Saved report
        </button>
        {showActions ? (
          <>
          <button type="button" className="button" onClick={() => fileInputRef.current?.click()}>
            <Upload size={16} aria-hidden="true" />
            Open saved
          </button>
          <button type="button" className="button secondary" onClick={onLoadSample}>
            <FileText size={16} aria-hidden="true" />
            Sample
          </button>
          </>
        ) : null}
      </div>
    </header>
  );
}
