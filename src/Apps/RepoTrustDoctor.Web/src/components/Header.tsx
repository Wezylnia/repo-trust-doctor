import { FileText, Radar } from 'lucide-react';

interface HeaderProps {
  hasReport: boolean;
  mode: 'report' | 'scan';
  onOpenReport: () => void;
  onOpenScan: () => void;
}

export function Header({
  hasReport,
  mode,
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
          disabled={!hasReport}
        >
          <FileText size={16} aria-hidden="true" />
          Report
        </button>
      </div>
    </header>
  );
}
