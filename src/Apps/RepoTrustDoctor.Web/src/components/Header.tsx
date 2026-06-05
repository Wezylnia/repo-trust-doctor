import { FileText, Upload } from 'lucide-react';
import type { RefObject } from 'react';

interface HeaderProps {
  fileInputRef: RefObject<HTMLInputElement | null>;
  showActions: boolean;
  onLoadSample: () => void;
}

export function Header({ fileInputRef, showActions, onLoadSample }: HeaderProps) {
  return (
    <header className="topbar">
      <div>
        <div className="eyebrow">repo-trust-doctor</div>
        <h1>Report viewer</h1>
      </div>
      {showActions ? (
        <div className="topbar-actions">
          <button type="button" className="button" onClick={() => fileInputRef.current?.click()}>
            <Upload size={16} aria-hidden="true" />
            Open JSON
          </button>
          <button type="button" className="button secondary" onClick={onLoadSample}>
            <FileText size={16} aria-hidden="true" />
            Sample
          </button>
        </div>
      ) : null}
    </header>
  );
}
