import { Play, RefreshCw, Square } from 'lucide-react';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import type { RepositoryScan } from '../../domain/report';
import {
  cancelScan,
  getScanReport,
  getScanStatus,
  isTerminalScanState,
  startScan,
  type ScanStatusResponse
} from './apiScanClient';

interface ApiScanPanelProps {
  onReportLoaded: (report: RepositoryScan) => void;
}

const depths = ['Fast', 'Standard', 'Deep'];
const profiles = [
  'Personal',
  'ProductionDependency',
  'EnterpriseDependency',
  'CiCdTool',
  'SecuritySensitiveDependency',
  'ContainerDependency'
];

export function ApiScanPanel({ onReportLoaded }: ApiScanPanelProps) {
  const [apiBaseUrl, setApiBaseUrl] = useState('http://localhost:5000');
  const [target, setTarget] = useState('.');
  const [depth, setDepth] = useState('Fast');
  const [trustProfile, setTrustProfile] = useState('ProductionDependency');
  const [scanId, setScanId] = useState<string | null>(null);
  const [status, setStatus] = useState<ScanStatusResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const pollTimer = useRef<number | null>(null);

  const canCancel = scanId !== null && status !== null && !isTerminalScanState(status.state);

  useEffect(() => {
    return () => {
      if (pollTimer.current !== null) {
        window.clearTimeout(pollTimer.current);
      }
    };
  }, []);

  const pollScan = async (nextScanId: string) => {
    try {
      const nextStatus = await getScanStatus(apiBaseUrl, nextScanId);
      setStatus(nextStatus);

      if (nextStatus.state === 'Completed') {
        const report = await getScanReport(apiBaseUrl, nextScanId);
        onReportLoaded(report);
        return;
      }

      if (!isTerminalScanState(nextStatus.state)) {
        pollTimer.current = window.setTimeout(() => void pollScan(nextScanId), 1000);
      }
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : 'Scan polling failed.');
    }
  };

  const submitScan = async (event: FormEvent) => {
    event.preventDefault();
    setIsSubmitting(true);
    setError(null);
    setStatus(null);
    setScanId(null);

    try {
      const started = await startScan({ apiBaseUrl, target, depth, trustProfile });
      setScanId(started.scanId);
      setStatus({
        scanId: started.scanId,
        target,
        depth,
        trustProfile,
        state: started.status
      });
      await pollScan(started.scanId);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : 'Scan request failed.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const requestCancel = async () => {
    if (!scanId) return;
    setError(null);
    try {
      await cancelScan(apiBaseUrl, scanId);
      const nextStatus = await getScanStatus(apiBaseUrl, scanId);
      setStatus(nextStatus);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : 'Cancel request failed.');
    }
  };

  return (
    <section className="api-scan-panel" aria-label="API scan">
      <div className="panel-heading">
        <div>
          <h2>Scan repository</h2>
          <span>Local backend scan</span>
        </div>
        {status ? <span className={`state-token ${status.state.toLowerCase()}`}>{status.state}</span> : null}
      </div>

      <form className="scan-form" onSubmit={(event) => void submitScan(event)}>
        <label>
          <span>Target</span>
          <input
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="C:\\path\\repo or https://github.com/owner/repo"
          />
        </label>
        <div className="field-grid">
          <label>
            <span>Depth</span>
            <select value={depth} onChange={(event) => setDepth(event.target.value)}>
              {depths.map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>Profile</span>
            <select value={trustProfile} onChange={(event) => setTrustProfile(event.target.value)}>
              {profiles.map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
          </label>
        </div>
        <label>
          <span>Backend</span>
          <input value={apiBaseUrl} onChange={(event) => setApiBaseUrl(event.target.value)} />
        </label>

        <div className="scan-actions">
          <button type="submit" className="button" disabled={isSubmitting || !target.trim() || !apiBaseUrl.trim()}>
            {isSubmitting ? <RefreshCw size={16} aria-hidden="true" /> : <Play size={16} aria-hidden="true" />}
            Start scan
          </button>
          <button type="button" className="button secondary" disabled={!canCancel} onClick={() => void requestCancel()}>
            <Square size={16} aria-hidden="true" />
            Cancel
          </button>
        </div>
      </form>

      {status ? (
        <dl className="scan-status-grid">
          <div>
            <dt>Scan ID</dt>
            <dd>{status.scanId}</dd>
          </div>
          <div>
            <dt>Score</dt>
            <dd>{status.overallScore ?? 'Pending'}</dd>
          </div>
          <div>
            <dt>Modules</dt>
            <dd>{status.moduleCount ?? 'Pending'}</dd>
          </div>
          <div>
            <dt>Findings</dt>
            <dd>{status.findingCount ?? 'Pending'}</dd>
          </div>
        </dl>
      ) : null}

      {error ? <div className="error-message">{error}</div> : null}
    </section>
  );
}
