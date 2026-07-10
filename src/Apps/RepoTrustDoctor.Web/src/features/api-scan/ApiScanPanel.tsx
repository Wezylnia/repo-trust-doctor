import { Download, Play, RefreshCw, Square, Wifi, WifiOff } from 'lucide-react';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import type { RepositoryScan } from '../../domain/report';
import { formatDecision, formatStatus } from '../../domain/reportSelectors';
import {
  cancelScan,
  checkHealth,
  buildGitHubRepositoryUrl,
  getScanReport,
  getScanProgress,
  getScanStatus,
  isTerminalScanState,
  normalizeGitHubRepositoryInput,
  startScan,
  type HealthResponse,
  type ScanStatusResponse
} from './apiScanClient';
import type { ScanProgressResponse } from './apiScanClient';
import { ScanProgressTimeline } from './ScanProgressTimeline';

interface ApiScanPanelProps {
  onReportLoaded: (report: RepositoryScan) => void;
  repositorySuggestion: string | null;
  onSuggestionUsed: () => void;
}

const depths = [
  { label: 'Fast scan', value: 'Fast' },
  { label: 'Standard scan', value: 'Standard' },
  { label: 'Deep scan', value: 'Deep' }
];
const profiles = [
  { label: 'Personal project', value: 'Personal' },
  { label: 'Production dependency', value: 'ProductionDependency' },
  { label: 'Enterprise or security-sensitive', value: 'SecuritySensitiveDependency' }
];

export function ApiScanPanel({ onReportLoaded, repositorySuggestion, onSuggestionUsed }: ApiScanPanelProps) {
  const apiBaseUrl = 'http://localhost:5000';
  const [repository, setRepository] = useState('');
  const [depth, setDepth] = useState('Standard');
  const [trustProfile, setTrustProfile] = useState('ProductionDependency');
  const [scanId, setScanId] = useState<string | null>(null);
  const [status, setStatus] = useState<ScanStatusResponse | null>(null);
  const [progress, setProgress] = useState<ScanProgressResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const pollTimer = useRef<number | null>(null);

  const lastRequest = useRef<{ repository: string; depth: string; trustProfile: string } | null>(null);

  const canCancel = scanId !== null && status !== null && !isTerminalScanState(status.state);
  const isTerminal = status !== null && isTerminalScanState(status.state);
  const canRetry = isTerminal && lastRequest.current !== null;

  useEffect(() => {
    return () => {
      if (pollTimer.current !== null) {
        window.clearTimeout(pollTimer.current);
      }
    };
  }, []);

  const refreshHealth = async () => {
    try {
      const h = await checkHealth(apiBaseUrl);
      setHealth(h);
      setHealthError(null);
    } catch {
      setHealth(null);
      setHealthError(`API is unreachable at ${apiBaseUrl}. Ensure the backend is running.`);
    }
  };

  useEffect(() => {
    void refreshHealth();
  }, []);

  useEffect(() => {
    if (repositorySuggestion) {
      setRepository(repositorySuggestion);
      onSuggestionUsed();
    }
  }, [repositorySuggestion, onSuggestionUsed]);

  const pollScan = async (nextScanId: string) => {
    try {
      const [nextStatus, nextProgress] = await Promise.all([
        getScanStatus(apiBaseUrl, nextScanId),
        getScanProgress(apiBaseUrl, nextScanId)
      ]);
      setStatus(nextStatus);
      setProgress(nextProgress);

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

  const startSubmittedScan = async (request: { repository: string; depth: string; trustProfile: string }) => {
    setIsSubmitting(true);
    setError(null);
    setStatus(null);
    setProgress(null);
    setScanId(null);

    if (pollTimer.current !== null) {
      window.clearTimeout(pollTimer.current);
      pollTimer.current = null;
    }

    lastRequest.current = request;

    try {
      const target = buildGitHubRepositoryUrl(request.repository);
      const started = await startScan({ apiBaseUrl, ...request });
      setScanId(started.scanId);
      setStatus({
        scanId: started.scanId,
        target,
        depth: request.depth,
        trustProfile: request.trustProfile,
        state: started.status
      });
      await pollScan(started.scanId);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : 'Scan request failed.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const submitScan = async (event: FormEvent) => {
    event.preventDefault();
    await startSubmittedScan({ repository, depth, trustProfile });
  };

  const retryScan = async () => {
    if (!lastRequest.current) return;
    const request = lastRequest.current;
    setRepository(request.repository);
    setDepth(request.depth);
    setTrustProfile(request.trustProfile);
    await startSubmittedScan(request);
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
          <h2>Get an adoption recommendation</h2>
          <span>Choose how you plan to use the repository; we will apply the matching policy.</span>
        </div>
        <div className="panel-heading-right">
          {health ? (
            <span className="health-indicator connected" title={`${health.product} API is ready`}>
              <Wifi size={14} aria-hidden="true" /> Local API ready
            </span>
          ) : healthError ? (
            <span className="health-indicator disconnected" title={healthError}>
              <WifiOff size={14} aria-hidden="true" /> Offline
            </span>
          ) : null}
          {status ? <span className={`state-token ${status.state.toLowerCase()}`}>{formatStatus(status.state)}</span> : null}
        </div>
      </div>

      {healthError ? (
        <div className="error-message api-offline">
          <p>{healthError}</p>
          <button type="button" className="button" onClick={() => void refreshHealth()}>
            <RefreshCw size={14} aria-hidden="true" /> Retry
          </button>
        </div>
      ) : null}

      <form className="scan-form" onSubmit={(event) => void submitScan(event)}>
        <label>
          <span>Repository to review</span>
          <div className="github-input">
            <span>github.com/</span>
            <input
              value={repository}
              onChange={(event) => setRepository(normalizeGitHubRepositoryInput(event.target.value))}
              placeholder="owner/repo"
              disabled={isSubmitting}
            />
          </div>
        </label>
        <div className="field-grid">
          <label>
            <span>Evidence depth</span>
            <select value={depth} onChange={(event) => setDepth(event.target.value)} disabled={isSubmitting}>
              {depths.map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>How will you use it?</span>
            <select value={trustProfile} onChange={(event) => setTrustProfile(event.target.value)} disabled={isSubmitting}>
              {profiles.map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="scan-actions">
          {!canRetry ? (
            <>
              <button type="submit" className="button" disabled={isSubmitting || !repository.trim() || healthError !== null}>
                {isSubmitting ? <RefreshCw size={16} aria-hidden="true" /> : <Play size={16} aria-hidden="true" />}
                Start scan
              </button>
              <button type="button" className="button secondary" disabled={!canCancel} onClick={() => void requestCancel()}>
                <Square size={16} aria-hidden="true" />
                Cancel
              </button>
            </>
          ) : (
            <button type="button" className="button" onClick={() => void retryScan()}>
              <RefreshCw size={16} aria-hidden="true" /> Scan again
            </button>
          )}
        </div>
        <p className="scan-safety-note">The scanner reads repository files and safe metadata only; it does not execute repository code.</p>
      </form>

      {status ? (
        <>
          {progress && !isTerminal ? <ScanProgressTimeline progress={progress} /> : null}
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
              <dt>Recommendation</dt>
              <dd>{status.decision ? formatDecision(status.decision) : 'Pending'}</dd>
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

          {isTerminal && status.reportJsonUrl && status.reportMarkdownUrl && status.reportSarifUrl ? (
            <div className="export-actions">
              <span className="export-label">Download report:</span>
              <a href={`${apiBaseUrl}${status.reportJsonUrl}`} className="button secondary" download>
                <Download size={14} aria-hidden="true" /> JSON
              </a>
              <a href={`${apiBaseUrl}${status.reportMarkdownUrl}`} className="button secondary" download>
                <Download size={14} aria-hidden="true" /> Markdown
              </a>
              <a href={`${apiBaseUrl}${status.reportSarifUrl}`} className="button secondary" download>
                <Download size={14} aria-hidden="true" /> SARIF
              </a>
            </div>
          ) : null}
        </>
      ) : null}

      {error ? <div className="error-message">{error}</div> : null}
    </section>
  );
}
