import { Check, Circle, LoaderCircle } from 'lucide-react';
import { formatStatus } from '../../domain/reportSelectors';
import type { ScanProgressResponse } from './apiScanClient';

const stages = [
  { state: 'PreparingRepository', label: 'Prepare repository' },
  { state: 'RunningStaticAnalyzers', label: 'Static repository checks' },
  { state: 'RunningDependencyAnalyzers', label: 'Dependencies and supply chain' },
  { state: 'RunningSecurityAnalyzers', label: 'Security and deep code review' },
  { state: 'Scoring', label: 'Score evidence' },
  { state: 'Reporting', label: 'Build recommendation' }
];

const stateRank: Record<string, number> = {
  Queued: -1,
  PreparingRepository: 0,
  RunningFastModules: 1,
  RunningStaticAnalyzers: 1,
  RunningDependencyAnalyzers: 2,
  RunningSecurityAnalyzers: 3,
  Scoring: 4,
  Reporting: 5,
  Completed: 6
};

export function ScanProgressTimeline({ progress }: { progress: ScanProgressResponse }) {
  const currentRank = stateRank[progress.state] ?? 0;
  const ratio = progress.totalModuleCount > 0
    ? Math.round((progress.completedModuleCount / progress.totalModuleCount) * 100)
    : Math.max(4, Math.round(((currentRank + 1) / stages.length) * 100));

  return (
    <section className="scan-progress" aria-live="polite" aria-label="Scan progress">
      <div className="scan-progress-heading">
        <div>
          <span>Analysis in progress</span>
          <strong>{progress.statusMessage ?? formatStatus(progress.state)}</strong>
        </div>
        <b>{Math.min(100, ratio)}%</b>
      </div>
      <div className="progress-track"><span style={{ width: `${Math.min(100, ratio)}%` }} /></div>
      <ol className="progress-stages">
        {stages.map((stage, index) => {
          const complete = currentRank > index;
          const active = currentRank === index || (progress.state === 'RunningFastModules' && index === 1);
          return (
            <li className={complete ? 'complete' : active ? 'active' : ''} key={stage.state}>
              {complete ? <Check size={14} aria-hidden="true" /> : active ? <LoaderCircle size={14} aria-hidden="true" /> : <Circle size={12} aria-hidden="true" />}
              <span>{stage.label}</span>
            </li>
          );
        })}
      </ol>
      {progress.totalModuleCount > 0 ? (
        <small>{progress.completedModuleCount} of {progress.totalModuleCount} analyzer modules complete</small>
      ) : null}
    </section>
  );
}
