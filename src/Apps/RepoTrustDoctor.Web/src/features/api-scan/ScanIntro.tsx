import { ArrowRight, CheckCircle2, FileSearch, GitBranch, ShieldCheck } from 'lucide-react';

export function ScanIntro({ onTryExample, onOpenDemo }: { onTryExample: () => void; onOpenDemo: () => void }) {
  return (
    <section className="scan-intro" aria-label="Product overview">
      <div className="scan-intro-copy">
        <span className="eyebrow">Evidence-backed adoption decisions</span>
        <h2>Know whether to use, fix, or avoid a repository—before it reaches production.</h2>
        <p>
          Turn scattered security, maintenance, release, dependency, CI/CD, and code signals into one explainable recommendation.
          Review the evidence, understand coverage limits, and export a report your team can act on.
        </p>
        <div className="intro-actions">
          <button type="button" className="button hero-button" onClick={onTryExample}>
            Try with FastAPI <ArrowRight size={16} aria-hidden="true" />
          </button>
          <button type="button" className="button hero-secondary" onClick={onOpenDemo}>
            <FileSearch size={16} aria-hidden="true" /> Explore a demo report
          </button>
          <span>Public GitHub repositories · Static analysis only</span>
        </div>
      </div>
      <div className="intro-outcomes" aria-label="Review outcomes">
        <div>
          <ShieldCheck size={18} aria-hidden="true" />
          <strong>Use with confidence</strong>
          <span>See the signals that support adoption.</span>
        </div>
        <div>
          <GitBranch size={18} aria-hidden="true" />
          <strong>Fix before adopting</strong>
          <span>Focus on the few issues blocking your profile.</span>
        </div>
        <div>
          <CheckCircle2 size={18} aria-hidden="true" />
          <strong>Share the evidence</strong>
          <span>Export JSON, Markdown, or SARIF for the next step.</span>
        </div>
      </div>
    </section>
  );
}
