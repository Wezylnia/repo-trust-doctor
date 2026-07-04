import { Activity, GitBranch, ShieldCheck } from 'lucide-react';

export function ScanIntro() {
  return (
    <section className="scan-intro" aria-label="Product overview">
      <div>
        <span className="eyebrow">Repository trust review</span>
        <h2>Evaluate a GitHub repository before you depend on it.</h2>
        <p>
          Repo Trust Doctor reviews public repository signals that are easy to miss during adoption:
          security posture, dependency risk, release evidence, project maintenance, CI/CD safety, infrastructure as code,
          containers, and static code intelligence.
        </p>
      </div>
      <div className="intro-points" aria-label="Review focus areas">
        <div>
          <ShieldCheck size={18} aria-hidden="true" />
          <span>Security and supply-chain risk</span>
        </div>
        <div>
          <Activity size={18} aria-hidden="true" />
          <span>Maintenance and project readiness</span>
        </div>
        <div>
          <GitBranch size={18} aria-hidden="true" />
          <span>Release, automation, infrastructure, and code signals</span>
        </div>
      </div>
    </section>
  );
}
