import type { RepositoryScan } from './report';

export const demoReport: RepositoryScan = {
  id: 'demo-report',
  target: 'https://github.com/example/production-service',
  depth: 'Standard',
  trustProfile: 'ProductionDependency',
  toolVersion: 'demo',
  status: 'CompletedWithWarnings',
  startedAt: '2026-07-10T10:00:00Z',
  completedAt: '2026-07-10T10:00:04Z',
  modules: [
    { moduleId: 'repository-health', displayName: 'Repository Health', category: 'RepositoryHealth', status: 'Completed', findingsCount: 1 },
    { moduleId: 'github-actions-basic', displayName: 'GitHub Actions Security', category: 'CiCd', status: 'Completed', findingsCount: 1 },
    { moduleId: 'secret-quick-scan', displayName: 'Secret Quick Scan', category: 'Security', status: 'Completed', findingsCount: 0 },
    { moduleId: 'dependency-inventory', displayName: 'Dependency Inventory', category: 'Dependencies', status: 'Completed', findingsCount: 0 },
    { moduleId: 'dependency-vulnerabilities', displayName: 'Dependency Vulnerabilities', category: 'Dependencies', status: 'CompletedWithWarnings', findingsCount: 1, warnings: ['One package could not be resolved to an exact version.'] },
    { moduleId: 'docker-basic', displayName: 'Docker Security', category: 'Containers', status: 'Completed', findingsCount: 1 },
    { moduleId: 'release-evidence', displayName: 'Release Evidence', category: 'Releases', status: 'Completed', findingsCount: 1 }
  ],
  findings: [
    {
      ruleId: 'TRUST-VULN001', title: 'Direct dependency has a known vulnerability', category: 'Dependencies', severity: 'High', confidence: 'High',
      message: 'A direct production dependency matches a high-severity advisory.',
      evidence: [{ kind: 'vulnerability-advisory', message: 'The resolved package version is affected by a published advisory.', filePath: 'package-lock.json', lineNumber: 184 }],
      recommendation: { message: 'Upgrade the dependency to a fixed version before production adoption.' }, isBlocking: false, fingerprint: 'demo-vulnerability'
    },
    {
      ruleId: 'TRUST-GHA005', title: 'Workflow action is not pinned to a commit', category: 'CiCd', severity: 'Medium', confidence: 'High',
      message: 'A workflow action uses a mutable version tag.',
      evidence: [{ kind: 'workflow-action', message: 'actions/setup-node is referenced by tag.', filePath: '.github/workflows/ci.yml', lineNumber: 18 }],
      recommendation: { message: 'Pin third-party actions to a full commit SHA.' }, fingerprint: 'demo-workflow'
    },
    {
      ruleId: 'TRUST-DOCKER004', title: 'Container runs as root', category: 'Containers', severity: 'Medium', confidence: 'Medium',
      message: 'No non-root USER instruction was observed.',
      evidence: [{ kind: 'dockerfile', message: 'The final image does not select a non-root user.', filePath: 'Dockerfile' }],
      recommendation: { message: 'Create and select a dedicated non-root runtime user.' }, fingerprint: 'demo-docker'
    },
    {
      ruleId: 'TRUST-REPO003', title: 'Security policy is missing', category: 'RepositoryHealth', severity: 'Low', confidence: 'High',
      message: 'SECURITY.md was not found.', evidence: [{ kind: 'file-missing', message: 'SECURITY.md was not found.' }],
      recommendation: { message: 'Add vulnerability reporting instructions and supported versions.' }, fingerprint: 'demo-security-policy'
    },
    {
      ruleId: 'TRUST-REL003', title: 'Release artifacts lack provenance', category: 'Releases', severity: 'Low', confidence: 'Medium',
      message: 'No SBOM or provenance evidence was observed for release artifacts.',
      evidence: [{ kind: 'release-evidence', message: 'No SBOM or provenance file was found.' }],
      recommendation: { message: 'Publish an SBOM and signed provenance with releases.' }, fingerprint: 'demo-release'
    }
  ],
  score: {
    overall: 72,
    categories: [
      { category: 'Security', score: 100 }, { category: 'RepositoryHealth', score: 88 },
      { category: 'Dependencies', score: 58 }, { category: 'Licenses', score: 92 },
      { category: 'CiCd', score: 68 }, { category: 'Containers', score: 74 },
      { category: 'Releases', score: 82 }
    ],
    decision: {
      kind: 'UseWithCaution',
      reasons: [
        'POLICY-VULN: A high-severity direct dependency vulnerability requires remediation.',
        'POLICY-GHA-PINNING: A workflow action is not pinned to an immutable commit.',
        'POLICY-SECURITY-MD: The selected policy requires SECURITY.md.'
      ]
    }
  }
};
