import type { DependencyInventoryArtifact, Finding, FindingSummary, RepositoryScan } from './report';

export const severityOrder: Record<string, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Info: 1
};

export const severities = ['All', 'Critical', 'High', 'Medium', 'Low', 'Info'];

export function scoreTone(score: number): 'excellent' | 'good' | 'warning' | 'danger' {
  if (score >= 90) return 'excellent';
  if (score >= 80) return 'good';
  if (score >= 60) return 'warning';
  return 'danger';
}

export function recommendationText(finding: Finding): string {
  return typeof finding.recommendation === 'string'
    ? finding.recommendation
    : finding.recommendation?.message ?? '';
}

const categoryLabels: Record<string, string> = {
  RepositoryHealth: 'Repository health',
  CiCd: 'CI/CD workflows',
  Security: 'Security exposure',
  Containers: 'Container hygiene',
  Dependencies: 'Dependencies',
  Releases: 'Release provenance',
  Licenses: 'License risk',
  Codebase: 'Codebase maintainability',
  Documentation: 'Documentation'
};

const decisionLabels: Record<string, string> = {
  SafeToTry: 'Safe to try',
  UseWithCaution: 'Use with caution',
  AvoidAsProductionDependency: 'Avoid as production dependency',
  NeedsManualReview: 'Needs manual review'
};

const profileLabels: Record<string, string> = {
  Personal: 'Personal project',
  ProductionDependency: 'Production dependency',
  EnterpriseDependency: 'Enterprise or security-sensitive',
  CiCdTool: 'Production dependency',
  SecuritySensitiveDependency: 'Enterprise or security-sensitive',
  ContainerDependency: 'Production dependency'
};

export interface AreaScore {
  id: string;
  label: string;
  score: number;
  description: string;
  categories: string[];
}

const areaDefinitions = [
  {
    id: 'security',
    label: 'Security exposure',
    categories: ['Security'],
    description: 'Secrets, known vulnerability signals, and security policy expectations.'
  },
  {
    id: 'repository-health',
    label: 'Repository health',
    categories: ['RepositoryHealth', 'Documentation'],
    description: 'License, ownership, contribution process, README quality, and project hygiene.'
  },
  {
    id: 'dependencies',
    label: 'Dependency and license risk',
    categories: ['Dependencies', 'Licenses'],
    description: 'Dependency inventory, version pinning, package metadata, provenance, and licenses.'
  },
  {
    id: 'automation',
    label: 'CI/CD workflow safety',
    categories: ['CiCd'],
    description: 'Workflow permissions, pinned actions, artifact handling, and build runner risk.'
  },
  {
    id: 'containers',
    label: 'Container hygiene',
    categories: ['Containers'],
    description: 'Dockerfile hardening, runtime user, health checks, and build image practices.'
  },
  {
    id: 'releases',
    label: 'Release readiness',
    categories: ['Releases'],
    description: 'Release notes, artifacts, checksums, provenance, and reproducible delivery signals.'
  },
  {
    id: 'codebase',
    label: 'Codebase maintainability',
    categories: ['Codebase'],
    description: 'Public API surface, critical paths, coverage evidence, and risky implementation patterns.'
  }
];

export function formatCategory(value: string): string {
  return categoryLabels[value] ?? splitIdentifier(value);
}

export function formatDecision(value: string): string {
  return decisionLabels[value] ?? splitIdentifier(value);
}

export function formatTrustProfile(value: string): string {
  return profileLabels[value] ?? splitIdentifier(value);
}

export function formatStatus(value: string): string {
  return splitIdentifier(value);
}

export function formatEvidenceKind(value: string): string {
  return capitalizeFirst(splitIdentifier(value.replaceAll('-', ' ')));
}

export function explainFinding(finding: Finding): string {
  if (finding.ruleId.startsWith('TRUST-VULN')) {
    return 'A dependency or package source appears to have vulnerability risk. Treat this as a signal to inspect the affected package, version, advisory status, and whether the vulnerable code path is reachable in your use case.';
  }

  if (finding.ruleId.startsWith('TRUST-SECRET')) {
    return 'The scanner found content that resembles a secret or credential. Even when this is a false positive, verify it manually because exposed credentials can require rotation and repository history cleanup.';
  }

  if (finding.ruleId.startsWith('TRUST-GHA')) {
    return 'This finding affects workflow safety. CI/CD files can run with repository tokens, publish artifacts, and access build secrets, so weak workflow configuration can become a supply-chain risk.';
  }

  if (finding.ruleId.startsWith('TRUST-DOCKER')) {
    return 'This finding affects container build or runtime hygiene. Container issues can increase image size, weaken runtime isolation, or make production behavior harder to monitor.';
  }

  if (finding.ruleId === 'TRUST-DEP050') {
    return 'A Gradle version catalog (libs.versions.toml) declares a dependency with a dynamic version such as "3.+" or "latest.release". Dynamic versions make builds non-reproducible. Pin to a specific version.';
  }

  if (finding.ruleId === 'TRUST-DEP051') {
    return 'A Gradle version catalog declares a plugin with a dynamic version. Plugin version drift can silently change build behavior. Pin to a specific plugin version.';
  }

  if (finding.ruleId.startsWith('TRUST-DEP') || finding.ruleId.startsWith('TRUST-LIC') || finding.ruleId.startsWith('TRUST-ORIGIN')) {
    return 'This finding affects dependency trust. Review package source, pinning, freshness, license, and maintainer signals before relying on this repository in another project.';
  }

  if (finding.ruleId.startsWith('TRUST-REPO')) {
    return 'This finding affects repository readiness. Missing project metadata does not always mean the code is unsafe, but it makes adoption, maintenance, support, and incident response harder to judge.';
  }

  if (finding.ruleId.startsWith('TRUST-REL')) {
    return 'This finding affects release trust. Strong release evidence helps users verify what changed, where artifacts came from, and whether downloaded files match the published source.';
  }

  if (finding.ruleId.startsWith('TRUST-WS')) {
    return 'This repository uses a monorepo workspace pattern. Workspaces are a valid choice but may require different review strategies for each project within the repository.';
  }

  if (finding.ruleId.startsWith('TRUST-GLCI')) {
    return 'This finding affects GitLab CI/CD pipeline safety. Remote includes, unpinned images, CI variable interpolation, privileged Docker-in-Docker, and broad cache paths can introduce supply-chain, injection, or isolation risks.';
  }

  if (finding.ruleId.startsWith('TRUST-AZP')) {
    return 'This finding affects Azure Pipelines security. PR-controlled variables, persisted credentials, unpinned images, self-hosted pools, and broad artifact paths can weaken pipeline isolation.';
  }

  if (finding.ruleId.startsWith('TRUST-CIRCLE')) {
    return 'This finding affects CircleCI configuration security. Unpinned orbs, unpinned Docker images, broad workspace persistence, inline secrets, and unversioned remote Docker can introduce supply-chain or isolation risks.';
  }

  if (finding.ruleId.startsWith('TRUST-COMP')) {
    if (finding.ruleId === 'TRUST-COMP006') {
      return 'The Docker socket is mounted into a service container. This grants high privilege over the host Docker daemon — a compromised container could control all containers on the host. Remove the socket mount or use an isolated builder.';
    }
    if (finding.ruleId === 'TRUST-COMP007') {
      return 'A Compose service loads environment from a .env-like file. These files often contain secrets or sensitive configuration. Review whether the file content is safe to expose inside the container.';
    }
    return 'This finding affects Docker Compose configuration. Privileged containers, host network access, Docker socket mounts, and broad port exposure can weaken container isolation.';
  }

  if (finding.ruleId.startsWith('TRUST-K8S')) {
    if (finding.ruleId === 'TRUST-K8S006') {
      return 'A workload mounts a hostPath volume, which exposes host directories to the container. This breaks container isolation. Prefer persistent volume claims or projected volumes.';
    }
    if (finding.ruleId === 'TRUST-K8S007') {
      return 'A container adds broad Linux capabilities such as SYS_ADMIN or ALL. These capabilities allow powerful system operations that increase the blast radius of a compromise.';
    }
    if (finding.ruleId === 'TRUST-K8S008') {
      return 'A container has allowPrivilegeEscalation set to true, which lets child processes gain more privileges than the parent. Set to false unless the container genuinely needs it.';
    }
    return 'This finding affects Kubernetes manifest security. Privileged pods, host namespace sharing, hostPath volumes, and broad capabilities increase the blast radius of a compromised container.';
  }

  if (finding.ruleId.startsWith('TRUST-EVI')) {
    if (finding.ruleId === 'TRUST-EVI004') {
      return 'An SBOM evidence file could not be parsed as valid JSON. Corrupt evidence cannot be trusted. Regenerate or re-export the SBOM file.';
    }
    if (finding.ruleId === 'TRUST-EVI005') {
      return 'An SBOM file is valid JSON but contains no components or packages. It provides no dependency visibility. Regenerate the SBOM from the build graph.';
    }
    if (finding.ruleId === 'TRUST-EVI006') {
      return 'A provenance or attestation file could not be parsed. Corrupt provenance cannot verify build integrity. Regenerate the provenance file from the build system.';
    }
    return 'This finding relates to supply-chain evidence. SBOMs and provenance attestations help verify what went into a build and how it was produced.';
  }

  return 'Review this finding together with its evidence and recommendation. The severity reflects expected impact, while confidence reflects how directly the scanner could prove the signal.';
}

export function buildAreaScores(report: RepositoryScan): AreaScore[] {
  const scoreByCategory = new Map(report.score.categories.map((item) => [item.category, item.score]));
  const moduleCategories = new Set(report.modules.map((module) => module.category));

  return areaDefinitions
    .map((area) => {
      const categoryScores = scoresForArea(area.categories, scoreByCategory, moduleCategories);
      if (!categoryScores.length) {
        return null;
      }

      return {
        ...area,
        score: Math.round(categoryScores.reduce((sum, score) => sum + score, 0) / categoryScores.length)
      };
    })
    .filter((area): area is AreaScore => area !== null);
}

function scoresForArea(
  categories: string[],
  scoreByCategory: Map<string, number>,
  moduleCategories: Set<string>
): number[] {
  return categories.flatMap((category) => {
    const explicitScore = scoreByCategory.get(category);
    if (explicitScore !== undefined) {
      return [explicitScore];
    }

    return moduleCategories.has(category) ? [100] : [];
  });
}

export function summarizeFindings(findings: Finding[]): FindingSummary {
  return findings.reduce(
    (summary, finding) => {
      const severity = finding.severity.toLowerCase();
      summary.total += 1;
      if (severity === 'critical') summary.critical += 1;
      if (severity === 'high') summary.high += 1;
      if (severity === 'medium') summary.medium += 1;
      if (severity === 'low') summary.low += 1;
      if (severity === 'info') summary.info += 1;
      if (finding.isBlocking) summary.blocking += 1;
      return summary;
    },
    { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, blocking: 0 }
  );
}

export function getDependencyInventory(report: RepositoryScan): DependencyInventoryArtifact | null {
  const raw = report.artifacts?.['dependency.inventory'];
  if (!raw || typeof raw !== 'object') {
    return null;
  }

  return raw as DependencyInventoryArtifact;
}

function splitIdentifier(value: string): string {
  return value
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/\bCi Cd\b/g, 'CI/CD')
    .replace(/\bApi\b/g, 'API')
    .replace(/\bUrl\b/g, 'URL')
    .replace(/\s+/g, ' ')
    .trim();
}

function capitalizeFirst(value: string): string {
  return value ? `${value[0].toUpperCase()}${value.slice(1)}` : value;
}
