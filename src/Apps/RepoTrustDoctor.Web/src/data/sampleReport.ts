import type { RepositoryScan } from '../domain/report';

export const sampleReport: RepositoryScan = {
  id: '4a9b3f1c-c841-4cb3-a2a5-b4b91a0f4b52',
  target: 'https://github.com/example/service',
  depth: 'Standard',
  trustProfile: 'ProductionDependency',
  toolVersion: '0.4.0',
  status: 'Completed',
  startedAt: '2026-06-05T09:15:00Z',
  completedAt: '2026-06-05T09:15:12Z',
  modules: [
    {
      moduleId: 'repository-health',
      displayName: 'Repository Health',
      category: 'RepositoryHealth',
      status: 'Completed',
      findingsCount: 1
    },
    {
      moduleId: 'github-actions-basic',
      displayName: 'GitHub Actions',
      category: 'CiCd',
      status: 'Completed',
      findingsCount: 2
    },
    {
      moduleId: 'dependency-inventory',
      displayName: 'Dependency Inventory',
      category: 'Dependencies',
      status: 'Completed',
      findingsCount: 1
    }
  ],
  findings: [
    {
      ruleId: 'TRUST-GHA002',
      title: 'Workflow uses permissions: write-all',
      category: 'CiCd',
      severity: 'High',
      confidence: 'High',
      message: 'A workflow grants write-all permissions.',
      evidence: [
        {
          kind: 'Workflow',
          message: 'permissions: write-all was found.',
          filePath: '.github/workflows/release.yml',
          lineNumber: 14
        }
      ],
      recommendation: {
        message: 'Replace write-all with the narrowest permissions required by each job.'
      },
      isBlocking: false,
      tags: ['github-actions', 'permissions'],
      fingerprint: 'sample-gha002'
    },
    {
      ruleId: 'TRUST-GHA005',
      title: 'Third-party action is not pinned by SHA',
      category: 'CiCd',
      severity: 'Medium',
      confidence: 'High',
      message: 'A third-party GitHub Action is referenced by a mutable tag.',
      evidence: [
        {
          kind: 'Workflow',
          message: 'Action vendor/action@v1 is not pinned to a full commit SHA.',
          filePath: '.github/workflows/ci.yml',
          lineNumber: 22
        }
      ],
      recommendation: {
        message: 'Pin third-party GitHub Actions to a full commit SHA.'
      },
      isBlocking: false,
      tags: ['github-actions', 'supply-chain'],
      fingerprint: 'sample-gha005'
    },
    {
      ruleId: 'TRUST-DEP004',
      title: 'Dependency uses a ranged version',
      category: 'Dependencies',
      severity: 'Medium',
      confidence: 'High',
      message: 'A package reference allows version drift.',
      evidence: [
        {
          kind: 'Manifest',
          message: 'Package Floating.Package uses version [1.0.0,2.0.0).',
          filePath: 'src/App/App.csproj',
          lineNumber: 18
        }
      ],
      recommendation: {
        message: 'Prefer pinned dependency versions for production dependency review.'
      },
      isBlocking: false,
      tags: ['dependencies'],
      fingerprint: 'sample-dep004'
    },
    {
      ruleId: 'TRUST-REPO010',
      title: 'SECURITY.md is missing',
      category: 'RepositoryHealth',
      severity: 'Info',
      confidence: 'High',
      message: 'The repository does not document security reporting expectations.',
      evidence: [
        {
          kind: 'File',
          message: 'No SECURITY.md file was found at repository root.'
        }
      ],
      recommendation: {
        message: 'Add a SECURITY.md file with supported versions and private reporting instructions.'
      },
      isBlocking: false,
      tags: ['documentation'],
      fingerprint: 'sample-repo010'
    }
  ],
  score: {
    overall: 72,
    categories: [
      { category: 'CiCd', score: 58 },
      { category: 'Dependencies', score: 76 },
      { category: 'RepositoryHealth', score: 92 }
    ],
    decision: {
      kind: 'UseWithCaution',
      reasons: ['High severity CI/CD findings require review before production use.']
    }
  },
  summary: {
    total: 4,
    critical: 0,
    high: 1,
    medium: 2,
    low: 0,
    info: 1,
    blocking: 0
  },
  artifacts: {
    'dependency.inventory': {
      manifests: [{ path: 'src/App/App.csproj' }],
      lockfiles: [],
      packages: [{ name: 'Floating.Package', ecosystem: 'NuGet', isVersionPinned: false }],
      packageSources: []
    }
  }
};
