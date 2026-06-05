export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info' | string;

export interface Evidence {
  kind: string;
  message: string;
  filePath?: string | null;
  lineNumber?: number | null;
  value?: string | null;
}

export interface Recommendation {
  message: string;
}

export interface Finding {
  ruleId: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: string;
  message: string;
  evidence: Evidence[];
  recommendation: Recommendation | string;
  isBlocking?: boolean;
  tags?: string[] | null;
  fingerprint?: string | null;
}

export interface ScanModule {
  moduleId: string;
  displayName: string;
  category: string;
  status: string;
  findingsCount: number;
  errorMessage?: string | null;
  skippedReason?: string | null;
}

export interface CategoryScore {
  category: string;
  score: number;
}

export interface TrustScore {
  overall: number;
  categories: CategoryScore[];
  decision: {
    kind: string;
    reasons: string[];
  };
}

export interface FindingSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  blocking: number;
}

export interface DependencyInventoryArtifact {
  manifests?: unknown[];
  lockfiles?: unknown[];
  packages?: Array<Record<string, unknown>>;
  packageSources?: Array<Record<string, unknown>>;
}

export interface RepositoryScan {
  id?: string;
  target: string;
  depth: string;
  trustProfile: string;
  toolVersion: string;
  status: string;
  startedAt?: string;
  completedAt?: string;
  modules: ScanModule[];
  findings: Finding[];
  score: TrustScore;
  summary?: FindingSummary;
  artifacts?: Record<string, unknown> | null;
}
