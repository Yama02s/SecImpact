export type Exposure = "internet" | "dmz" | "internal";

export type AssetType =
  | "webApp"
  | "database"
  | "server"
  | "activeDirectory"
  | "network"
  | "cloud"
  | "workstation";

export type FindingStatus = "open" | "mitigated" | "accepted";

export type RiskLevel = "low" | "medium" | "high" | "critical";

export type GrcFramework = "iso27001" | "nistCsf" | "cisControls" | "owaspTop10";

export interface RiskOverride {
  impact: number;
  likelihood: number;
  note: string;
  customGrcControl?: string;
}

export interface CveEnrichment {
  cveId: string;
  found: boolean;
  title: string;
  description: string;
  cvss: number;
  epss: number;
  inKev: boolean;
  cwe: string;
}

export interface NmapImportResult {
  assets: Asset[];
  findings: Finding[];
  hostsParsed: number;
  openPortsTotal: number;
  cvesFound: number;
}

export interface AuditConfig {
  matrixSize: 3 | 4 | 5;
  framework: GrcFramework;
}

export interface Asset {
  id: string;
  name: string;
  host: string;
  assetType: AssetType;
  exposure: Exposure;
  criticality: number; // 1..5
  owner: string;
}

export interface Finding {
  id: string;
  cveId: string;
  title: string;
  description: string;
  cvss: number; // 0..10
  epss: number; // 0..100
  inKev: boolean;
  status: FindingStatus;
  assetIds: string[];
  remediation: string;
  cwe?: string;
}

export interface AuditProject {
  name: string;
  client: string;
  auditor: string;
  date: string;
  config: AuditConfig;
  assets: Asset[];
  findings: Finding[];
  overrides: Record<string, RiskOverride>;
  plannedRemediationIds: string[];
}

export interface RiskItem {
  id: string;
  findingId: string;
  cveId: string;
  title: string;
  assetId: string;
  assetName: string;
  assetHost: string;
  assetType: AssetType;
  exposure: Exposure;
  assetCriticality: number;
  cvss: number;
  epss: number;
  inKev: boolean;
  status: FindingStatus;
  suggestedImpact: number;
  suggestedLikelihood: number;
  suggestionReason: string;
  impact: number;
  likelihood: number;
  isCalibrated: boolean;
  auditorNote: string;
  riskScore: number;
  maxScore: number;
  riskLevel: RiskLevel;
  slaWindow: string;
  grcControl: string;
  remediation: string;
  inRemediationPlan: boolean;
}

export interface MatrixCell {
  impact: number;
  likelihood: number;
  score: number;
  level: RiskLevel;
  count: number;
  itemIds: string[];
}

export interface MatrixSummary {
  matrixSize: number;
  maxScore: number;
  totalAssets: number;
  totalFindings: number;
  openRiskPairs: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  kevCount: number;
  calibratedCount: number;
  currentAvgScore: number;
  residualOpenPairs: number;
  residualCriticalCount: number;
  residualHighCount: number;
  residualAvgScore: number;
  riskReductionPct: number;
}

export interface MatrixReport {
  summary: MatrixSummary;
  cells: MatrixCell[];
  items: RiskItem[];
}
