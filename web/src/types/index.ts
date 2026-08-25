/**
 * SENTINELTRACE domain model.
 *
 * Every service (real backend or mock) normalises into these shapes, so no UI
 * component ever touches a raw FastAPI payload. Backend-shaped types live in
 * `services/adapters.ts` and are converted here at the boundary.
 */

/* ------------------------------------------------------------------ */
/* Shared primitives                                                   */
/* ------------------------------------------------------------------ */

export const SEVERITIES = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Verdict taxonomy shown on the analyzer result card. */
export const CLASSIFICATIONS = [
  'LEGITIMATE',
  'SUSPICIOUS',
  'PHISHING',
  'IMPERSONATION',
  'FRAUD',
  'MALWARE',
  'BUSINESS_EMAIL_COMPROMISE',
] as const;
export type Classification = (typeof CLASSIFICATIONS)[number];

export type AuthVerdict = 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NEUTRAL' | 'NONE' | 'ERROR';

/** How much weight an investigator should give a relay hop. */
export type HopTrust = 'TRUSTED' | 'SUSPICIOUS' | 'UNKNOWN';

export type IocType =
  | 'IP'
  | 'DOMAIN'
  | 'URL'
  | 'EMAIL'
  | 'HASH'
  | 'ATTACHMENT'
  | 'MESSAGE_ID';

export type Reputation = 'CLEAN' | 'UNKNOWN' | 'SUSPICIOUS' | 'MALICIOUS';

export type Role = 'ADMIN' | 'SOC_ANALYST' | 'INVESTIGATOR' | 'AUDITOR';

/** Which data source answered a request — surfaced in the UI, never hidden. */
export type DataOrigin = 'LIVE_BACKEND' | 'SIMULATED';

/* ------------------------------------------------------------------ */
/* Session & access control                                            */
/* ------------------------------------------------------------------ */

export interface Session {
  analystId: string;
  displayName: string;
  email: string;
  role: Role;
  unit: string;
  signedInAt: string;
  demo: boolean;
}

/** Capability keys gate navigation and destructive actions per role. */
export type Capability =
  | 'analyze:email'
  | 'view:forensics'
  | 'view:intel'
  | 'manage:cases'
  | 'manage:alerts'
  | 'export:report'
  | 'view:audit'
  | 'manage:settings';

/* ------------------------------------------------------------------ */
/* Service health                                                      */
/* ------------------------------------------------------------------ */

export type ServiceState = 'ONLINE' | 'DEGRADED' | 'OFFLINE' | 'CHECKING';

export interface ServiceStatus {
  id: 'ai_engine' | 'threat_intel' | 'geolocation' | 'forensic_engine';
  label: string;
  state: ServiceState;
  detail: string;
  latencyMs: number | null;
}

/* ------------------------------------------------------------------ */
/* Threat scoring                                                      */
/* ------------------------------------------------------------------ */

/** One weighted contributor to the composite threat score. */
export interface ScoreComponent {
  id:
    | 'phishing'
    | 'spoofing'
    | 'domain_risk'
    | 'ip_reputation'
    | 'header_anomaly'
    | 'social_engineering'
    | 'attachment_risk'
    | 'url_risk';
  label: string;
  /** 0–100 probability/risk for this dimension. */
  value: number;
  /** Relative contribution to the composite score, 0–1. */
  weight: number;
  summary: string;
}

export interface ThreatScore {
  /** Composite 0–100. Higher is more dangerous. */
  total: number;
  level: Severity;
  components: ScoreComponent[];
}

/* ------------------------------------------------------------------ */
/* Email headers & authentication                                      */
/* ------------------------------------------------------------------ */

export interface HeaderField {
  name: string;
  value: string;
  /** Set when the field itself is evidence of tampering or mismatch. */
  anomaly?: {
    severity: Severity;
    reason: string;
  };
}

export interface AuthenticationCheck {
  mechanism: 'SPF' | 'DKIM' | 'DMARC';
  verdict: AuthVerdict;
  /** Whether the authenticated identifier aligns with the visible From domain. */
  aligned: boolean | null;
  detail: string;
  /** Raw record or signature fragment, shown in a mono block. */
  raw?: string;
}

export interface AuthenticationSummary {
  senderDomain: string;
  checks: AuthenticationCheck[];
  /** 0–100 — how much the receiving infrastructure should trust this sender. */
  trustScore: number;
  alignmentNote: string;
}

/* ------------------------------------------------------------------ */
/* SMTP relay reconstruction                                           */
/* ------------------------------------------------------------------ */

export interface GeoPoint {
  country: string;
  countryCode: string;
  city: string | null;
  region: string | null;
  latitude: number;
  longitude: number;
}

export interface RelayHop {
  /** 1 = closest to the original sender. */
  index: number;
  ip: string | null;
  hostname: string | null;
  geo: GeoPoint | null;
  isp: string | null;
  asn: string | null;
  timestamp: string | null;
  trust: HopTrust;
  reputation: Reputation;
  /** 0–100 confidence that this hop's attributes were resolved correctly. */
  confidence: number;
  notes: string[];
  /** Verbatim Received: header this hop was parsed from. */
  raw: string;
  /** True for the recipient-side infrastructure at the end of the chain. */
  isDestination?: boolean;
}

/**
 * Origin assessment. Deliberately phrased as an investigative lead: this
 * describes *infrastructure*, never a person.
 */
export interface OriginAssessment {
  earliestReliableHopIndex: number | null;
  observedSourceIp: string | null;
  estimatedLocation: GeoPoint | null;
  isp: string | null;
  asn: string | null;
  proxyOrVpnIndicator: 'DETECTED' | 'NOT_DETECTED' | 'INCONCLUSIVE';
  torIndicator: 'DETECTED' | 'NOT_DETECTED' | 'INCONCLUSIVE';
  hostingType: 'DATACENTER' | 'RESIDENTIAL' | 'MOBILE' | 'UNKNOWN';
  /** 0–100 confidence in the estimate above. */
  confidence: number;
  /** Plain-language caveats that must be shown alongside the estimate. */
  caveats: string[];
}

/* ------------------------------------------------------------------ */
/* Infrastructure intelligence                                         */
/* ------------------------------------------------------------------ */

export interface DomainIntelligence {
  domain: string;
  registrar: string | null;
  createdAt: string | null;
  /** Age in days at time of analysis; null when registration data is absent. */
  ageDays: number | null;
  nameservers: string[];
  mxRecords: { host: string; priority: number; suspicious: boolean }[];
  spfRecord: string | null;
  dmarcRecord: string | null;
  reputation: Reputation;
  risk: Severity;
  /** Lookalike analysis against a legitimate brand domain. */
  similarity?: {
    comparedTo: string;
    score: number;
    technique: string;
  };
  blacklists: { source: string; listed: boolean }[];
  notes: string[];
}

export interface IpIntelligence {
  ip: string;
  hostname: string | null;
  geo: GeoPoint | null;
  isp: string | null;
  organization: string | null;
  asn: string | null;
  asnOwner: string | null;
  reputation: Reputation;
  risk: Severity;
  hostingType: 'DATACENTER' | 'RESIDENTIAL' | 'MOBILE' | 'UNKNOWN';
  blacklists: { source: string; listed: boolean }[];
  firstSeen: string | null;
  lastSeen: string | null;
  associatedDomains: string[];
  notes: string[];
}

/* ------------------------------------------------------------------ */
/* Indicators of compromise                                            */
/* ------------------------------------------------------------------ */

export interface Ioc {
  id: string;
  type: IocType;
  value: string;
  risk: Severity;
  reputation: Reputation;
  /** Where in the message this indicator was observed. */
  source: string;
  relatedIncidents: string[];
  firstSeen: string | null;
}

/* ------------------------------------------------------------------ */
/* AI assessment                                                       */
/* ------------------------------------------------------------------ */

export interface Finding {
  id: string;
  label: string;
  severity: Severity;
  /** Which evidence supports this finding — cited back to the raw email. */
  evidence: string;
  /** Model contribution to the verdict, 0–1. */
  contribution: number;
}

export type RecommendedActionKind =
  | 'QUARANTINE_EMAIL'
  | 'BLOCK_DOMAIN'
  | 'BLOCK_IP'
  | 'INVESTIGATE_RELATED'
  | 'CREATE_INCIDENT'
  | 'EXPORT_REPORT'
  | 'NOTIFY_RECIPIENT'
  | 'NO_ACTION';

export interface RecommendedAction {
  kind: RecommendedActionKind;
  label: string;
  rationale: string;
  priority: Severity;
}

export interface AiAssessment {
  classification: Classification;
  /** 0–100. */
  confidence: number;
  /** Two or three sentences an analyst can paste into a ticket. */
  narrative: string;
  findings: Finding[];
  recommendedActions: RecommendedAction[];
  modelVersion: string;
  /** Named techniques the model matched, for analyst credibility. */
  techniques: string[];
}

/* ------------------------------------------------------------------ */
/* The analysis aggregate                                              */
/* ------------------------------------------------------------------ */

export interface EmailMetadata {
  from: string;
  fromDisplayName: string | null;
  to: string;
  replyTo: string | null;
  returnPath: string | null;
  subject: string;
  date: string | null;
  messageId: string | null;
}

export interface AttachmentRecord {
  filename: string;
  sizeBytes: number;
  sha256: string;
  mimeType: string | null;
  risk: Severity;
  note: string | null;
}

export interface UrlRecord {
  url: string;
  displayText: string | null;
  host: string;
  risk: Severity;
  reputation: Reputation;
  /** True when anchor text disguises a different destination. */
  mismatchedAnchor: boolean;
  note: string | null;
}

/** Evidence integrity record backing the chain-of-custody view. */
export interface EvidenceRecord {
  evidenceId: string;
  sha256: string;
  sizeBytes: number;
  acquiredAt: string;
  source: string;
  analystId: string;
  integrity: 'VERIFIED' | 'UNVERIFIED' | 'COMPROMISED';
  custody: CustodyEntry[];
}

export interface CustodyEntry {
  at: string;
  actor: string;
  action: string;
  detail: string;
  hashAfter: string;
}

export interface EmailAnalysis {
  id: string;
  /** Backend row id when persisted by FastAPI; null in simulated mode. */
  backendId: number | null;
  origin: DataOrigin;
  analyzedAt: string;
  filename: string;
  metadata: EmailMetadata;
  headers: HeaderField[];
  rawHeaders: string;
  bodyPreview: string;
  score: ThreatScore;
  assessment: AiAssessment;
  authentication: AuthenticationSummary;
  relayChain: RelayHop[];
  originAssessment: OriginAssessment;
  iocs: Ioc[];
  urls: UrlRecord[];
  attachments: AttachmentRecord[];
  domainIntel: DomainIntelligence[];
  ipIntel: IpIntelligence[];
  evidence: EvidenceRecord;
  /** Populated when the analysis was linked to a campaign cluster. */
  campaignId: string | null;
  /** Non-fatal backend notices, e.g. persistence warnings. */
  warnings: string[];
}

/** Compact row shape for lists and tables. */
export interface AnalysisSummary {
  id: string;
  backendId: number | null;
  origin: DataOrigin;
  sender: string;
  subject: string;
  score: number;
  level: Severity;
  classification: Classification;
  country: string | null;
  analyzedAt: string;
}

/* ------------------------------------------------------------------ */
/* Campaigns                                                           */
/* ------------------------------------------------------------------ */

export interface Campaign {
  id: string;
  name: string;
  /** What tied these messages together. */
  clusterBasis: string[];
  emailCount: number;
  domainCount: number;
  ipCount: number;
  victimCount: number;
  firstObserved: string;
  lastObserved: string;
  risk: Severity;
  classification: Classification;
  status: 'ACTIVE' | 'CONTAINED' | 'DORMANT';
  /** Per-day volume for the activity sparkline. */
  activity: { date: string; count: number }[];
  topDomains: string[];
  topIps: string[];
  summary: string;
}

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

export type CaseStatus = 'OPEN' | 'INVESTIGATING' | 'PENDING_REVIEW' | 'CLOSED';

export interface CaseNote {
  id: string;
  at: string;
  author: string;
  body: string;
}

export interface CaseRecord {
  id: string;
  title: string;
  severity: Severity;
  status: CaseStatus;
  assignedTo: string;
  createdAt: string;
  updatedAt: string;
  summary: string;
  linkedAnalysisIds: string[];
  linkedCampaignIds: string[];
  indicators: Ioc[];
  notes: CaseNote[];
  evidence: EvidenceRecord[];
  slaDueAt: string | null;
}

export interface NewCaseInput {
  title: string;
  severity: Severity;
  summary: string;
  assignedTo: string;
  linkedAnalysisIds: string[];
}

/* ------------------------------------------------------------------ */
/* Alerts                                                              */
/* ------------------------------------------------------------------ */

export type AlertStatus = 'NEW' | 'ACKNOWLEDGED' | 'RESOLVED';

export interface Alert {
  id: string;
  at: string;
  severity: Severity;
  title: string;
  detail: string;
  source: string;
  status: AlertStatus;
  relatedAnalysisId: string | null;
  relatedCampaignId: string | null;
}

/* ------------------------------------------------------------------ */
/* Graph investigation                                                 */
/* ------------------------------------------------------------------ */

export type GraphNodeKind =
  | 'EMAIL'
  | 'DOMAIN'
  | 'IP'
  | 'USER'
  | 'ALIAS'
  | 'URL'
  | 'HASH'
  | 'CAMPAIGN'
  | 'INCIDENT'
  | 'ASN';

export type GraphEdgeKind =
  | 'SENT_FROM'
  | 'RESOLVES_TO'
  | 'HOSTED_ON'
  | 'LINKED_TO'
  | 'SEEN_IN'
  | 'REPLY_TO'
  | 'ASSOCIATED_WITH';

export interface GraphNode {
  id: string;
  kind: GraphNodeKind;
  label: string;
  risk: Severity;
  /** Extra attributes rendered in the inspector panel. */
  attributes: Record<string, string>;
  /** True when more neighbours exist than are currently loaded. */
  expandable: boolean;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  kind: GraphEdgeKind;
  /** 0–1, drives stroke weight. */
  weight: number;
}

export interface InvestigationGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/* ------------------------------------------------------------------ */
/* Analytics                                                           */
/* ------------------------------------------------------------------ */

export type TimeRange = '24H' | '7D' | '30D' | '90D';

export interface DashboardMetrics {
  emailsAnalyzed: number;
  threatsDetected: number;
  criticalThreats: number;
  suspiciousDomains: number;
  maliciousIps: number;
  activeInvestigations: number;
  /** Percentage change vs the previous equivalent window. */
  deltas: Record<
    'emailsAnalyzed' | 'threatsDetected' | 'criticalThreats' | 'activeInvestigations',
    number
  >;
  /** 14-point trend for the header sparkline. */
  trend: { date: string; analyzed: number; threats: number }[];
  origin: DataOrigin;
}

export interface AnalyticsBundle {
  range: TimeRange;
  origin: DataOrigin;
  byCategory: { category: string; count: number; severity: Severity }[];
  overTime: { date: string; phishing: number; bec: number; malware: number; spam: number }[];
  topDomains: { domain: string; count: number; risk: Severity }[];
  topIps: { ip: string; count: number; country: string; risk: Severity }[];
  countryDistribution: { country: string; countryCode: string; count: number; avgScore: number }[];
  confidenceDistribution: { bucket: string; count: number }[];
  authFailures: { mechanism: string; pass: number; fail: number; softfail: number }[];
  campaignActivity: { date: string; campaigns: number; emails: number }[];
}

/* ------------------------------------------------------------------ */
/* Reports                                                             */
/* ------------------------------------------------------------------ */

export interface ReportSection {
  id: string;
  title: string;
  /** Analysts can exclude sections before export. */
  included: boolean;
}

export interface ForensicReport {
  id: string;
  analysisId: string;
  caseId: string | null;
  generatedAt: string;
  generatedBy: string;
  classification: Classification;
  sections: ReportSection[];
  analystNotes: string;
  /** SHA-256 over the report body, printed in the document footer. */
  documentHash: string;
}

/* ------------------------------------------------------------------ */
/* Pipeline                                                            */
/* ------------------------------------------------------------------ */

/**
 * The forensic pipeline's stage definitions and progress types live in
 * `@/lib/pipeline`, next to the stage list itself, so the analyser and the views
 * that render its progress share one source of truth. They are deliberately not
 * re-exported here.
 */

/* ------------------------------------------------------------------ */
/* Audit log (privacy & compliance)                                    */
/* ------------------------------------------------------------------ */

export interface AuditEntry {
  id: string;
  at: string;
  actor: string;
  role: Role;
  action: string;
  target: string;
  outcome: 'SUCCESS' | 'DENIED';
  ipAddress: string;
}

export interface PrivacySettings {
  maskRecipients: boolean;
  maskBodyContent: boolean;
  retentionDays: number;
  storeRawEmail: boolean;
  redactAttachments: boolean;
  auditLogging: boolean;
}
