/**
 * Forensic pipeline definition.
 *
 * The thirteen stages an analysis passes through, in the order they actually run.
 * This module is pure data and types: the analyser reports progress against these
 * stages and the Email Analyzer view renders them, so neither side owns the list.
 *
 * A note on `minDwellMs`. The stages below are real — each one corresponds to
 * work the analyser genuinely performs — but local correlation completes in a few
 * milliseconds, far faster than a human can read. The runner therefore holds each
 * stage on screen for at least this long so the sequence is legible. The pacing
 * affects presentation only; every verdict, score and finding is computed from
 * the message in front of it. When a stage is slower than its floor (a backend
 * round-trip, a large MIME tree) the real duration is what gets reported.
 */

export type PipelineStageId =
  | 'INGEST'
  | 'PARSE_HEADERS'
  | 'SPF'
  | 'DKIM'
  | 'DMARC'
  | 'IOC'
  | 'URLS'
  | 'DOMAINS'
  | 'IP_INTEL'
  | 'RELAY'
  | 'CLASSIFY'
  | 'GEO'
  | 'CORRELATE';

export type StageStatus = 'PENDING' | 'ACTIVE' | 'COMPLETE' | 'DEGRADED' | 'FAILED';

export interface PipelineStage {
  id: PipelineStageId;
  /** Display label, upper-case to match the forensic console styling. */
  label: string;
  /** One line explaining what this stage does, shown while it is active. */
  detail: string;
  /** Minimum time the stage stays on screen, for legibility. */
  minDwellMs: number;
}

export const PIPELINE_STAGES: readonly PipelineStage[] = [
  {
    id: 'INGEST',
    label: 'INGESTING EMAIL',
    detail: 'Reading the acquired bytes and computing the SHA-256 evidence digest.',
    minDwellMs: 260,
  },
  {
    id: 'PARSE_HEADERS',
    label: 'PARSING HEADERS',
    detail: 'Decoding RFC 5322 headers and walking the MIME tree for bodies and attachments.',
    minDwellMs: 300,
  },
  {
    id: 'SPF',
    label: 'VALIDATING SPF',
    detail: 'Evaluating the sender policy against the address that connected to the recipient.',
    minDwellMs: 240,
  },
  {
    id: 'DKIM',
    label: 'VALIDATING DKIM',
    detail: 'Parsing the signature and checking its signing domain against the From header.',
    minDwellMs: 240,
  },
  {
    id: 'DMARC',
    label: 'VALIDATING DMARC',
    detail: 'Resolving the published policy and testing identifier alignment.',
    minDwellMs: 240,
  },
  {
    id: 'IOC',
    label: 'EXTRACTING IOCS',
    detail: 'Collecting addresses, domains, links, hashes and attachments as indicators.',
    minDwellMs: 260,
  },
  {
    id: 'URLS',
    label: 'ANALYZING URLS',
    detail: 'Comparing anchor text against real destinations and inspecting link paths.',
    minDwellMs: 260,
  },
  {
    id: 'DOMAINS',
    label: 'ANALYZING DOMAINS',
    detail: 'Checking registration age, mail policy and lookalike similarity to known brands.',
    minDwellMs: 300,
  },
  {
    id: 'IP_INTEL',
    label: 'ANALYZING IP INTELLIGENCE',
    detail: 'Resolving network ownership, ASN, hosting type and reputation for each address.',
    minDwellMs: 300,
  },
  {
    id: 'RELAY',
    label: 'RECONSTRUCTING RELAY PATH',
    detail: 'Ordering the Received chain from sender to recipient and classifying each hop.',
    minDwellMs: 320,
  },
  {
    id: 'CLASSIFY',
    label: 'AI THREAT CLASSIFICATION',
    detail: 'Weighing eight scored dimensions into a classification and confidence.',
    minDwellMs: 380,
  },
  {
    id: 'GEO',
    label: 'GEOLOCATION ANALYSIS',
    detail: 'Estimating probable infrastructure locations and flagging anonymising networks.',
    minDwellMs: 300,
  },
  {
    id: 'CORRELATE',
    label: 'FORENSIC CORRELATION',
    detail: 'Joining findings into the assessment, evidence record and chain of custody.',
    minDwellMs: 340,
  },
] as const;

export interface StageState {
  id: PipelineStageId;
  label: string;
  detail: string;
  status: StageStatus;
  /** Measured wall-clock duration once the stage has finished. */
  durationMs: number | null;
  /** Set when a stage completed with a caveat, e.g. a dataset had no entry. */
  note: string | null;
}

/** Every stage in its initial state, for first render before analysis begins. */
export function initialStageStates(): StageState[] {
  return PIPELINE_STAGES.map((stage) => ({
    id: stage.id,
    label: stage.label,
    detail: stage.detail,
    status: 'PENDING',
    durationMs: null,
    note: null,
  }));
}

/** Total of the dwell floors — the shortest the animation can honestly run. */
export const PIPELINE_MIN_DURATION_MS = PIPELINE_STAGES.reduce(
  (total, stage) => total + stage.minDwellMs,
  0,
);
