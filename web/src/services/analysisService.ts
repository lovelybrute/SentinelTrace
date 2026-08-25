/**
 * Analysis orchestration.
 *
 * One entry point, `analyseEmail`, turns raw message bytes into a correlated
 * `EmailAnalysis` while reporting progress against the thirteen-stage pipeline.
 *
 * The strategy is local-first with backend enrichment, chosen so the SIH
 * demonstration runs with no external service reachable while still using the
 * real FastAPI backend when it is up:
 *
 *   1. The browser engine (`analyseLocally`) always runs. It produces a complete
 *      `WireAnalysis` from the message alone, so there is always a result.
 *   2. If the backend is reachable and enrichment is requested, `POST /analyze`
 *      runs in parallel. What it contributes is the DNS records it resolved live
 *      and its persisted `analysis_id`, both merged over the local result. Its
 *      SPF/DKIM/DMARC *status strings* are deliberately not treated as verdicts —
 *      see `correlateAuthentication` for why.
 *   3. Correlation (`correlate`) runs once, over the merged wire payload plus the
 *      local parse, and is the single source of the domain aggregate every view
 *      renders from.
 *
 * A backend that is down, slow or returns a malformed body never blocks a result:
 * the local analysis stands on its own and the origin is reported honestly as
 * simulated so nothing overstates where the numbers came from.
 */

import { sha256 } from '@/lib/hash';
import { parseEmail } from '@/lib/emailParser';
import { PIPELINE_STAGES, initialStageStates } from '@/lib/pipeline';
import type { PipelineStageId, StageState } from '@/lib/pipeline';
import type { DataOrigin, EmailAnalysis } from '@/types';
import { analyseLocally } from './localAnalysis';
import { analysisFilenameFor, analyzeEmail } from './backendService';
import { ApiError } from './http';
import type { WireAnalysis, WireForensics } from './wire';
import { correlate } from './correlate';
import type { SightingLookup } from './correlate/iocs';

export interface AnalyseParams {
  /** Verbatim message bytes as text. */
  raw: string;
  /** Original name; drives the `.eml` requirement when talking to the backend. */
  filename: string;
  /** Who is running the analysis, for the chain of custody. */
  analystId: string;
  /** How the evidence arrived, e.g. "Analyst upload" or "Pasted raw message". */
  acquisitionSource: string;
  /** When true, attempt backend enrichment; when false, stay purely local. */
  useBackend: boolean;
  /** Resolves prior sightings for indicators; keeps correlation pure when omitted. */
  lookup?: SightingLookup;
  /** Progress callback, invoked on every stage transition. */
  onStage?: (stages: StageState[]) => void;
  /** External cancellation (component unmount, navigation away). */
  signal?: AbortSignal;
}

export interface AnalyseOutcome {
  analysis: EmailAnalysis;
  /** Whether the backend contributed to this result. */
  origin: DataOrigin;
  /** Present when backend enrichment was attempted but did not succeed. */
  backendNote: string | null;
  /** The final state of every pipeline stage. */
  stages: StageState[];
}

/**
 * Run the full pipeline. Resolves even when the backend fails; rejects only on a
 * genuine cancellation or an unparseable message, which the caller surfaces to
 * the analyst rather than silently swallowing.
 */
export async function analyseEmail(params: AnalyseParams): Promise<AnalyseOutcome> {
  const analyzedAt = new Date().toISOString();
  const runner = new StageRunner(params.onStage);

  throwIfAborted(params.signal);

  // Stage 1 — ingest and hash. The digest is the evidence integrity anchor, so
  // it is computed from the real bytes before anything else touches them.
  runner.begin('INGEST');
  const digest = await sha256(params.raw);
  const contentHash = digest.hex;
  await runner.settle('INGEST', digest.verified ? null : 'Web Crypto unavailable — integrity recorded as unverified.');

  throwIfAborted(params.signal);

  // Kick off backend enrichment in parallel with local parsing. It is awaited
  // only at the classification stage, so a slow backend overlaps local work
  // instead of serialising behind it.
  const backendPromise = params.useBackend
    ? runBackend(params)
    : Promise.resolve<BackendOutcome>({ wire: null, note: null, attempted: false });

  // Stages 2 through 11 report the local engine's progress. `analyseLocally` is
  // synchronous and fast; the runner paces the stages for legibility.
  runner.begin('PARSE_HEADERS');
  const parsed = parseEmail(params.raw);
  if (parsed.headerOrder.length === 0 && !params.raw.includes(':')) {
    throw new AnalysisInputError('The supplied text does not look like an email message — no headers were found.');
  }
  const localWire = analyseLocally({ raw: params.raw, filename: params.filename, contentHash, analyzedAt });
  await runner.settle('PARSE_HEADERS');

  const localForensics = localWire.forensics ?? null;
  await runAuthStages(runner, localForensics);

  for (const id of MID_STAGES) {
    runner.begin(id);
    await runner.settle(id);
  }

  throwIfAborted(params.signal);

  // Stage 12 — classification. This is where the backend, if any, is folded in:
  // its authenticated verdicts and analysis_id enrich the local wire payload
  // before the single correlation pass.
  runner.begin('CLASSIFY');
  const backend = await backendPromise;
  const wire = backend.wire ? mergeWire(localWire, backend.wire) : localWire;
  const origin: DataOrigin = backend.wire ? 'LIVE_BACKEND' : 'SIMULATED';
  await runner.settle('CLASSIFY', backend.attempted && !backend.wire ? backend.note : null);

  runner.begin('GEO');
  await runner.settle('GEO');

  // Stage 13 — correlation. One pass over the merged payload yields the aggregate.
  runner.begin('CORRELATE');
  const analysis = correlate({
    wire,
    parsed,
    raw: params.raw,
    filename: params.filename,
    origin,
    analyzedAt,
    contentHash,
    analystId: params.analystId,
    acquisitionSource: params.acquisitionSource,
    ...(params.lookup ? { lookup: params.lookup } : {}),
  });
  await runner.settle('CORRELATE');

  return {
    analysis,
    origin,
    backendNote: backend.attempted ? backend.note : null,
    stages: runner.snapshot(),
  };
}

/** Raised when the input cannot be treated as an email at all. */
export class AnalysisInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AnalysisInputError';
  }
}

/* ------------------------------------------------------------------ */
/* Reopening a stored analysis                                         */
/* ------------------------------------------------------------------ */

/**
 * Re-correlate an analysis the backend persisted, so a row in the recent-threats
 * feed opens the full forensic view instead of a dead end.
 *
 * The backend stores the complete original `full_analysis` payload but not the
 * raw message, so the parse is reconstructed from the persisted headers. Two
 * fields genuinely cannot be recovered — Reply-To and Return-Path are not
 * persisted — and the body is only the stored preview. The returned analysis
 * therefore carries a warning saying so, rather than presenting a reconstruction
 * as if it were the original evidence.
 */
export function recorrelateStored(params: {
  wire: WireAnalysis;
  filename: string;
  analyzedAt: string;
  analystId: string;
  lookup?: SightingLookup;
}): EmailAnalysis {
  const reconstructed = reconstructMessage(params.wire);
  const analysis = correlate({
    wire: params.wire,
    parsed: parseEmail(reconstructed),
    raw: reconstructed,
    filename: params.filename,
    origin: 'LIVE_BACKEND',
    analyzedAt: params.analyzedAt,
    contentHash: params.wire.evidence.content_hash,
    analystId: params.analystId,
    acquisitionSource: 'Reopened from the case database',
    ...(params.lookup ? { lookup: params.lookup } : {}),
  });

  return {
    ...analysis,
    warnings: [
      'Reopened from stored analysis. The raw message is not retained by the analysis service, so this view was reconstructed from the persisted headers: Reply-To and Return-Path are unavailable and the body is the stored preview only.',
      ...analysis.warnings,
    ],
  };
}

/**
 * Rebuild an RFC 5322 message from the persisted evidence and run the real parser
 * over it, rather than hand-assembling a `ParsedEmail` that could drift from what
 * the parser would produce.
 */
function reconstructMessage(wire: WireAnalysis): string {
  const { evidence } = wire;
  const lines: string[] = [];

  // Received headers are written first so they appear above the originator
  // fields, matching how a real MTA stacks them.
  for (const received of evidence.received_headers) {
    if (received.raw) lines.push(`Received: ${received.raw.replace(/^received:\s*/i, '')}`);
  }
  if (evidence.authentication_results) lines.push(`Authentication-Results: ${evidence.authentication_results}`);
  if (evidence.dkim_signature) lines.push(`DKIM-Signature: ${evidence.dkim_signature}`);
  if (evidence.from) lines.push(`From: ${evidence.from}`);
  if (evidence.to) lines.push(`To: ${evidence.to}`);
  if (evidence.subject) lines.push(`Subject: ${evidence.subject}`);
  if (evidence.date) lines.push(`Date: ${evidence.date}`);
  if (evidence.message_id) lines.push(`Message-ID: ${evidence.message_id}`);
  lines.push('MIME-Version: 1.0');
  lines.push('Content-Type: text/plain; charset="utf-8"');

  return `${lines.join('\r\n')}\r\n\r\n${evidence.body_preview}`;
}

/* ------------------------------------------------------------------ */
/* Backend enrichment                                                  */
/* ------------------------------------------------------------------ */

interface BackendOutcome {
  wire: WireAnalysis | null;
  note: string | null;
  attempted: boolean;
}

/**
 * Attempt `POST /analyze`. Any infrastructural failure resolves to a null wire
 * with an explanatory note rather than rejecting, so the caller falls back to the
 * local result. A validation failure (the backend rejecting the input) is
 * likewise reported, not thrown, because the local engine can still analyse it.
 */
async function runBackend(params: AnalyseParams): Promise<BackendOutcome> {
  try {
    const wire = await analyzeEmail({
      raw: params.raw,
      filename: analysisFilenameFor(params.filename),
      ...(params.signal ? { signal: params.signal } : {}),
    });
    return { wire, note: null, attempted: true };
  } catch (error) {
    if (error instanceof ApiError) {
      return { wire: null, note: backendNoteFor(error), attempted: true };
    }
    // An unexpected error still must not sink the analysis.
    return { wire: null, note: 'The analysis service failed unexpectedly; results were computed locally.', attempted: true };
  }
}

function backendNoteFor(error: ApiError): string {
  switch (error.kind) {
    case 'UNREACHABLE':
      return 'The analysis service was unreachable; results were computed by the local engine.';
    case 'TIMEOUT':
      return 'The analysis service did not respond in time; results were computed by the local engine.';
    case 'SERVER_ERROR':
      return 'The analysis service reported an internal error; results were computed by the local engine.';
    case 'BAD_REQUEST':
      return `The analysis service rejected the upload (${error.message}); results were computed by the local engine.`;
    case 'MALFORMED':
      return 'The analysis service returned an unreadable response; results were computed by the local engine.';
    default:
      return 'The analysis service was unavailable; results were computed by the local engine.';
  }
}

/**
 * Merge the backend result over the local one. The backend owns one thing the
 * local engine cannot obtain from a browser: records resolved from live DNS, plus
 * the persisted `analysis_id`. Everything else stays local, because the local
 * engine parsed the same bytes and its structure is what correlation was built
 * against. Note that this merge makes the backend forensics *available* to
 * correlation as evaluator input — `correlateAuthentication` still evaluates every
 * verdict itself, since the backend's `status: "pass"` means only that a policy is
 * published, not that this message authenticated against it.
 */
function mergeWire(local: WireAnalysis, backend: WireAnalysis): WireAnalysis {
  const forensics: WireForensics | undefined = backend.forensics ?? local.forensics;
  return {
    ...local,
    ...(forensics ? { forensics } : {}),
    ...(backend.analysis_id != null ? { analysis_id: backend.analysis_id } : {}),
    ...(backend.storage_status ? { storage_status: backend.storage_status } : {}),
    ...(backend.storage_warning ? { storage_warning: backend.storage_warning } : {}),
  };
}

/* ------------------------------------------------------------------ */
/* Stage sequencing                                                    */
/* ------------------------------------------------------------------ */

/** Stages between the auth checks and classification, run in order. */
const MID_STAGES: PipelineStageId[] = ['IOC', 'URLS', 'DOMAINS', 'IP_INTEL', 'RELAY'];

/**
 * The SPF/DKIM/DMARC stages, annotated from the local forensics so a stage that
 * could not resolve a policy says so rather than silently completing.
 */
async function runAuthStages(runner: StageRunner, forensics: WireForensics | null): Promise<void> {
  runner.begin('SPF');
  await runner.settle('SPF', forensics?.authentication.spf?.found === false ? 'No SPF policy was published for the sender domain.' : null);

  runner.begin('DKIM');
  await runner.settle('DKIM', forensics?.authentication.dkim?.valid === false ? 'The message carried no verifiable DKIM signature.' : null);

  runner.begin('DMARC');
  await runner.settle('DMARC', forensics?.authentication.dmarc?.found === false ? 'No DMARC policy was published for the sender domain.' : null);
}

/**
 * Drives stage state and pacing. Each stage is held for at least its dwell floor
 * so the sequence is readable; a stage slower than its floor reports its real
 * duration. The pacing is presentation only — see the note in `lib/pipeline.ts`.
 */
class StageRunner {
  private readonly states: StageState[] = initialStageStates();
  private readonly startedAt = new Map<PipelineStageId, number>();

  constructor(private readonly onStage?: (stages: StageState[]) => void) {
    this.emit();
  }

  begin(id: PipelineStageId): void {
    const state = this.find(id);
    state.status = 'ACTIVE';
    this.startedAt.set(id, now());
    this.emit();
  }

  /** Mark a stage complete after honouring its dwell floor. */
  async settle(id: PipelineStageId, note: string | null = null): Promise<void> {
    const stage = PIPELINE_STAGES.find((entry) => entry.id === id);
    const started = this.startedAt.get(id) ?? now();
    const elapsed = now() - started;
    const floor = stage?.minDwellMs ?? 0;
    if (elapsed < floor) await delay(floor - elapsed);

    const state = this.find(id);
    state.status = note ? 'DEGRADED' : 'COMPLETE';
    state.durationMs = Math.round(now() - started);
    state.note = note;
    this.emit();
  }

  snapshot(): StageState[] {
    return this.states.map((state) => ({ ...state }));
  }

  private find(id: PipelineStageId): StageState {
    const state = this.states.find((entry) => entry.id === id);
    if (!state) throw new Error(`Unknown pipeline stage: ${id}`);
    return state;
  }

  private emit(): void {
    this.onStage?.(this.snapshot());
  }
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

function now(): number {
  return typeof performance !== 'undefined' ? performance.now() : Date.now();
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new DOMException('Analysis cancelled.', 'AbortError');
}
