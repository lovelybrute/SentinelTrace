/**
 * Typed client for the SentinelTrace FastAPI backend.
 *
 * One function per endpoint that actually exists in `backend/main.py`, and
 * nothing more. The endpoint list is deliberately not aspirational: campaigns,
 * cases, alerts and reports have no backend routes, so those views are served by
 * the clearly-separated demo services rather than by inventing calls that would
 * 404 in front of a judge.
 *
 * Every function here either returns data or throws `ApiError`. Deciding what to
 * do about a failure — fall back to the local engine, show a degraded badge,
 * surface a validation message — belongs to the caller, which has the context to
 * choose. See `analysisService.ts` for the analysis fallback policy.
 */

import { ApiError, request } from './http';
import type {
  WireAnalysis,
  WireCountryThreat,
  WireRecentThreat,
  WireStats,
  WireStoredAnalysis,
} from './wire';

/** `GET /` — service identity and liveness. */
export interface BackendIdentity {
  project: string;
  problem: string;
  status: string;
  module: string;
}

export function fetchIdentity(signal?: AbortSignal): Promise<BackendIdentity> {
  return request<BackendIdentity>('/', signal ? { signal } : {});
}

/**
 * `POST /analyze` — the only write endpoint.
 *
 * The backend validates the extension and rejects anything not ending `.eml`,
 * so pasted text and `.msg` input must be presented under an `.eml` name. The
 * caller owns that decision; `analysisFilenameFor` below implements it.
 */
export async function analyzeEmail(
  params: { raw: string; filename: string; timeoutMs?: number; signal?: AbortSignal },
): Promise<WireAnalysis> {
  const body = new FormData();
  // The FastAPI parameter is `file: UploadFile = File(...)`; the field name and
  // the transmitted filename both matter to its validation.
  body.append('file', new Blob([params.raw], { type: 'message/rfc822' }), params.filename);

  const payload = await request<WireAnalysis>('/analyze', {
    method: 'POST',
    body,
    // Deliberately no Content-Type header: the browser must set the multipart
    // boundary itself, and overriding it makes FastAPI reject the request.
    ...(params.timeoutMs === undefined ? {} : { timeoutMs: params.timeoutMs }),
    ...(params.signal ? { signal: params.signal } : {}),
  });

  if (!isWireAnalysis(payload)) {
    throw new ApiError('MALFORMED', 'The analysis service returned a payload with no evidence section.');
  }
  return payload;
}

/**
 * The backend accepts only `.eml`. Pasted text and other containers are analysed
 * locally under their own name, but when they are sent upstream they need a name
 * the service will accept — the bytes are unchanged either way.
 */
export function analysisFilenameFor(filename: string): string {
  return filename.toLowerCase().endsWith('.eml') ? filename : `${stripExtension(filename)}.eml`;
}

function stripExtension(filename: string): string {
  const trimmed = filename.trim() || 'pasted-message';
  const dot = trimmed.lastIndexOf('.');
  return dot > 0 ? trimmed.slice(0, dot) : trimmed;
}

/** `GET /stats` — aggregate counters over persisted analyses. */
export function fetchStats(signal?: AbortSignal): Promise<WireStats> {
  return request<WireStats>('/stats', signal ? { signal } : {});
}

/** `GET /recent-threats` — flagged analyses, newest first. */
export function fetchRecentThreats(limit = 10, signal?: AbortSignal): Promise<WireRecentThreat[]> {
  return request<WireRecentThreat[]>(
    `/recent-threats?limit=${encodeURIComponent(String(limit))}`,
    signal ? { signal } : {},
  );
}

/** `GET /threat-by-country` — sender-country distribution, at most 20 rows. */
export function fetchThreatsByCountry(signal?: AbortSignal): Promise<WireCountryThreat[]> {
  return request<WireCountryThreat[]>('/threat-by-country', signal ? { signal } : {});
}

export interface ModelMetrics {
  validation_status: string;
  message?: string;
  trained_at?: string;
  dataset_records?: number;
  train_records?: number;
  test_records?: number;
  labels?: string[];
  selected_model?: string;
  models?: Record<string, { accuracy: number; precision_macro: number; recall_macro: number; f1_macro: number; confusion_matrix: number[][] }>;
  limitations?: string;
}

export function fetchModelMetrics(signal?: AbortSignal): Promise<ModelMetrics> {
  return request<ModelMetrics>('/model/metrics', signal ? { signal } : {});
}

/**
 * `GET /analysis/{id}` — a stored analysis. `full_analysis` holds the complete
 * original payload, so a persisted case can be re-correlated rather than
 * re-analysed. It is `{}` for rows written before that column was populated,
 * which `storedWireAnalysis` reports as absent instead of as an empty analysis.
 */
export function fetchStoredAnalysis(id: number, signal?: AbortSignal): Promise<WireStoredAnalysis> {
  return request<WireStoredAnalysis>(
    `/analysis/${encodeURIComponent(String(id))}`,
    signal ? { signal } : {},
  );
}

/** Recover the re-correlatable payload from a stored row, if it has one. */
export function storedWireAnalysis(stored: WireStoredAnalysis): WireAnalysis | null {
  return isWireAnalysis(stored.full_analysis) ? stored.full_analysis : null;
}

/**
 * Structural guard. The backend is untyped at the wire, and a proxy error page or
 * a truncated body would otherwise surface as a crash deep inside correlation,
 * where the cause is unrecognisable. Checking the sections correlation actually
 * dereferences turns that into a clear failure at the boundary.
 */
export function isWireAnalysis(value: unknown): value is WireAnalysis {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Partial<WireAnalysis>;
  return (
    typeof candidate.evidence === 'object' &&
    candidate.evidence !== null &&
    typeof candidate.threat_assessment === 'object' &&
    candidate.threat_assessment !== null &&
    Array.isArray(candidate.evidence.received_headers) &&
    typeof candidate.geolocation === 'object' &&
    candidate.geolocation !== null &&
    Array.isArray(candidate.geolocation.sender_locations) &&
    typeof candidate.threat_indicators === 'object' &&
    candidate.threat_indicators !== null &&
    Array.isArray(candidate.threat_indicators.urls) &&
    Array.isArray(candidate.threat_indicators.ip_addresses) &&
    Array.isArray(candidate.threat_indicators.emails) &&
    Array.isArray(candidate.attachments)
  );
}
