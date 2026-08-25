/**
 * HTTP transport for the SentinelTrace backend.
 *
 * Deliberately thin: timeouts, abort handling and typed failures, so callers can
 * distinguish "backend is down" (fall back to the simulation) from "backend
 * rejected this input" (surface the message to the analyst).
 */

/** Base URL for the FastAPI service. The Vite dev server proxies `/api` → :8000. */
export const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '/api';

export const DEFAULT_TIMEOUT_MS = 20_000;

export type ApiFailureKind =
  | 'UNREACHABLE'
  | 'TIMEOUT'
  | 'BAD_REQUEST'
  | 'NOT_FOUND'
  | 'SERVER_ERROR'
  | 'MALFORMED';

export class ApiError extends Error {
  readonly kind: ApiFailureKind;
  readonly status: number | null;

  constructor(kind: ApiFailureKind, message: string, status: number | null = null) {
    super(message);
    this.name = 'ApiError';
    this.kind = kind;
    this.status = status;
  }

  /** True when the sensible response is to fall back to simulated data. */
  get isInfrastructural(): boolean {
    return this.kind === 'UNREACHABLE' || this.kind === 'TIMEOUT' || this.kind === 'SERVER_ERROR';
  }
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  body?: BodyInit | null;
  headers?: Record<string, string>;
  timeoutMs?: number;
  signal?: AbortSignal;
}

/** Perform a request and parse a JSON response, normalising every failure. */
export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body = null, headers = {}, timeoutMs = DEFAULT_TIMEOUT_MS, signal } = options;

  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(new DOMException('timeout', 'TimeoutError')), timeoutMs);

  // Propagate an externally supplied abort (e.g. component unmount).
  const onExternalAbort = () => controller.abort(new DOMException('cancelled', 'AbortError'));
  signal?.addEventListener('abort', onExternalAbort);

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method,
      body,
      headers,
      signal: controller.signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'TimeoutError') {
      throw new ApiError('TIMEOUT', `Request to ${path} exceeded ${timeoutMs}ms.`);
    }
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new ApiError('UNREACHABLE', 'Request cancelled.');
    }
    throw new ApiError('UNREACHABLE', 'Analysis backend is not reachable.');
  } finally {
    window.clearTimeout(timer);
    signal?.removeEventListener('abort', onExternalAbort);
  }

  if (!response.ok) {
    const detail = await readErrorDetail(response);
    if (response.status === 400 || response.status === 422) {
      throw new ApiError('BAD_REQUEST', detail, response.status);
    }
    if (response.status === 404) {
      throw new ApiError('NOT_FOUND', detail, response.status);
    }
    throw new ApiError('SERVER_ERROR', detail, response.status);
  }

  // 204 and genuinely empty bodies are valid for some calls.
  const text = await response.text();
  if (!text) return null as unknown as T;

  try {
    return JSON.parse(text) as T;
  } catch {
    throw new ApiError('MALFORMED', `Backend returned a non-JSON response for ${path}.`);
  }
}

/** FastAPI puts human-readable errors in `detail`; fall back gracefully. */
async function readErrorDetail(response: Response): Promise<string> {
  try {
    const text = await response.text();
    if (!text) return `${response.status} ${response.statusText}`;
    const parsed = JSON.parse(text) as { detail?: unknown };
    if (typeof parsed.detail === 'string') return parsed.detail;
    if (Array.isArray(parsed.detail)) {
      const first = parsed.detail[0] as { msg?: string } | undefined;
      if (first?.msg) return first.msg;
    }
    return text.slice(0, 300);
  } catch {
    return `${response.status} ${response.statusText}`;
  }
}

/** Short-timeout liveness probe used by the service-status strip. */
export async function probeBackend(
  timeoutMs = 2500,
): Promise<{ reachable: boolean; latencyMs: number | null; detail: string }> {
  const started = performance.now();
  try {
    const payload = await request<{ status?: string; module?: string }>('/', { timeoutMs });
    const latencyMs = Math.round(performance.now() - started);
    return {
      reachable: true,
      latencyMs,
      detail: payload?.module ? `${payload.module} · ${latencyMs}ms` : `Responding in ${latencyMs}ms`,
    };
  } catch (error) {
    const message = error instanceof ApiError ? error.message : 'Probe failed.';
    return { reachable: false, latencyMs: null, detail: message };
  }
}
