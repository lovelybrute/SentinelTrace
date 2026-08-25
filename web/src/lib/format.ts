import type { Classification, Severity } from '@/types';

/* ------------------------------------------------------------------ */
/* Numbers                                                             */
/* ------------------------------------------------------------------ */

export function formatNumber(value: number): string {
  return new Intl.NumberFormat('en-IN').format(Math.round(value));
}

export function formatCompact(value: number): string {
  return new Intl.NumberFormat('en-IN', {
    notation: 'compact',
    maximumFractionDigits: 1,
  }).format(value);
}

export function formatPercent(value: number, digits = 1): string {
  return `${value.toFixed(digits)}%`;
}

export function formatDelta(value: number): string {
  const sign = value > 0 ? '+' : '';
  return `${sign}${value.toFixed(1)}%`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB'];
  let size = bytes / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size >= 100 ? 0 : 1)} ${units[unit]}`;
}

/* ------------------------------------------------------------------ */
/* Dates                                                               */
/* ------------------------------------------------------------------ */

const DATE_TIME = new Intl.DateTimeFormat('en-GB', {
  day: '2-digit',
  month: 'short',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
});

const DATE_ONLY = new Intl.DateTimeFormat('en-GB', {
  day: '2-digit',
  month: 'short',
  year: 'numeric',
});

const TIME_ONLY = new Intl.DateTimeFormat('en-GB', {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
});

function toDate(value: string | number | Date | null | undefined): Date | null {
  if (value === null || value === undefined || value === '') return null;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function formatDateTime(value: string | Date | null | undefined): string {
  const d = toDate(value);
  return d ? DATE_TIME.format(d).replace(',', '') : '—';
}

export function formatDate(value: string | Date | null | undefined): string {
  const d = toDate(value);
  return d ? DATE_ONLY.format(d) : '—';
}

export function formatTime(value: string | Date | null | undefined): string {
  const d = toDate(value);
  return d ? TIME_ONLY.format(d) : '—';
}

/** "4 min ago" / "3 days ago" — for alert feeds and activity rails. */
export function formatRelative(value: string | Date | null | undefined): string {
  const d = toDate(value);
  if (!d) return '—';
  const diffMs = Date.now() - d.getTime();
  const abs = Math.abs(diffMs);
  const minute = 60_000;
  const hour = 3_600_000;
  const day = 86_400_000;

  if (abs < minute) return 'just now';
  if (abs < hour) {
    const n = Math.round(abs / minute);
    return `${n} min${n === 1 ? '' : 's'} ago`;
  }
  if (abs < day) {
    const n = Math.round(abs / hour);
    return `${n} hour${n === 1 ? '' : 's'} ago`;
  }
  const n = Math.round(abs / day);
  if (n < 30) return `${n} day${n === 1 ? '' : 's'} ago`;
  return formatDate(d);
}

/** ISO 8601 with millisecond precision — used for custody timestamps. */
export function isoNow(): string {
  return new Date().toISOString();
}

/* ------------------------------------------------------------------ */
/* Strings                                                             */
/* ------------------------------------------------------------------ */

/** BUSINESS_EMAIL_COMPROMISE -> "Business Email Compromise" */
export function titleCaseEnum(value: string): string {
  return value
    .toLowerCase()
    .split('_')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

/** BUSINESS_EMAIL_COMPROMISE -> "BUSINESS EMAIL COMPROMISE" */
export function spacedEnum(value: string): string {
  return value.replace(/_/g, ' ');
}

export function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, Math.max(0, max - 1))}…`;
}

/** Shorten a hash for inline display while keeping both ends recognisable. */
export function shortHash(hash: string, head = 10, tail = 8): string {
  if (hash.length <= head + tail + 1) return hash;
  return `${hash.slice(0, head)}…${hash.slice(-tail)}`;
}

interface AngleAddr {
  address: string;
  /** Offset of the opening `<`, so callers can recover the display name. */
  start: number;
}

/**
 * The routable address in a header value, or null if it carries no angle-addr.
 *
 * A display name may itself contain something that looks like an address, and
 * attackers put one there deliberately — mail clients render the display name
 * and hide the rest:
 *
 *     From: "Anand Krishnan <anand.krishnan@nexoragroup.in>" <a.k.nexora@gmail.com>
 *
 * RFC 5322 puts the deliverable address in the *final* angle-addr, so the last
 * group wins. Taking the first would point every downstream check — SPF, DKIM
 * alignment, domain reputation, geolocation — at the impersonated party's
 * domain instead of the sender's, which is precisely the outcome the technique
 * is designed to produce.
 */
function finalAngleAddr(value: string): AngleAddr | null {
  const pattern = /<([^<>]*)>/g;
  let last: AngleAddr | null = null;
  let addressLike: AngleAddr | null = null;

  let match: RegExpExecArray | null = pattern.exec(value);
  while (match !== null) {
    const found: AngleAddr = { address: match[1].trim(), start: match.index };
    last = found;
    // A group only displaces an earlier one if it could be an address; a bare
    // `<>` envelope sender or stray brackets in a name must not win.
    if (found.address.includes('@')) addressLike = found;
    match = pattern.exec(value);
  }

  return addressLike ?? last;
}

/** Extract the domain from an addr-spec or a display-name address. */
export function domainOf(address: string): string {
  const bare = addressOf(address);
  const at = bare.lastIndexOf('@');
  return at === -1 ? '' : bare.slice(at + 1).toLowerCase();
}

/** Strip the display name from `"Name" <a@b.com>`. */
export function addressOf(value: string): string {
  const found = finalAngleAddr(value);
  return (found ? found.address : value).trim();
}

/**
 * Pull the display name out of `"Name" <a@b.com>`, if present.
 *
 * The whole display name is returned, including any address embedded inside it
 * — that embedded text is evidence, and the spoofing check downstream needs to
 * see it rather than a copy truncated at the first bracket.
 */
export function displayNameOf(value: string): string | null {
  const found = finalAngleAddr(value);
  if (!found) return null;
  const name = value.slice(0, found.start).trim().replace(/^"|"$/g, '').trim();
  return name.length > 0 ? name : null;
}

/**
 * An addr-spec embedded in a display name, when it differs from the address
 * that actually sent the message. Null when the name carries no address or
 * carries the same one.
 */
export function embeddedAddressOf(value: string): string | null {
  const displayName = displayNameOf(value);
  if (!displayName) return null;
  const embedded = displayName.match(/[\w.+-]+@[\w.-]+\.\w{2,}/)?.[0]?.toLowerCase() ?? null;
  if (!embedded) return null;
  return embedded === addressOf(value).toLowerCase() ? null : embedded;
}

/**
 * Partially mask an email address for the data-minimisation setting.
 * `finance@example.com` -> `fi•••••@example.com`
 */
export function maskEmail(value: string): string {
  const address = addressOf(value);
  const at = address.lastIndexOf('@');
  if (at <= 0) return value;
  const local = address.slice(0, at);
  const domain = address.slice(at);
  const keep = Math.min(2, local.length);
  return `${local.slice(0, keep)}${'•'.repeat(Math.max(3, local.length - keep))}${domain}`;
}

/** Mask the final octet of an IPv4 address. */
export function maskIp(ip: string): string {
  const parts = ip.split('.');
  if (parts.length !== 4) return ip;
  return `${parts[0]}.${parts[1]}.${parts[2]}.xxx`;
}

/* ------------------------------------------------------------------ */
/* Severity helpers                                                    */
/* ------------------------------------------------------------------ */

const SEVERITY_ORDER: Record<Severity, number> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

export function compareSeverityDesc(a: Severity, b: Severity): number {
  return SEVERITY_ORDER[b] - SEVERITY_ORDER[a];
}

export function severityFromScore(score: number): Severity {
  if (score >= 75) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 25) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'INFO';
}

/** Verdict headline shown above the classification on the analyzer. */
export function verdictHeadline(level: Severity, classification: Classification): string {
  if (classification === 'LEGITIMATE') return 'NO THREAT DETECTED';
  switch (level) {
    case 'CRITICAL':
      return 'CRITICAL THREAT DETECTED';
    case 'HIGH':
      return 'HIGH-RISK THREAT DETECTED';
    case 'MEDIUM':
      return 'SUSPICIOUS ACTIVITY DETECTED';
    case 'LOW':
      return 'LOW-RISK ANOMALIES DETECTED';
    default:
      return 'ANALYSIS COMPLETE';
  }
}

/* ------------------------------------------------------------------ */
/* Misc                                                                */
/* ------------------------------------------------------------------ */

export function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

/** Stable pseudo-id for client-created records. */
export function makeId(prefix: string): string {
  const rand = Math.random().toString(36).slice(2, 8).toUpperCase();
  return `${prefix}-${rand}`;
}

/**
 * Deterministic 64-hex digest stand-in.
 *
 * Used only to label *simulated* evidence so the chain-of-custody view has
 * realistic-looking values. Real hashes always come from the backend, which
 * computes SHA-256 over the uploaded bytes.
 */
export function pseudoSha256(seed: string): string {
  let h1 = 0x6a09e667;
  let h2 = 0xbb67ae85;
  let h3 = 0x3c6ef372;
  let h4 = 0xa54ff53a;
  for (let i = 0; i < seed.length; i += 1) {
    const c = seed.charCodeAt(i);
    h1 = (Math.imul(h1 ^ c, 2654435761) >>> 0) ^ (h4 >>> 3);
    h2 = (Math.imul(h2 + c, 1597334677) >>> 0) ^ (h1 >>> 5);
    h3 = (Math.imul(h3 ^ (c + i), 2246822519) >>> 0) ^ (h2 >>> 7);
    h4 = (Math.imul(h4 + (c * (i + 1)), 3266489917) >>> 0) ^ (h3 >>> 11);
  }
  const words = [h1, h2, h3, h4, h1 ^ h3, h2 ^ h4, Math.imul(h1, 31) >>> 0, Math.imul(h2, 17) >>> 0];
  return words.map((w) => (w >>> 0).toString(16).padStart(8, '0')).join('');
}
