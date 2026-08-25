/**
 * Small helpers shared by the correlation modules.
 *
 * These exist so that severity escalation, host extraction and organisational
 * domain comparison behave identically everywhere. A relay hop, a URL and an
 * IOC must agree on what "the same organisation" means, or the findings
 * contradict each other.
 */

import { organisationalDomain } from '@/lib/authEval';
import { hostOf } from '@/lib/emailParser';
import { compareSeverityDesc } from '@/lib/format';
import type { Severity } from '@/types';

/** Shown for a header the forensics view must list even when it is absent. */
export const NOT_PRESENT = '(not present)';

/** Raise `current` to `candidate` when `candidate` is the more severe of the two. */
export function escalate(current: Severity, candidate: Severity): Severity {
  return compareSeverityDesc(current, candidate) > 0 ? candidate : current;
}

/** The most severe value in a list, or `INFO` when the list is empty. */
export function highest(values: Severity[]): Severity {
  return values.reduce<Severity>((worst, value) => escalate(worst, value), 'INFO');
}

export function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}

/**
 * Host portion of a URL, tolerating the malformed values that turn up in real
 * phishing mail. `hostOf` uses the URL constructor and returns null for anything
 * it rejects, so this falls back to a manual authority parse rather than
 * discarding the indicator.
 */
export function hostFromUrl(url: string): string {
  const parsed = hostOf(url);
  if (parsed) return parsed;

  const match = url.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#\s]+)/i);
  const authority = match ? match[1] : url;
  return authority
    .replace(/^[^@]*@/, '')
    .replace(/:\d+$/, '')
    .trim()
    .toLowerCase();
}

/** Organisational domain of a hostname or address domain, or null. */
export function orgOf(domain: string | null | undefined): string | null {
  if (!domain) return null;
  const trimmed = domain.trim().toLowerCase().replace(/^www\./, '');
  if (!trimmed || !trimmed.includes('.')) return null;
  return organisationalDomain(trimmed);
}

/** True when both values resolve to the same organisational domain. */
export function sameOrganisation(a: string | null | undefined, b: string | null | undefined): boolean {
  const left = orgOf(a);
  const right = orgOf(b);
  return left !== null && right !== null && left === right;
}

/**
 * Filename extensions that look like TLDs. Without this, `invoice.pdf` in
 * anchor text is read as a domain and every attachment reference becomes a
 * false anchor-mismatch finding.
 */
const FILE_EXTENSIONS = new Set([
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'csv', 'rtf',
  'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'webp', 'ico',
  'zip', 'rar', 'gz', 'tar', 'exe', 'msi', 'dmg', 'iso', 'img',
  'html', 'htm', 'js', 'json', 'xml', 'md', 'css', 'php', 'asp', 'aspx', 'jsp',
]);

/**
 * Best-effort hostname mentioned inside a fragment of text — used to detect
 * anchor text that advertises one destination while the href points elsewhere.
 */
export function hostFromText(text: string): string | null {
  const embeddedUrl = text.match(/https?:\/\/[^\s<>"']+/i);
  if (embeddedUrl) return hostFromUrl(embeddedUrl[0]);

  const candidate = text
    .match(/\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)\b/i)?.[1]
    ?.toLowerCase();
  if (!candidate) return null;

  const tld = candidate.slice(candidate.lastIndexOf('.') + 1);
  if (tld.length < 2 || FILE_EXTENSIONS.has(tld)) return null;
  return candidate;
}

/** Registrable label of a domain — `nexoragroup` from `nexoragroup.in`. */
export function registrableLabel(domain: string | null | undefined): string {
  const org = orgOf(domain);
  return org ? org.split('.')[0] : '';
}

/** Join sentence fragments into a single note, or null when there is nothing to say. */
export function joinNotes(fragments: (string | null | undefined)[]): string | null {
  const kept = fragments.filter((fragment): fragment is string => Boolean(fragment && fragment.trim()));
  return kept.length > 0 ? kept.join(' ') : null;
}
