/**
 * Indicator-of-compromise extraction.
 *
 * Collapses the analysis into the flat, copyable indicator list an analyst pushes
 * into a blocklist, a SIEM query or a threat-intelligence platform.
 *
 * Two deliberate design choices:
 *
 *  - Indicator IDs are derived from the type and value rather than randomly
 *    generated, so the same indicator carries the same ID across analyses. That
 *    makes list keys stable and lets the graph and campaign views join on it.
 *
 *  - Prior sightings are supplied through an injected `SightingLookup` callback.
 *    Correlation stays a pure function of the message plus the offline datasets;
 *    it never reaches into campaign or case storage itself.
 *
 * Values are stored verbatim. Masking of personal data is a presentation concern
 * driven by the privacy settings, so the record keeps what was observed and the
 * UI decides what to show.
 */

import type {
  AttachmentRecord,
  DomainIntelligence,
  Ioc,
  IocType,
  IpIntelligence,
  Reputation,
  Severity,
  UrlRecord,
} from '@/types';
import { domainOf, pseudoSha256 } from '@/lib/format';
import { escalate } from './shared';

/** What the platform already knows about an indicator from earlier work. */
export interface Sighting {
  /** Case or campaign identifiers this indicator already appears in. */
  incidentIds: string[];
  /** Earliest recorded observation, ISO-8601. */
  firstSeen: string | null;
}

/**
 * Resolves prior sightings for an indicator. Supplied by the caller so this
 * module has no dependency on campaign or case storage.
 */
export type SightingLookup = (type: IocType, value: string) => Sighting | null;

export interface EmailMention {
  address: string;
  /** Where the address was observed, e.g. "From header", "Reply-To header". */
  source: string;
}

export interface IocBuildInput {
  ipIntel: IpIntelligence[];
  domainIntel: DomainIntelligence[];
  urls: UrlRecord[];
  emails: EmailMention[];
  attachments: AttachmentRecord[];
  messageId: string | null;
  /** SHA-256 of the acquired message bytes. */
  contentHash: string | null;
  analyzedAt: string;
  lookup?: SightingLookup;
}

const RISK_ORDER: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

/** Deterministic identifier for an indicator. */
function iocId(type: IocType, value: string): string {
  return `IOC-${type}-${pseudoSha256(`${type}:${value.toLowerCase()}`).slice(0, 12).toUpperCase()}`;
}

export function buildIocs(input: IocBuildInput): Ioc[] {
  const iocs: Ioc[] = [];
  const seen = new Set<string>();

  const add = (
    type: IocType,
    value: string,
    risk: Severity,
    reputation: Reputation,
    source: string,
    observedAt: string | null,
  ): void => {
    const trimmed = value.trim();
    if (!trimmed) return;

    const key = `${type}:${trimmed.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);

    const sighting = input.lookup?.(type, trimmed) ?? null;

    iocs.push({
      id: iocId(type, trimmed),
      type,
      value: trimmed,
      risk,
      reputation,
      source,
      relatedIncidents: sighting?.incidentIds ?? [],
      // Prefer a recorded earlier sighting over this observation; that is the
      // whole point of asking.
      firstSeen: sighting?.firstSeen ?? observedAt,
    });
  };

  for (const ip of input.ipIntel) {
    add('IP', ip.ip, ip.risk, ip.reputation, ip.notes[0] ?? 'Observed in the relay chain', ip.firstSeen);
  }

  for (const domain of input.domainIntel) {
    add('DOMAIN', domain.domain, domain.risk, domain.reputation, domain.notes[0] ?? 'Observed in message headers', domain.createdAt);
  }

  for (const url of input.urls) {
    add('URL', url.url, url.risk, url.reputation, `Link in message body (host ${url.host})`, input.analyzedAt);
  }

  // Email addresses inherit the standing of their domain: an address at a
  // malicious lookalike domain is itself an actionable indicator.
  for (const mention of input.emails) {
    const domain = domainOf(mention.address);
    const intel = input.domainIntel.find((entry) => entry.domain === domain);
    add(
      'EMAIL',
      mention.address,
      intel?.risk ?? 'INFO',
      intel?.reputation ?? 'UNKNOWN',
      mention.source,
      input.analyzedAt,
    );
  }

  for (const attachment of input.attachments) {
    add(
      'ATTACHMENT',
      attachment.filename,
      attachment.risk,
      attachment.risk === 'CRITICAL' ? 'MALICIOUS' : attachment.risk === 'HIGH' ? 'SUSPICIOUS' : 'UNKNOWN',
      attachment.note ?? 'Attached to the analysed message',
      input.analyzedAt,
    );
    if (attachment.sha256) {
      add(
        'HASH',
        attachment.sha256,
        attachment.risk,
        attachment.risk === 'CRITICAL' ? 'MALICIOUS' : 'UNKNOWN',
        `SHA-256 of attachment ${attachment.filename}`,
        input.analyzedAt,
      );
    }
  }

  if (input.messageId) {
    add(
      'MESSAGE_ID',
      input.messageId,
      'INFO',
      'UNKNOWN',
      'Message-ID header — pivots to other messages from the same generator',
      input.analyzedAt,
    );
  }

  if (input.contentHash) {
    add(
      'HASH',
      input.contentHash,
      'INFO',
      'UNKNOWN',
      'SHA-256 of the acquired message bytes — the evidence integrity anchor',
      input.analyzedAt,
    );
  }

  // Indicators already tied to an open incident are what an analyst wants to see
  // first, so they outrank raw severity ordering within a band.
  return iocs.sort((a, b) => {
    const byRisk = RISK_ORDER[b.risk] - RISK_ORDER[a.risk];
    if (byRisk !== 0) return byRisk;
    const byIncident = b.relatedIncidents.length - a.relatedIncidents.length;
    if (byIncident !== 0) return byIncident;
    return a.type.localeCompare(b.type) || a.value.localeCompare(b.value);
  });
}

/** Highest indicator risk present, for headline badges. */
export function peakIocRisk(iocs: Ioc[]): Severity {
  return iocs.reduce<Severity>((worst, ioc) => escalate(worst, ioc.risk), 'INFO');
}
