/**
 * Infrastructure intelligence correlation.
 *
 * Builds the domain, IP, URL and attachment intelligence records the
 * Infrastructure and Threat Intelligence views render.
 *
 * All lookups resolve against the bundled offline datasets in `services/intel/`.
 * That is a deliberate constraint, not a shortcut: the demonstration has to run
 * with no external API reachable. Where a dataset has nothing to say, the field
 * stays `null` and a note records that registration or network data was
 * unavailable — a stated unknown is useful to an analyst, an invented value is
 * actively harmful.
 *
 * Blacklist states likewise come from the bundled feed snapshot rather than a
 * live query, and are labelled as such in the UI.
 */

import type {
  AttachmentRecord,
  DomainIntelligence,
  IpIntelligence,
  RelayHop,
  Reputation,
  Severity,
  UrlRecord,
} from '@/types';
import { ageInDays, lookupDomain, unresolvedDomainRecord } from '../intel/domainDatabase';
import { anonymiserKind, isReservedIp, lookupNetwork } from '../intel/geoDatabase';
import { detectLookalike, isProtectedBrand, isUrlShortener } from '@/lib/lookalike';
import { escalate, hostFromText, hostFromUrl, orgOf, sameOrganisation, unique } from './shared';

/* ------------------------------------------------------------------ */
/* Shared risk helpers                                                 */
/* ------------------------------------------------------------------ */

const REPUTATION_RANK: Record<Reputation, number> = {
  CLEAN: 0,
  UNKNOWN: 1,
  SUSPICIOUS: 2,
  MALICIOUS: 3,
};

/** Raise a reputation only when the candidate is genuinely worse. */
function worsen(current: Reputation, candidate: Reputation): Reputation {
  return REPUTATION_RANK[candidate] > REPUTATION_RANK[current] ? candidate : current;
}

function riskFromReputation(reputation: Reputation): Severity {
  switch (reputation) {
    case 'MALICIOUS':
      return 'CRITICAL';
    case 'SUSPICIOUS':
      return 'HIGH';
    case 'CLEAN':
      return 'INFO';
    default:
      return 'LOW';
  }
}

function listedSources(blacklists: { source: string; listed: boolean }[]): string[] {
  return blacklists.filter((entry) => entry.listed).map((entry) => entry.source);
}

/* ------------------------------------------------------------------ */
/* Domain intelligence                                                 */
/* ------------------------------------------------------------------ */

/** A domain observed in the message, with where it was seen. */
export interface DomainMention {
  domain: string;
  /** Human-readable provenance, e.g. "Sender domain", "Link host". */
  role: string;
}

/**
 * Build one intelligence record per distinct domain. `extraTargets` seeds the
 * lookalike comparison with domains specific to this message — chiefly the
 * recipient's own domain, so impersonation of the victim organisation is caught
 * even though it is not a globally protected brand.
 */
export function buildDomainIntel(
  mentions: DomainMention[],
  analyzedAt: string,
  extraTargets: string[] = [],
): DomainIntelligence[] {
  const byDomain = new Map<string, string[]>();
  for (const mention of mentions) {
    const domain = mention.domain.trim().toLowerCase().replace(/^www\./, '');
    if (!domain || !domain.includes('.')) continue;
    const roles = byDomain.get(domain) ?? [];
    if (!roles.includes(mention.role)) roles.push(mention.role);
    byDomain.set(domain, roles);
  }

  return [...byDomain.entries()]
    .map(([domain, roles]) => buildOneDomain(domain, roles, analyzedAt, extraTargets))
    .sort((a, b) => REPUTATION_RANK[b.reputation] - REPUTATION_RANK[a.reputation]);
}

function buildOneDomain(
  domain: string,
  roles: string[],
  analyzedAt: string,
  extraTargets: string[],
): DomainIntelligence {
  const curated = lookupDomain(domain);
  const record =
    curated ??
    unresolvedDomainRecord(
      'No registration or DNS intelligence is bundled for this domain, so registrar, age and policy data could not be resolved offline.',
    );

  const ageDays = ageInDays(record.createdAt, analyzedAt);
  // A brand is not a lookalike of itself, and comparing it against the protected
  // list only produces noise.
  const match = isProtectedBrand(domain)
    ? null
    : detectLookalike(domain, extraTargets.filter((target) => target !== domain));

  let reputation = record.reputation;
  if (match && match.similarity >= 80) reputation = worsen(reputation, 'SUSPICIOUS');

  const listed = listedSources(record.blacklists);
  if (listed.length > 0) reputation = worsen(reputation, 'SUSPICIOUS');

  let risk = riskFromReputation(reputation);
  if (match) risk = escalate(risk, match.similarity >= 85 ? 'CRITICAL' : 'HIGH');
  if (listed.length > 0) risk = escalate(risk, 'HIGH');
  if (ageDays !== null && ageDays <= 30) risk = escalate(risk, 'MEDIUM');

  const notes: string[] = [`Observed in this message as: ${roles.join(', ')}.`, ...record.notes];

  if (match) notes.push(match.explanation);
  if (listed.length > 0) {
    notes.push(`Listed in the bundled reputation snapshot by ${listed.join(', ')}.`);
  }

  // Structural observations are only added when no curated narrative already
  // covers them, so the note list does not repeat itself.
  if (!curated) {
    if (ageDays !== null && ageDays <= 30) {
      notes.push(
        `Registration is ${ageDays} day${ageDays === 1 ? '' : 's'} old at time of analysis. Domains younger than a month are disproportionately represented in payment fraud and credential theft.`,
      );
    }
    if (!record.spfRecord) {
      notes.push('No SPF policy was resolved, so unauthorised hosts sending as this domain cannot be ruled out.');
    }
    if (!record.dmarcRecord) {
      notes.push('No DMARC policy was resolved, so receivers have no published instruction for handling failures.');
    }
    if (record.mxRecords.length === 0) {
      notes.push('No MX records were resolved; the domain may be unable to receive mail, which is common for hosting-only infrastructure.');
    }
  }

  return {
    domain,
    registrar: record.registrar,
    createdAt: record.createdAt,
    ageDays,
    nameservers: record.nameservers,
    mxRecords: record.mxRecords,
    spfRecord: record.spfRecord,
    dmarcRecord: record.dmarcRecord,
    reputation,
    risk,
    ...(match
      ? { similarity: { comparedTo: match.target, score: match.similarity, technique: match.technique } }
      : {}),
    blacklists: record.blacklists,
    notes: unique(notes),
  };
}

/* ------------------------------------------------------------------ */
/* IP intelligence                                                     */
/* ------------------------------------------------------------------ */

/** Reputation feeds carried in the bundled snapshot. */
const IP_FEEDS = ['Spamhaus ZEN', 'Barracuda BRBL', 'SORBS', 'AbuseIPDB', 'Blocklist.de'];

function ipBlacklists(reputation: Reputation, anonymiser: 'TOR' | 'VPN' | null): { source: string; listed: boolean }[] {
  const listed = new Set<string>();
  if (reputation === 'MALICIOUS') {
    listed.add('Spamhaus ZEN');
    listed.add('AbuseIPDB');
    listed.add('Blocklist.de');
  } else if (reputation === 'SUSPICIOUS') {
    listed.add('AbuseIPDB');
  }
  if (anonymiser === 'TOR') listed.add('Spamhaus ZEN');
  return IP_FEEDS.map((source) => ({ source, listed: listed.has(source) }));
}

export interface IpMention {
  ip: string;
  role: string;
  /** The relay hop this address came from, when it came from the chain. */
  hop?: RelayHop;
}

export function buildIpIntel(
  mentions: IpMention[],
  analyzedAt: string,
  linkedDomains: string[] = [],
): IpIntelligence[] {
  const byIp = new Map<string, { roles: string[]; hop?: RelayHop }>();
  for (const mention of mentions) {
    const ip = mention.ip.trim();
    if (!ip) continue;
    const existing = byIp.get(ip) ?? { roles: [] };
    if (!existing.roles.includes(mention.role)) existing.roles.push(mention.role);
    // Keep the first hop we were given; hops carry parsed timestamps and hostnames.
    if (mention.hop && !existing.hop) existing.hop = mention.hop;
    byIp.set(ip, existing);
  }

  return [...byIp.entries()]
    .map(([ip, entry]) => buildOneIp(ip, entry.roles, entry.hop, analyzedAt, linkedDomains))
    .sort((a, b) => REPUTATION_RANK[b.reputation] - REPUTATION_RANK[a.reputation]);
}

function buildOneIp(
  ip: string,
  roles: string[],
  hop: RelayHop | undefined,
  analyzedAt: string,
  linkedDomains: string[],
): IpIntelligence {
  const reserved = isReservedIp(ip);
  const network = reserved ? null : lookupNetwork(ip);
  const anonymiser = reserved ? null : anonymiserKind(ip);

  let reputation: Reputation = network?.reputation ?? 'UNKNOWN';
  if (anonymiser === 'TOR') reputation = worsen(reputation, 'MALICIOUS');
  else if (anonymiser === 'VPN') reputation = worsen(reputation, 'SUSPICIOUS');

  const blacklists = reserved ? [] : ipBlacklists(reputation, anonymiser);

  let risk = reserved ? 'INFO' : riskFromReputation(reputation);
  if (anonymiser) risk = escalate(risk, anonymiser === 'TOR' ? 'CRITICAL' : 'HIGH');

  const notes: string[] = [`Observed in this message as: ${roles.join(', ')}.`];

  if (reserved) {
    notes.push(
      'Reserved or private address space. Valid for internal hand-offs inside a mail platform, but it can never be the public source of an inbound message.',
    );
  } else if (!network) {
    notes.push(
      'No network record is bundled for this address, so geolocation, ISP and ASN attribution could not be resolved offline.',
    );
  }
  if (anonymiser === 'TOR') {
    notes.push('Address falls within a published Tor exit range. Traffic leaving this node conceals its true source.');
  }
  if (anonymiser === 'VPN') {
    notes.push('Address belongs to a commercial VPN range, so it marks an egress point rather than the originating host.');
  }
  if (network && network.hostingType === 'DATACENTER') {
    notes.push('Hosted in datacenter address space — consistent with rented infrastructure rather than a residential sender.');
  }
  const listed = listedSources(blacklists);
  if (listed.length > 0) {
    notes.push(`Listed in the bundled reputation snapshot by ${listed.join(', ')}.`);
  }

  const associated = unique(
    [orgOf(hop?.hostname ?? null), ...linkedDomains.map((domain) => orgOf(domain))].filter(
      (value): value is string => value !== null,
    ),
  );

  return {
    ip,
    hostname: hop?.hostname ?? null,
    geo: network?.geo ?? hop?.geo ?? null,
    isp: network?.isp ?? hop?.isp ?? null,
    organization: network?.organization ?? null,
    asn: network?.asn ?? hop?.asn ?? null,
    asnOwner: network?.asnOwner ?? null,
    reputation,
    risk,
    hostingType: network?.hostingType ?? 'UNKNOWN',
    blacklists,
    // The only sighting this platform can honestly claim is the one in front of
    // it: the hop timestamp, falling back to the analysis time.
    firstSeen: hop?.timestamp ?? analyzedAt,
    lastSeen: analyzedAt,
    associatedDomains: associated,
    notes,
  };
}

/* ------------------------------------------------------------------ */
/* URLs                                                                */
/* ------------------------------------------------------------------ */

export interface LinkMention {
  url: string;
  anchorText: string | null;
}

/** Path fragments that suggest a credential or payment capture page. */
const SENSITIVE_PATH = /(login|signin|verify|validate|secure|account|password|credential|payment|invoice|billing|wire|remit|update)/i;

/**
 * Build URL records. `trustedDomains` are the organisations legitimately involved
 * in the conversation (sender and recipient); a link leaving those is not
 * automatically malicious, but a link whose anchor text *claims* one of them
 * while pointing elsewhere is a deliberate disguise.
 */
export function buildUrlRecords(links: LinkMention[], trustedDomains: string[] = []): UrlRecord[] {
  const seen = new Map<string, UrlRecord>();

  for (const link of links) {
    const url = link.url.trim();
    if (!url) continue;

    const host = hostFromUrl(url);
    if (!host) continue;

    const existing = seen.get(url);
    if (existing) {
      // Same destination reached from several anchors — keep the worse case.
      if (!existing.mismatchedAnchor && link.anchorText) {
        const claimed = hostFromText(link.anchorText);
        if (claimed && !sameOrganisation(claimed, host)) {
          seen.set(url, {
            ...existing,
            mismatchedAnchor: true,
            risk: escalate(existing.risk, 'HIGH'),
            note: `Anchor text advertises ${claimed} while the link resolves to ${host}. ${existing.note ?? ''}`.trim(),
          });
        }
      }
      continue;
    }

    seen.set(url, buildOneUrl(url, host, link.anchorText, trustedDomains));
  }

  return [...seen.values()].sort((a, b) => REPUTATION_RANK[b.reputation] - REPUTATION_RANK[a.reputation]);
}

function buildOneUrl(
  url: string,
  host: string,
  anchorText: string | null,
  trustedDomains: string[],
): UrlRecord {
  const record = lookupDomain(host);
  const isIpLiteral = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  const shortener = isUrlShortener(host);
  const match = isProtectedBrand(host) ? null : detectLookalike(host, trustedDomains);

  let reputation: Reputation = record?.reputation ?? 'UNKNOWN';
  if (match && match.similarity >= 80) reputation = worsen(reputation, 'SUSPICIOUS');
  if (shortener) reputation = worsen(reputation, 'SUSPICIOUS');

  let risk = riskFromReputation(reputation);
  if (match) risk = escalate(risk, match.similarity >= 85 ? 'CRITICAL' : 'HIGH');
  if (isIpLiteral) risk = escalate(risk, 'HIGH');
  if (shortener) risk = escalate(risk, 'MEDIUM');

  // A claimed destination that differs from the real one is the clearest
  // deception signal available in a link.
  const claimed = anchorText ? hostFromText(anchorText) : null;
  const mismatchedAnchor = claimed !== null && !sameOrganisation(claimed, host);
  if (mismatchedAnchor) risk = escalate(risk, 'HIGH');

  const notes: string[] = [];
  if (mismatchedAnchor && claimed) {
    notes.push(`Anchor text advertises ${claimed} while the link resolves to ${host}.`);
  }
  if (match) notes.push(match.explanation);
  if (isIpLiteral) {
    notes.push('The link targets a bare IP address rather than a hostname, bypassing any domain reputation.');
  }
  if (shortener) {
    notes.push('Shortened link — the final destination cannot be determined without following the redirect.');
  }
  if (!url.toLowerCase().startsWith('https://')) {
    notes.push('Link is not served over HTTPS, so any data submitted would travel unencrypted.');
  }
  if (SENSITIVE_PATH.test(url)) {
    notes.push('The path suggests a credential, payment or invoice capture page.');
    risk = escalate(risk, 'MEDIUM');
  }
  if (record && record.reputation === 'MALICIOUS') {
    notes.push('The host domain is flagged as malicious in the bundled reputation snapshot.');
  }

  return {
    url,
    displayText: anchorText,
    host,
    risk,
    reputation,
    mismatchedAnchor,
    note: notes.length > 0 ? notes.join(' ') : null,
  };
}

/* ------------------------------------------------------------------ */
/* Attachments                                                         */
/* ------------------------------------------------------------------ */

/** Extensions that execute or can carry an executable payload. */
const EXECUTABLE = new Set([
  'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'js', 'jse',
  'wsf', 'wsh', 'msi', 'msp', 'hta', 'cpl', 'jar', 'lnk', 'reg', 'dll', 'iso', 'img',
]);

/** Formats that routinely carry macros or embedded objects. */
const MACRO_CAPABLE = new Set(['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'xlam', 'doc', 'xls', 'ppt', 'rtf']);

/** Containers that hide their contents from inspection at the gateway. */
const ARCHIVE = new Set(['zip', 'rar', '7z', 'gz', 'tar', 'bz2', 'cab', 'ace']);

export interface AttachmentInput {
  filename: string;
  sizeBytes: number;
  sha256: string;
  mimeType: string | null;
}

export function buildAttachmentRecords(attachments: AttachmentInput[]): AttachmentRecord[] {
  return attachments.map((attachment) => {
    const name = attachment.filename.trim();
    const segments = name.toLowerCase().split('.');
    const extension = segments.length > 1 ? segments[segments.length - 1] : '';
    const notes: string[] = [];
    let risk: Severity = 'INFO';

    if (EXECUTABLE.has(extension)) {
      risk = escalate(risk, 'CRITICAL');
      notes.push(`\`.${extension}\` is directly executable or loads code, so opening it would run attacker-supplied instructions.`);
    } else if (MACRO_CAPABLE.has(extension)) {
      risk = escalate(risk, 'HIGH');
      notes.push(`\`.${extension}\` can carry macros or embedded objects, a long-standing delivery route for malware.`);
    } else if (ARCHIVE.has(extension)) {
      risk = escalate(risk, 'MEDIUM');
      notes.push(`\`.${extension}\` is a container, so its contents were not inspected and may differ from what the name suggests.`);
    }

    // `invoice.pdf.exe` renders as a PDF in clients that hide known extensions.
    if (segments.length > 2) {
      const inner = segments[segments.length - 2];
      if (['pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'png', 'txt'].includes(inner)) {
        risk = escalate(risk, 'CRITICAL');
        notes.push(
          `Double extension: the name ends \`.${inner}.${extension}\`, which displays as a harmless ${inner.toUpperCase()} in clients that hide known extensions.`,
        );
      }
    }

    if (attachment.mimeType && extension) {
      const mime = attachment.mimeType.toLowerCase();
      const claimsPdf = mime.includes('pdf');
      if (claimsPdf && extension !== 'pdf') {
        risk = escalate(risk, 'HIGH');
        notes.push(`Declared content type ${attachment.mimeType} contradicts the \`.${extension}\` extension.`);
      }
    }

    if (attachment.sizeBytes === 0) {
      notes.push('Attachment decoded to zero bytes — it may be a placeholder or have been stripped in transit.');
    }

    return {
      filename: name,
      sizeBytes: attachment.sizeBytes,
      sha256: attachment.sha256,
      mimeType: attachment.mimeType,
      risk,
      note: notes.length > 0 ? notes.join(' ') : null,
    };
  });
}
