/**
 * Correlation orchestrator.
 *
 * Turns a `WireAnalysis` — from the FastAPI backend or the local browser engine,
 * which emit the same shape — plus the locally parsed message into the single
 * `EmailAnalysis` aggregate every view renders from.
 *
 * The pipeline runs in dependency order, because later stages genuinely need
 * earlier results:
 *
 *   headers → relay chain → authentication → infrastructure intel
 *           → indicators → signals → score → assessment → evidence
 *
 * Authentication depends on the relay chain because SPF has to be evaluated
 * against the address that actually connected to the recipient's mail server,
 * which is not the same as the origin address the geolocation view reports.
 * Conflating the two is the most common way header analysis goes wrong.
 */

import type {
  AnalysisSummary,
  DataOrigin,
  EmailAnalysis,
  EmailMetadata,
  EvidenceRecord,
  CustodyEntry,
  RelayHop,
} from '@/types';
import type { ParsedEmail } from '@/lib/emailParser';
import { header } from '@/lib/emailParser';
import { toPlainText } from '@/lib/languageAnalysis';
import { isReservedIp } from '../intel/geoDatabase';
import { lookupDomain } from '../intel/domainDatabase';
import { isDigestVerified } from '@/lib/hash';
import { addressOf, displayNameOf, domainOf, makeId } from '@/lib/format';
import { buildThreatScore, buildAssessment } from '../assess';
import type { WireAnalysis } from '../wire';
import { authAnomalies, buildHeaderForensics, correlateAuthentication } from './authentication';
import { reconstructRelayChain } from './relay';
import {
  buildAttachmentRecords,
  buildDomainIntel,
  buildIpIntel,
  buildUrlRecords,
} from './intel';
import type { AttachmentInput, DomainMention, IpMention, LinkMention } from './intel';
import { buildIocs } from './iocs';
import type { SightingLookup } from './iocs';
import { buildSignals } from './signals';
import { orgOf, sameOrganisation } from './shared';

export interface CorrelateInput {
  wire: WireAnalysis;
  /** Locally parsed message — supplies Reply-To, Return-Path and anchor text. */
  parsed: ParsedEmail;
  /** Verbatim acquired bytes, retained for the evidence record. */
  raw: string;
  filename: string;
  origin: DataOrigin;
  analyzedAt: string;
  /** SHA-256 over the acquired bytes. */
  contentHash: string;
  analystId: string;
  /** How the evidence was acquired, e.g. "Analyst upload". */
  acquisitionSource: string;
  /** Resolves prior sightings for indicators; omitted keeps correlation pure. */
  lookup?: SightingLookup;
}

export function correlate(input: CorrelateInput): EmailAnalysis {
  const { wire, parsed, analyzedAt } = input;

  /* 1 — Metadata. The backend returns the common fields; Reply-To and
   * Return-Path only exist in the local parse, so the two are merged. */
  const metadata = buildMetadata(wire, parsed);
  const fromDomain = domainOf(metadata.from);
  const recipientDomain = metadata.to ? orgOf(domainOf(metadata.to)) : null;

  /* 2 — Header forensics. `analyzedAt` anchors the Date plausibility check and
   * `parsed` supplies the notable-header rows. */
  const { headers, anomalies: headerAnomalies } = buildHeaderForensics(metadata, analyzedAt, parsed);

  /* 3 — Relay chain and origin. */
  const receivedRaw = wire.evidence.received_headers.map((entry) => entry.raw).filter(Boolean);
  const { hops, origin: originAssessment, timestampAnomalies } = reconstructRelayChain(
    receivedRaw,
    wire.geolocation.sender_locations,
  );

  /* 4 — Authentication. SPF is evaluated at the boundary: the last external hop
   * that handed the message to the recipient's infrastructure. */
  const boundary = boundaryIp(hops, recipientDomain) ?? originAssessment.observedSourceIp;
  const auth = correlateAuthentication({
    fromDomain,
    dkimSignature: wire.evidence.dkim_signature,
    returnPathDomain: metadata.returnPath ? domainOf(metadata.returnPath) : null,
    senderDomainRecord: fromDomain ? lookupDomain(fromDomain) : null,
    observedIp: boundary,
    wireForensics: wire.forensics ?? null,
    origin: input.origin,
  });

  const allAnomalies = [...headerAnomalies, ...authAnomalies(auth)];

  /* 5 — Infrastructure intelligence. */
  const links = collectLinks(parsed, wire);
  const urls = buildUrlRecords(links, [fromDomain, recipientDomain].filter((d): d is string => Boolean(d)));

  const domainIntel = buildDomainIntel(
    collectDomainMentions(metadata, urls.map((url) => url.host), hops),
    analyzedAt,
    recipientDomain ? [recipientDomain] : [],
  );

  const ipIntel = buildIpIntel(
    collectIpMentions(hops, wire),
    analyzedAt,
    domainIntel.map((entry) => entry.domain),
  );

  const attachments = buildAttachmentRecords(collectAttachments(wire, parsed));

  /* 6 — Indicators. */
  const iocs = buildIocs({
    ipIntel,
    domainIntel,
    urls,
    emails: collectEmailMentions(metadata, wire),
    attachments,
    messageId: metadata.messageId,
    contentHash: input.contentHash,
    analyzedAt,
    ...(input.lookup ? { lookup: input.lookup } : {}),
  });

  /* 7 — Signals, score, assessment. */
  const bodyText = parsed.textBody || toPlainText(parsed.htmlBody);
  const signals = buildSignals({
    metadata,
    bodyText,
    auth,
    hops,
    origin: originAssessment,
    urls,
    attachments,
    domainIntel,
    ipIntel,
    headerAnomalies: allAnomalies,
    timestampAnomalies,
    wire,
    recipientDomain,
  });

  const score = buildThreatScore(signals);
  const assessment = buildAssessment(signals, score);

  /* 8 — Evidence and chain of custody. */
  const evidence = buildEvidence(input, score.level);

  const warnings: string[] = [];
  if (wire.storage_warning) warnings.push(wire.storage_warning);
  if (!isDigestVerified(input.contentHash)) {
    warnings.push(
      'The evidence digest could not be computed in this browser context, so integrity is recorded as unverified.',
    );
  }
  if (hops.length === 0) {
    warnings.push('No Received headers were present, so no relay path or origin could be reconstructed.');
  }

  return {
    id: makeId('AN'),
    backendId: wire.analysis_id ?? null,
    origin: input.origin,
    analyzedAt,
    filename: input.filename,
    metadata,
    headers,
    rawHeaders: parsed.rawHeaderBlock,
    bodyPreview: wire.evidence.body_preview || bodyText.slice(0, 500),
    score,
    assessment,
    authentication: auth.summary,
    relayChain: hops,
    originAssessment,
    iocs,
    urls,
    attachments,
    domainIntel,
    ipIntel,
    evidence,
    campaignId: null,
    warnings,
  };
}

/** Compact row shape for lists, tables and dashboard feeds. */
export function summarise(analysis: EmailAnalysis): AnalysisSummary {
  return {
    id: analysis.id,
    backendId: analysis.backendId,
    origin: analysis.origin,
    sender: analysis.metadata.from,
    subject: analysis.metadata.subject,
    score: analysis.score.total,
    level: analysis.score.level,
    classification: analysis.assessment.classification,
    country: analysis.originAssessment.estimatedLocation?.country ?? null,
    analyzedAt: analysis.analyzedAt,
  };
}

/* ------------------------------------------------------------------ */
/* Metadata                                                            */
/* ------------------------------------------------------------------ */

function buildMetadata(wire: WireAnalysis, parsed: ParsedEmail): EmailMetadata {
  const from = wire.evidence.from || header(parsed, 'from') || '';
  return {
    from,
    fromDisplayName: displayNameOf(from),
    to: wire.evidence.to || header(parsed, 'to') || '',
    // Only the local parse recovers these; the backend does not return them.
    replyTo: header(parsed, 'reply-to'),
    returnPath: header(parsed, 'return-path'),
    subject: wire.evidence.subject || header(parsed, 'subject') || '',
    date: wire.evidence.date || header(parsed, 'date') || null,
    messageId: wire.evidence.message_id || header(parsed, 'message-id') || null,
  };
}

/* ------------------------------------------------------------------ */
/* Boundary address                                                    */
/* ------------------------------------------------------------------ */

/**
 * The address that connected to the recipient's mail infrastructure — the hop
 * closest to the recipient that is still external to it. This is the IP a
 * receiving MTA evaluates SPF against, and it is frequently *not* the origin
 * address: a message relayed through a second host fails SPF at the boundary
 * even when the origin sits inside the sender's own published range.
 */
function boundaryIp(hops: RelayHop[], recipientDomain: string | null): string | null {
  const external = hops.filter(
    (hop) =>
      hop.ip !== null &&
      !isReservedIp(hop.ip) &&
      !hop.isDestination &&
      !(recipientDomain && sameOrganisation(hop.hostname, recipientDomain)),
  );
  if (external.length === 0) return null;
  // Highest index is closest to the recipient.
  return external[external.length - 1].ip;
}

/* ------------------------------------------------------------------ */
/* Collectors                                                          */
/* ------------------------------------------------------------------ */

function collectLinks(parsed: ParsedEmail, wire: WireAnalysis): LinkMention[] {
  const mentions: LinkMention[] = parsed.links.map((link) => ({
    url: link.url,
    anchorText: link.anchorText,
  }));

  // The backend extracts URLs from the whole message, including places the
  // client-side anchor walk does not reach. Add anything it found that is new.
  const known = new Set(mentions.map((mention) => mention.url));
  for (const url of wire.threat_indicators.urls) {
    if (!known.has(url)) {
      known.add(url);
      mentions.push({ url, anchorText: null });
    }
  }
  return mentions;
}

function collectDomainMentions(
  metadata: EmailMetadata,
  urlHosts: string[],
  hops: RelayHop[],
): DomainMention[] {
  const mentions: DomainMention[] = [];

  const push = (value: string | null | undefined, role: string): void => {
    if (!value) return;
    const domain = value.includes('@') ? domainOf(value) : value;
    if (domain && domain.includes('.')) mentions.push({ domain, role });
  };

  push(metadata.from, 'Sender domain (From)');
  push(metadata.to, 'Recipient domain (To)');
  push(metadata.replyTo, 'Reply-To domain');
  push(metadata.returnPath, 'Envelope Return-Path domain');
  for (const host of urlHosts) push(host, 'Link host');
  for (const hop of hops) {
    if (hop.hostname) push(hop.hostname, `Relay hop ${hop.index} hostname`);
  }

  return mentions;
}

function collectIpMentions(hops: RelayHop[], wire: WireAnalysis): IpMention[] {
  const mentions: IpMention[] = [];

  for (const hop of hops) {
    if (!hop.ip) continue;
    mentions.push({
      ip: hop.ip,
      role: hop.isDestination ? 'Recipient gateway' : `Relay hop ${hop.index}`,
      hop,
    });
  }

  const known = new Set(mentions.map((mention) => mention.ip));
  for (const ip of wire.threat_indicators.ip_addresses) {
    if (!known.has(ip)) {
      known.add(ip);
      mentions.push({ ip, role: 'Referenced in message content' });
    }
  }

  return mentions;
}

function collectEmailMentions(
  metadata: EmailMetadata,
  wire: WireAnalysis,
): { address: string; source: string }[] {
  const mentions: { address: string; source: string }[] = [];

  const push = (value: string | null | undefined, source: string): void => {
    const address = value ? addressOf(value) : '';
    if (address && address.includes('@')) mentions.push({ address, source });
  };

  push(metadata.from, 'From header');
  push(metadata.replyTo, 'Reply-To header');
  push(metadata.returnPath, 'Envelope Return-Path');
  push(metadata.to, 'Recipient (To header)');

  const known = new Set(mentions.map((mention) => mention.address.toLowerCase()));
  for (const address of wire.threat_indicators.emails) {
    const normalised = addressOf(address).toLowerCase();
    if (normalised && !known.has(normalised)) {
      known.add(normalised);
      mentions.push({ address: addressOf(address), source: 'Extracted from message body' });
    }
  }

  return mentions;
}

function collectAttachments(wire: WireAnalysis, parsed: ParsedEmail): AttachmentInput[] {
  // Prefer the wire list: its hashes are computed over the real decoded bytes.
  // The local parse contributes the declared MIME type, which the wire omits.
  const parsedByName = new Map(
    parsed.parts
      .filter((part) => part.filename)
      .map((part) => [part.filename as string, part]),
  );

  const records: AttachmentInput[] = wire.attachments.map((attachment) => ({
    filename: attachment.filename,
    sizeBytes: attachment.size,
    sha256: attachment.hash,
    mimeType: parsedByName.get(attachment.filename)?.contentType ?? null,
  }));

  const known = new Set(records.map((record) => record.filename));
  for (const [filename, part] of parsedByName) {
    if (known.has(filename)) continue;
    records.push({
      filename,
      sizeBytes: part.sizeBytes,
      // No digest is claimed for a part the analysis service did not hash.
      sha256: '',
      mimeType: part.contentType,
    });
  }

  return records;
}

/* ------------------------------------------------------------------ */
/* Evidence and chain of custody                                       */
/* ------------------------------------------------------------------ */

function buildEvidence(input: CorrelateInput, level: string): EvidenceRecord {
  const verified = isDigestVerified(input.contentHash);
  const sizeBytes = new TextEncoder().encode(input.raw).length;

  const custody: CustodyEntry[] = [
    {
      at: input.analyzedAt,
      actor: input.analystId,
      action: 'ACQUIRED',
      detail: `${input.acquisitionSource} — ${input.filename} (${sizeBytes} bytes) ingested for analysis.`,
      hashAfter: input.contentHash,
    },
    {
      at: input.analyzedAt,
      actor: verified ? 'SentinelTrace evidence service' : 'SentinelTrace evidence service (degraded)',
      action: 'HASHED',
      detail: verified
        ? 'SHA-256 computed over the acquired bytes via Web Crypto and recorded as the integrity anchor.'
        : 'SHA-256 could not be computed in this browser context; integrity is recorded as unverified.',
      hashAfter: input.contentHash,
    },
    {
      at: input.analyzedAt,
      actor: 'SentinelTrace correlation engine',
      action: 'ANALYSED',
      detail: `Forensic correlation completed against the ${
        input.origin === 'LIVE_BACKEND' ? 'live analysis service' : 'local analysis engine'
      }. Threat level assessed as ${level}. The source bytes were read only and were not modified.`,
      hashAfter: input.contentHash,
    },
  ];

  return {
    evidenceId: makeId('EVD'),
    sha256: input.contentHash,
    sizeBytes,
    acquiredAt: input.analyzedAt,
    source: input.acquisitionSource,
    analystId: input.analystId,
    integrity: verified ? 'VERIFIED' : 'UNVERIFIED',
    custody,
  };
}
