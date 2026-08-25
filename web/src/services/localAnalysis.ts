/**
 * Offline analysis path.
 *
 * Produces the same payload shape the FastAPI backend returns, computed entirely
 * in the browser from the raw message. This is what makes the platform usable
 * when the backend is unreachable — and it is what allows the SIH demonstration
 * to run with no external services at all.
 *
 * The scoring here intentionally mirrors `backend/threat_intelligence.py` so that
 * a message scored offline lands in the same band it would score through the
 * live service. Anything the browser cannot know (live DNS, WHOIS, IP
 * reputation feeds) comes from the curated tables in `services/intel`, and is
 * reported as unresolved when there is no entry.
 */

import { header, headerAll, hostOf, parseEmail, type ParsedEmail } from '@/lib/emailParser';
import { parseReceivedHeader } from '@/lib/receivedParser';
import { parseDkimSignature } from '@/lib/authEval';
import { domainOf, pseudoSha256 } from '@/lib/format';
import { isUrlShortener } from '@/lib/lookalike';
import { anonymiserKind, isReservedIp, lookupNetwork } from './intel/geoDatabase';
import { lookupDomain } from './intel/domainDatabase';
import type {
  WireAnalysis,
  WireAttachment,
  WireAuthentication,
  WireDkim,
  WireDmarc,
  WireHeaderChain,
  WireSenderLocation,
  WireSpf,
  WireSpoofing,
  WireThreatAssessment,
} from './wire';

const IPV4_GLOBAL = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
const EMAIL_GLOBAL = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

const SUSPICIOUS_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'short.link'];

const DANGEROUS_EXTENSIONS = [
  '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
  '.jar', '.zip', '.rar', '.7z', '.hta', '.lnk', '.iso', '.img',
  '.ps1', '.msi', '.docm', '.xlsm', '.pptm', '.vbe', '.wsf',
];

export interface LocalAnalysisParams {
  raw: string;
  filename: string;
  /** Real SHA-256 of the evidence bytes, computed by the caller. */
  contentHash: string;
  analyzedAt: string;
}

export function analyseLocally(params: LocalAnalysisParams): WireAnalysis {
  const parsed = parseEmail(params.raw);

  const from = header(parsed, 'from') ?? '';
  const senderDomain = domainOf(from) || null;

  const receivedRaw = headerAll(parsed, 'received');
  const relayIps = collectRelayIps(parsed, receivedRaw);
  const senderLocations = relayIps.map(toSenderLocation);

  const urls = parsed.links.map((link) => link.url);
  const bodyText = `${parsed.textBody}\n${parsed.htmlBody}`;
  const emails = unique(matchAll(`${parsed.rawHeaderBlock}\n${bodyText}`, EMAIL_GLOBAL)).filter(
    (address) => address.toLowerCase() !== from.toLowerCase(),
  );
  const ipAddresses = unique(matchAll(params.raw, IPV4_GLOBAL));
  const attachments = collectAttachments(parsed);

  const evidence = {
    from,
    to: header(parsed, 'to') ?? '',
    subject: header(parsed, 'subject') ?? '',
    date: header(parsed, 'date') ?? '',
    message_id: header(parsed, 'message-id') ?? '',
    content_hash: params.contentHash,
    authentication_results: header(parsed, 'authentication-results') ?? '',
    dkim_signature: header(parsed, 'dkim-signature') ?? '',
    received_headers: receivedRaw.map((raw) => ({ raw })),
    body_preview: (parsed.textBody || parsed.htmlBody).slice(0, 500),
    filename: params.filename,
  };

  const draft = {
    evidence,
    geolocation: { sender_locations: senderLocations, location_count: senderLocations.length },
    threat_indicators: { urls, ip_addresses: ipAddresses, emails },
    attachments,
  };

  return {
    ...draft,
    threat_assessment: scoreLocally(draft),
    forensics: {
      authentication: buildAuthentication(from, senderDomain, evidence.dkim_signature),
      spoofing_analysis: detectSpoofing(from, senderDomain, emails, evidence.subject),
      header_chain: analyseHeaderChain(receivedRaw),
    },
    analysis_id: null,
    storage_status: 'not_persisted',
    storage_warning:
      'Analysed locally in the browser; this result was not written to the case database because the analysis service was not reachable.',
  };
}

/* ------------------------------------------------------------------ */
/* Relay IPs and geolocation                                           */
/* ------------------------------------------------------------------ */

function collectRelayIps(parsed: ParsedEmail, receivedRaw: string[]): string[] {
  const ips: string[] = [];

  for (const raw of receivedRaw) {
    const hop = parseReceivedHeader(raw);
    if (hop.fromIp && !ips.includes(hop.fromIp)) ips.push(hop.fromIp);
  }

  // Some gateways record the true client address in a dedicated header.
  for (const name of ['x-originating-ip', 'x-sender-ip', 'x-client-ip', 'x-real-ip']) {
    const value = header(parsed, name);
    if (!value) continue;
    const found = value.match(IPV4_GLOBAL);
    if (found) {
      for (const ip of found) if (!ips.includes(ip)) ips.push(ip);
    }
  }

  return ips;
}

function toSenderLocation(ip: string): WireSenderLocation {
  if (isReservedIp(ip)) {
    return {
      ip,
      type: 'private',
      warning: 'Reserved or private address space — cannot be geolocated and cannot be an internet-facing origin.',
    };
  }

  const network = lookupNetwork(ip);
  if (!network) {
    return {
      ip,
      error: 'No curated network intelligence for this address, and no live geolocation provider is reachable.',
    };
  }

  const anonymiser = anonymiserKind(ip);
  return {
    ip,
    country: network.geo.country,
    country_code: network.geo.countryCode,
    region: network.geo.region,
    city: network.geo.city,
    latitude: network.geo.latitude,
    longitude: network.geo.longitude,
    isp: network.isp,
    organization: network.organization,
    threat_level:
      network.reputation === 'MALICIOUS' || anonymiser === 'TOR'
        ? 'high'
        : network.reputation === 'SUSPICIOUS' || anonymiser === 'VPN'
          ? 'medium'
          : 'low',
  };
}

/* ------------------------------------------------------------------ */
/* Attachments                                                         */
/* ------------------------------------------------------------------ */

function collectAttachments(parsed: ParsedEmail): WireAttachment[] {
  return parsed.parts
    .filter((part) => part.filename !== null)
    .map((part) => ({
      filename: part.filename as string,
      size: part.sizeBytes,
      // Attachment bytes are not decoded in the browser; the digest is derived
      // from the encoded part so it is stable, and flagged as derived in the UI.
      hash: pseudoSha256(`${part.filename}:${part.sizeBytes}:${part.contentType}`),
    }));
}

/* ------------------------------------------------------------------ */
/* Authentication (mirrors advanced_forensics.py)                      */
/* ------------------------------------------------------------------ */

function buildAuthentication(
  sender: string,
  senderDomain: string | null,
  dkimSignature: string,
): WireAuthentication {
  const authentication: WireAuthentication = {
    sender,
    sender_domain: senderDomain,
    dkim: null,
    spf: null,
    dmarc: null,
    overall_trust_score: 0,
  };

  if (!senderDomain) return authentication;

  authentication.dkim = validateDkim(dkimSignature, senderDomain);
  authentication.spf = checkSpf(senderDomain);
  authentication.dmarc = checkDmarc(senderDomain);

  let trust = 50;
  if (authentication.dkim.valid) trust += 20;
  if (authentication.spf.found) trust += 15;
  if (authentication.dmarc.found) trust += 15;
  authentication.overall_trust_score = Math.min(100, trust);

  return authentication;
}

function validateDkim(signature: string, senderDomain: string): WireDkim {
  if (!signature) {
    return { valid: false, status: 'missing', message: 'No DKIM signature found' };
  }
  const tags = parseDkimSignature(signature);
  if (tags.domain && tags.domain !== senderDomain) {
    return {
      valid: false,
      status: 'domain_mismatch',
      message: `DKIM domain '${tags.domain}' doesn't match sender domain '${senderDomain}'`,
      severity: 'high',
    };
  }
  return { valid: true, status: 'signed', message: 'Email is DKIM signed' };
}

function checkSpf(senderDomain: string): WireSpf {
  const record = lookupDomain(senderDomain);
  if (record?.spfRecord) {
    return { found: true, records: [record.spfRecord], status: 'pass', message: 'Valid SPF record found' };
  }
  if (record) {
    return {
      found: false,
      status: 'no_spf',
      message: `No SPF record found for ${senderDomain}`,
      severity: 'medium',
    };
  }
  return {
    found: false,
    status: 'dns_unavailable',
    message: `No DNS resolver available offline and no curated record for ${senderDomain}`,
    severity: 'low',
  };
}

function checkDmarc(senderDomain: string): WireDmarc {
  const record = lookupDomain(senderDomain);
  if (record?.dmarcRecord) {
    const policy = /p=reject/i.test(record.dmarcRecord)
      ? 'reject'
      : /p=quarantine/i.test(record.dmarcRecord)
        ? 'quarantine'
        : 'none';
    return {
      found: true,
      policy,
      records: [record.dmarcRecord],
      status: 'pass',
      message: `DMARC policy: ${policy}`,
    };
  }
  if (record) {
    return { found: false, status: 'no_dmarc', message: `No DMARC record for ${senderDomain}`, severity: 'low' };
  }
  return {
    found: false,
    status: 'dns_unavailable',
    message: `No DNS resolver available offline and no curated record for _dmarc.${senderDomain}`,
  };
}

function detectSpoofing(
  sender: string,
  senderDomain: string | null,
  bodyEmails: string[],
  subject: string,
): WireSpoofing {
  const result: WireSpoofing = { detected: false, confidence: 0, factors: [] };

  for (const address of bodyEmails) {
    const bodyDomain = domainOf(address);
    if (bodyDomain && senderDomain && bodyDomain !== senderDomain) {
      result.detected = true;
      result.confidence += 25;
      result.factors.push(`Body contains email from different domain: ${address.toLowerCase()}`);
    }
  }

  if (/verify.+account|confirm.+identity|update.+payment/i.test(subject)) {
    result.detected = true;
    result.confidence += 20;
    result.factors.push('Subject contains common spoofing keywords');
  }

  result.confidence = Math.min(100, result.confidence);
  return result;
}

function analyseHeaderChain(receivedRaw: string[]): WireHeaderChain {
  if (receivedRaw.length === 0) {
    return { chain_length: 0, anomalies: [], analysis: 'No Received headers found' };
  }

  const anomalies: string[] = [];
  const hopAnalysis = receivedRaw.map((raw, index) => {
    const serverMatch = raw.match(/from\s+([^\s[]+)/i);
    if (/localhost/i.test(raw)) anomalies.push(`Localhost detected in hop ${index + 1}`);
    if (raw.includes('[127.0.0.1]')) anomalies.push(`Internal IP in hop ${index + 1}`);
    return {
      hop: index + 1,
      server: serverMatch ? serverMatch[1] : 'Unknown',
      raw: raw.length > 100 ? `${raw.slice(0, 100)}...` : raw,
    };
  });

  return { chain_length: receivedRaw.length, anomalies, hop_analysis: hopAnalysis };
}

/* ------------------------------------------------------------------ */
/* Scoring (mirrors threat_intelligence.py)                            */
/* ------------------------------------------------------------------ */

interface ScoringDraft {
  evidence: { from: string; subject: string; dkim_signature: string };
  geolocation: { sender_locations: WireSenderLocation[] };
  threat_indicators: { urls: string[]; emails: string[] };
  attachments: WireAttachment[];
}

const URGENT_KEYWORDS = [
  'verify', 'confirm', 'act now', 'urgent', 'immediate',
  'click here', 'update account', 'suspended', 'locked',
];

const GENERIC_SENDER_NAMES = ['admin', 'support', 'noreply', 'do-not-reply', 'mailer-daemon'];

function scoreLocally(draft: ScoringDraft): WireThreatAssessment {
  const factors: string[] = [];
  let score = 0;

  score += phishingScore(draft, factors);
  score += attachmentScore(draft, factors);
  score += urlScore(draft, factors);
  score += senderScore(draft, factors);

  const total = Math.min(score, 100);
  const level = total >= 75 ? 'CRITICAL' : total >= 50 ? 'HIGH' : total >= 25 ? 'MEDIUM' : 'LOW';

  return { threat_score: total, threat_level: level, risk_factors: factors };
}

function phishingScore(draft: ScoringDraft, factors: string[]): number {
  let score = 0;
  const sender = draft.evidence.from.toLowerCase();
  const subject = draft.evidence.subject.toLowerCase();

  for (const keyword of URGENT_KEYWORDS) {
    if (subject.includes(keyword)) {
      score += 10;
      factors.push(`Phishing keyword detected: '${keyword}'`);
      break;
    }
  }

  for (const url of draft.threat_indicators.urls) {
    const host = hostOf(url);
    if (SUSPICIOUS_SHORTENERS.some((s) => url.includes(s)) || (host && isUrlShortener(host))) {
      score += 15;
      factors.push(`Shortened URL detected: ${url}`);
      break;
    }
  }

  for (const address of draft.threat_indicators.emails) {
    if (address.toLowerCase() !== sender) {
      score += 5;
      factors.push(`Different email address in content: ${address}`);
    }
  }

  return Math.min(score, 30);
}

function attachmentScore(draft: ScoringDraft, factors: string[]): number {
  if (draft.attachments.length === 0) return 0;
  let score = 0;

  for (const attachment of draft.attachments) {
    const filename = attachment.filename.toLowerCase();
    if (DANGEROUS_EXTENSIONS.some((ext) => filename.endsWith(ext))) {
      score += 20;
      factors.push(`Dangerous file type: ${attachment.filename}`);
    }
    if (attachment.size > 10_000_000) {
      score += 10;
      factors.push(`Large suspicious file: ${attachment.filename} (${attachment.size} bytes)`);
    }
  }

  if (draft.attachments.length > 3) {
    score += 5;
    factors.push(`Multiple attachments (${draft.attachments.length})`);
  }

  return Math.min(score, 30);
}

function urlScore(draft: ScoringDraft, factors: string[]): number {
  const urls = draft.threat_indicators.urls;
  if (urls.length === 0) return 0;
  let score = 0;

  for (const url of urls) {
    if (/^https?:\/\/\d+\.\d+\.\d+\.\d+/.test(url)) {
      score += 15;
      factors.push(`IP-based URL detected: ${url}`);
    }
    if (url.length > 100) {
      score += 10;
      factors.push('Suspiciously long URL detected');
    }
    if (url.includes('%2') || url.includes('%3')) {
      score += 10;
      factors.push(`URL encoding detected (obfuscation): ${url}`);
    }
  }

  return Math.min(score, 25);
}

function senderScore(draft: ScoringDraft, factors: string[]): number {
  let score = 0;
  const sender = draft.evidence.from.toLowerCase();
  const localPart = sender.includes('@') ? sender.split('@')[0].replace(/^.*</, '') : sender;

  if (GENERIC_SENDER_NAMES.includes(localPart)) {
    score += 10;
    factors.push(`Generic sender name: ${localPart}`);
  }

  if (!draft.evidence.dkim_signature) {
    score += 10;
    factors.push('No DKIM signature (authentication failed)');
  }

  for (const location of draft.geolocation.sender_locations) {
    if (location.threat_level === 'high') {
      score += 15;
      factors.push(`Sender IP flagged as high-threat: ${location.country ?? 'Unknown'}`);
    }
  }

  return Math.min(score, 25);
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function matchAll(text: string, pattern: RegExp): string[] {
  const regex = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`);
  return text.match(regex) ?? [];
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}
