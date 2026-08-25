/**
 * SMTP relay-path reconstruction.
 *
 * Turns the verbatim `Received:` stack into an ordered chain of hops, each
 * enriched with curated network intelligence and classified as a trusted,
 * suspicious or unknown hop. The origin assessment is derived from the earliest
 * hop whose attributes we can actually resolve — never the raw first line, which
 * an attacker can forge freely.
 *
 * Ordering: mail servers prepend `Received:` headers, so the stack arrives
 * newest-first (closest to the recipient at the top). `orderHopsFromSender`
 * reverses it, giving index 1 = closest to the original sender.
 */

import { parseReceivedHeader, orderHopsFromSender, findTimestampAnomalies } from '@/lib/receivedParser';
import { anonymiserKind, isReservedIp, lookupNetwork } from '../intel/geoDatabase';
import { lookupMta } from '../intel/mtaDatabase';
import type {
  GeoPoint,
  HopTrust,
  OriginAssessment,
  RelayHop,
  Reputation,
} from '@/types';
import type { WireSenderLocation } from '../wire';

/** A per-address geolocation hint recorded by a gateway, from the wire payload. */
export type LocationHint = WireSenderLocation;

interface RelayReconstruction {
  hops: RelayHop[];
  origin: OriginAssessment;
  timestampAnomalies: string[];
}

export function reconstructRelayChain(
  receivedRaw: string[],
  locationHints: LocationHint[],
): RelayReconstruction {
  if (receivedRaw.length === 0) {
    return { hops: [], origin: emptyOrigin(), timestampAnomalies: [] };
  }

  const senderFirst = orderHopsFromSender(receivedRaw);
  const lastIndex = senderFirst.length - 1;

  const hops: RelayHop[] = senderFirst.map((raw, position) => {
    const parsed = parseReceivedHeader(raw);
    const isDestination = position === lastIndex && senderFirst.length > 1;
    return buildHop(parsed, position + 1, raw, isDestination, locationHints);
  });

  const timestampAnomalies = findTimestampAnomalies(
    hops.map((hop) => ({ index: hop.index, timestamp: hop.timestamp })),
  ).map((anomaly) => anomaly.reason);

  return { hops, origin: assessOrigin(hops), timestampAnomalies };
}

function buildHop(
  parsed: ReturnType<typeof parseReceivedHeader>,
  index: number,
  raw: string,
  isDestination: boolean,
  locationHints: LocationHint[],
): RelayHop {
  const ip = parsed.fromIp;
  const hostname = parsed.fromHost;
  const notes: string[] = [];

  const network = ip && !isReservedIp(ip) ? lookupNetwork(ip) : null;
  const mta = lookupMta(hostname);
  const anonymiser = ip ? anonymiserKind(ip) : null;

  // Geolocation: prefer curated netblock intelligence, then any hint the
  // gateway recorded for this exact address.
  let geo: GeoPoint | null = network?.geo ?? null;
  let isp: string | null = network?.isp ?? mta?.isp ?? null;
  let asn: string | null = network?.asn ?? mta?.asn ?? null;

  if (!geo && ip) {
    const hint = locationHints.find((location) => location.ip === ip);
    if (hint && hint.latitude != null && hint.longitude != null && hint.country) {
      geo = {
        country: hint.country,
        countryCode: hint.country_code ?? '',
        city: hint.city ?? null,
        region: hint.region ?? null,
        latitude: hint.latitude,
        longitude: hint.longitude,
      };
      isp = isp ?? hint.isp ?? null;
    }
  }

  let reputation: Reputation = network?.reputation ?? 'UNKNOWN';
  if (anonymiser === 'TOR') reputation = 'MALICIOUS';
  else if (anonymiser === 'VPN' && reputation === 'UNKNOWN') reputation = 'SUSPICIOUS';

  if (ip && isReservedIp(ip)) {
    notes.push('Address is in reserved/private space — expected for internal hand-offs, not a public origin.');
  }
  if (anonymiser === 'TOR') notes.push('Address falls in a known Tor exit range — the true source is obscured.');
  if (anonymiser === 'VPN') notes.push('Address belongs to a commercial VPN range — an egress point, not necessarily the source.');
  if (mta?.trusted) notes.push(`Recognised infrastructure: ${mta.provider}.`);
  if (mta?.note) notes.push(mta.note);
  if (network && network.reputation !== 'CLEAN' && network.reputation !== 'UNKNOWN') {
    notes.push(`Netblock reputation is ${network.reputation.toLowerCase()} in the bundled intelligence feed.`);
  }
  if (!ip && !hostname) notes.push('Neither a source IP nor a hostname could be recovered from this hop.');

  const trust = classifyTrust({ reputation, mtaTrusted: mta?.trusted ?? false, anonymiser, isReserved: ip ? isReservedIp(ip) : false });
  const confidence = hopConfidence(parsed.confidence, { hasIp: Boolean(ip), hasGeo: Boolean(geo), hasHost: Boolean(hostname) });

  return {
    index,
    ip,
    hostname,
    geo,
    isp,
    asn,
    timestamp: parsed.timestamp,
    trust,
    reputation,
    confidence,
    notes,
    raw,
    ...(isDestination ? { isDestination: true } : {}),
  };
}

function classifyTrust(input: {
  reputation: Reputation;
  mtaTrusted: boolean;
  anonymiser: 'TOR' | 'VPN' | null;
  isReserved: boolean;
}): HopTrust {
  if (input.anonymiser === 'TOR' || input.reputation === 'MALICIOUS' || input.reputation === 'SUSPICIOUS') {
    return 'SUSPICIOUS';
  }
  if (input.mtaTrusted || input.reputation === 'CLEAN') return 'TRUSTED';
  return 'UNKNOWN';
}

/**
 * Confidence blends how much the header parser recovered with how much curated
 * intelligence corroborated it. A hop we located on the map is more trustworthy
 * than a bare IP with no backing record.
 */
function hopConfidence(parserConfidence: number, resolved: { hasIp: boolean; hasGeo: boolean; hasHost: boolean }): number {
  let score = Math.round(parserConfidence * 0.5);
  if (resolved.hasIp) score += 20;
  if (resolved.hasGeo) score += 20;
  if (resolved.hasHost) score += 10;
  return Math.min(100, score);
}

/**
 * The origin is the earliest hop that carries a public, resolvable IP. Reserved
 * addresses and unresolved hops are skipped because they cannot be an
 * internet-facing source.
 */
function assessOrigin(hops: RelayHop[]): OriginAssessment {
  const candidate = hops.find(
    (hop) => hop.ip !== null && !isReservedIp(hop.ip) && !hop.isDestination,
  );

  if (!candidate || !candidate.ip) return emptyOrigin();

  const anonymiser = anonymiserKind(candidate.ip);
  const network = lookupNetwork(candidate.ip);
  const caveats = [
    'Describes observed network infrastructure, not a person. Treat as an investigative lead requiring corroboration.',
  ];
  if (anonymiser) {
    caveats.push('An anonymising relay was detected on the path, so the true source may sit behind this egress point.');
  }
  if (!network) {
    caveats.push('No curated network record backed this address; the estimate rests on header data alone.');
  }

  const confidence = originConfidence(candidate, Boolean(network), anonymiser !== null);

  return {
    earliestReliableHopIndex: candidate.index,
    observedSourceIp: candidate.ip,
    estimatedLocation: candidate.geo,
    isp: candidate.isp,
    asn: candidate.asn,
    proxyOrVpnIndicator: anonymiser === 'VPN' ? 'DETECTED' : anonymiser === 'TOR' ? 'DETECTED' : network ? 'NOT_DETECTED' : 'INCONCLUSIVE',
    torIndicator: anonymiser === 'TOR' ? 'DETECTED' : network ? 'NOT_DETECTED' : 'INCONCLUSIVE',
    hostingType: network?.hostingType ?? 'UNKNOWN',
    confidence,
    caveats,
  };
}

function originConfidence(hop: RelayHop, backed: boolean, anonymised: boolean): number {
  let score = 40;
  if (hop.geo) score += 20;
  if (backed) score += 20;
  if (hop.hostname) score += 10;
  if (hop.timestamp) score += 5;
  if (anonymised) score -= 25;
  return Math.max(10, Math.min(95, score));
}

function emptyOrigin(): OriginAssessment {
  return {
    earliestReliableHopIndex: null,
    observedSourceIp: null,
    estimatedLocation: null,
    isp: null,
    asn: null,
    proxyOrVpnIndicator: 'INCONCLUSIVE',
    torIndicator: 'INCONCLUSIVE',
    hostingType: 'UNKNOWN',
    confidence: 0,
    caveats: ['No relay hop exposed a public source address, so no origin could be estimated from the header chain.'],
  };
}
