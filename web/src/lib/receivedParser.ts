/**
 * SMTP `Received:` header parser.
 *
 * The backend stores these headers verbatim (`{"raw": "..."}`), so relay-path
 * reconstruction happens here on the client. Received headers are notoriously
 * inconsistent between MTAs, so every field is optional and the parser reports
 * how much it managed to extract via a confidence score.
 */

export interface ParsedReceived {
  /** Host the message was received *from*, as claimed by the sending MTA. */
  fromHost: string | null;
  /** IP literal found in brackets or parentheses. */
  fromIp: string | null;
  /** Host that did the receiving. */
  byHost: string | null;
  /** ESMTP / ESMTPS / SMTP / local, etc. */
  protocol: string | null;
  /** Queue id assigned by the receiving MTA. */
  queueId: string | null;
  /** Envelope recipient, when disclosed. */
  forAddress: string | null;
  /** ISO timestamp parsed from the segment after the final semicolon. */
  timestamp: string | null;
  /** TLS details when the hop advertised them. */
  tls: string | null;
  /** 0–100: how many of the useful fields were recoverable. */
  confidence: number;
  raw: string;
}

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/;
const IPV6_BRACKET = /\[IPv6:([0-9a-f:]+)\]/i;

export function parseReceivedHeader(raw: string): ParsedReceived {
  // Collapse folded whitespace — Received headers are frequently multi-line.
  const text = raw.replace(/\s+/g, ' ').trim();

  const fromHost = matchHost(text, /(?:^|\s)from\s+([A-Za-z0-9._-]+)/i);
  const byHost = matchHost(text, /(?:^|\s)by\s+([A-Za-z0-9._-]+)/i);

  const ipv6 = text.match(IPV6_BRACKET);
  const ipv4 = text.match(IPV4);
  const fromIp = ipv6 ? ipv6[1] : (ipv4 ? ipv4[0] : null);

  const protocolMatch = text.match(/\bwith\s+((?:ESMTPS?A?|SMTPS?|LMTP|HTTP|HTTPS|local)\b[A-Za-z]*)/i);
  const protocol = protocolMatch ? protocolMatch[1].toUpperCase() : null;

  const idMatch = text.match(/\bid\s+([A-Za-z0-9._-]{4,})/i);
  const queueId = idMatch ? idMatch[1] : null;

  const forMatch = text.match(/\bfor\s+<([^>]+)>/i);
  const forAddress = forMatch ? forMatch[1] : null;

  const tlsMatch = text.match(/\b(?:cipher|version)=([A-Za-z0-9_.-]+)/i);
  const tls = tlsMatch ? tlsMatch[0] : null;

  const timestamp = parseTrailingDate(text);

  const recovered = [fromHost, fromIp, byHost, protocol, timestamp].filter(Boolean).length;
  const confidence = Math.round((recovered / 5) * 100);

  return {
    fromHost,
    fromIp,
    byHost,
    protocol,
    queueId,
    forAddress,
    timestamp,
    tls,
    confidence,
    raw,
  };
}

function matchHost(text: string, pattern: RegExp): string | null {
  const match = text.match(pattern);
  if (!match) return null;
  const value = match[1].trim().replace(/[.;,]+$/, '');
  // A bare IP in the `from`/`by` slot is captured separately, not as a hostname.
  if (!value || IPV4.test(value)) return null;
  return value.toLowerCase();
}

/**
 * The RFC 5322 date-time lives after the final `;`. Some MTAs omit it, and some
 * append `(envelope-from ...)` noise after it.
 */
function parseTrailingDate(text: string): string | null {
  const semicolon = text.lastIndexOf(';');
  const candidate = semicolon === -1 ? text : text.slice(semicolon + 1);
  const cleaned = candidate.replace(/\([^)]*\)/g, '').trim();
  if (!cleaned) return null;
  const parsed = new Date(cleaned);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

/**
 * Received headers are prepended by each MTA, so the array from the parser is in
 * reverse chronological order: index 0 is the *last* hop (closest to the
 * recipient). Reverse it so hop 1 is nearest the originating sender, which is
 * how an investigator reads a relay path.
 */
export function orderHopsFromSender<T>(headers: T[]): T[] {
  return [...headers].reverse();
}

/** Detect timestamps that run backwards — a classic sign of forged headers. */
export function findTimestampAnomalies(
  hops: { index: number; timestamp: string | null }[],
): { index: number; reason: string }[] {
  const anomalies: { index: number; reason: string }[] = [];
  let previous: number | null = null;
  let previousIndex = 0;

  for (const hop of hops) {
    if (!hop.timestamp) continue;
    const current = new Date(hop.timestamp).getTime();
    if (previous !== null) {
      if (current < previous - 60_000) {
        anomalies.push({
          index: hop.index,
          reason: `Timestamp precedes hop ${previousIndex} by ${Math.round((previous - current) / 1000)}s — chronology inconsistent with a forward relay path.`,
        });
      } else if (current - previous > 6 * 3600_000) {
        anomalies.push({
          index: hop.index,
          reason: `Unexplained ${Math.round((current - previous) / 3600_000)}h delay before this hop.`,
        });
      }
    }
    previous = current;
    previousIndex = hop.index;
  }

  return anomalies;
}

/** RFC 1918 / loopback / link-local detection. */
export function isPrivateIp(ip: string): boolean {
  const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
  const [a, b] = parts;
  if (a === 10 || a === 127) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  return false;
}
