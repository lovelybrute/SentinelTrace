/**
 * Authentication evaluation: SPF mechanism matching, identifier alignment and
 * DMARC disposition.
 *
 * Why this exists: the backend's `check_spf_record` reports whether a policy is
 * *published*, not whether the connecting IP is authorised by it. Given the
 * published record and the observed source IP we can evaluate the `ip4`/`ip6`
 * mechanisms locally and reach a definitive verdict in many real cases. Where a
 * record delegates via `include:` / `a` / `mx` we cannot resolve it without DNS,
 * and we say so rather than guessing — an inconclusive result stated plainly is
 * more useful to an investigator than a confident wrong one.
 */

import type { AuthVerdict } from '@/types';

export type SpfQualifier = '+' | '-' | '~' | '?';

export interface SpfEvaluation {
  verdict: AuthVerdict;
  /** The mechanism that decided the result, e.g. `ip4:203.0.113.0/24`. */
  matchedMechanism: string | null;
  /** Mechanisms that would have required a DNS lookup to evaluate. */
  unresolved: string[];
  /** True when the verdict is safe to present as final. */
  definitive: boolean;
  explanation: string;
}

const QUALIFIER_VERDICT: Record<SpfQualifier, AuthVerdict> = {
  '+': 'PASS',
  '-': 'FAIL',
  '~': 'SOFTFAIL',
  '?': 'NEUTRAL',
};

function ipv4ToLong(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    const octet = Number.parseInt(part, 10);
    if (Number.isNaN(octet) || octet < 0 || octet > 255) return null;
    value = value * 256 + octet;
  }
  return value;
}

/** IPv4 CIDR membership. Bare addresses are treated as /32. */
export function ipv4InCidr(ip: string, cidr: string): boolean {
  const [network, prefixText] = cidr.split('/');
  const prefix = prefixText === undefined ? 32 : Number.parseInt(prefixText, 10);
  if (Number.isNaN(prefix) || prefix < 0 || prefix > 32) return false;

  const ipLong = ipv4ToLong(ip);
  const networkLong = ipv4ToLong(network);
  if (ipLong === null || networkLong === null) return false;

  if (prefix === 0) return true;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return ((ipLong & mask) >>> 0) === ((networkLong & mask) >>> 0);
}

/**
 * Evaluate a published SPF record against an observed source IP.
 * `record` is the raw TXT value, e.g. `v=spf1 ip4:203.0.113.0/24 include:x -all`.
 */
export function evaluateSpf(record: string | null, ip: string | null): SpfEvaluation {
  if (!record) {
    return {
      verdict: 'NONE',
      matchedMechanism: null,
      unresolved: [],
      definitive: true,
      explanation: 'The sender domain publishes no SPF policy, so receiving servers have no authorised-sender list to check against.',
    };
  }

  if (!ip) {
    return {
      verdict: 'NEUTRAL',
      matchedMechanism: null,
      unresolved: [],
      definitive: false,
      explanation: 'An SPF policy is published, but no connecting IP could be recovered from the relay chain, so the policy could not be evaluated.',
    };
  }

  const terms = record.trim().split(/\s+/).filter((term) => term && !/^v=spf1$/i.test(term));
  const unresolved: string[] = [];

  for (const term of terms) {
    const qualifierChar = term[0];
    const hasQualifier = qualifierChar === '+' || qualifierChar === '-' || qualifierChar === '~' || qualifierChar === '?';
    const qualifier: SpfQualifier = hasQualifier ? (qualifierChar as SpfQualifier) : '+';
    const mechanism = hasQualifier ? term.slice(1) : term;
    const [name, value] = splitMechanism(mechanism);

    switch (name) {
      case 'ip4': {
        if (value && ipv4InCidr(ip, value)) {
          return {
            verdict: QUALIFIER_VERDICT[qualifier],
            matchedMechanism: mechanism,
            unresolved,
            definitive: true,
            explanation: `The observed source address ${ip} matches the published mechanism \`${mechanism}\`.`,
          };
        }
        break;
      }
      case 'ip6': {
        // IPv6 range maths is out of scope here; note it and continue.
        if (ip.includes(':')) unresolved.push(mechanism);
        break;
      }
      case 'a':
      case 'mx':
      case 'ptr':
      case 'exists':
      case 'include':
      case 'redirect': {
        unresolved.push(mechanism);
        break;
      }
      case 'all': {
        const verdict = QUALIFIER_VERDICT[qualifier];
        // A terminal `-all` only proves failure if nothing earlier was skipped.
        if (unresolved.length > 0 && verdict !== 'PASS') {
          return {
            verdict: 'NEUTRAL',
            matchedMechanism: mechanism,
            unresolved,
            definitive: false,
            explanation: `The policy terminates in \`${mechanism}\`, but ${unresolved.length} delegated mechanism${unresolved.length === 1 ? '' : 's'} (${unresolved.join(', ')}) could not be resolved offline. The result is inconclusive rather than a confirmed failure.`,
          };
        }
        return {
          verdict,
          matchedMechanism: mechanism,
          unresolved,
          definitive: true,
          explanation:
            verdict === 'FAIL'
              ? `No mechanism authorises ${ip} and the policy ends in \`${mechanism}\`, so the sending host is explicitly not permitted to use this domain.`
              : verdict === 'SOFTFAIL'
                ? `No mechanism authorises ${ip}; the policy ends in \`${mechanism}\`, marking the message as suspicious but not rejecting it.`
                : `The policy ends in \`${mechanism}\`, which does not assert anything about ${ip}.`,
        };
      }
      default:
        break;
    }
  }

  return {
    verdict: 'NEUTRAL',
    matchedMechanism: null,
    unresolved,
    definitive: false,
    explanation: unresolved.length
      ? `The policy relies on delegated mechanisms (${unresolved.join(', ')}) that require live DNS resolution, so it could not be evaluated offline.`
      : 'The policy contains no mechanism covering the observed source address and no terminal `all` directive.',
  };
}

function splitMechanism(mechanism: string): [string, string | null] {
  const separator = mechanism.search(/[:=]/);
  if (separator === -1) return [mechanism.toLowerCase(), null];
  return [mechanism.slice(0, separator).toLowerCase(), mechanism.slice(separator + 1)];
}

/* ------------------------------------------------------------------ */
/* Identifier alignment                                                */
/* ------------------------------------------------------------------ */

export type AlignmentMode = 'STRICT' | 'RELAXED';

/**
 * Organisational domain, approximated by taking the registrable label plus its
 * public suffix. Enough for alignment comparison without a PSL bundle.
 */
export function organisationalDomain(domain: string): string {
  const parts = domain.toLowerCase().replace(/^\.+|\.+$/g, '').split('.');
  if (parts.length <= 2) return parts.join('.');
  const secondLast = parts[parts.length - 2];
  if (['co', 'org', 'gov', 'net', 'ac', 'edu'].includes(secondLast) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

export function isAligned(
  authenticatedDomain: string | null,
  fromDomain: string,
  mode: AlignmentMode = 'RELAXED',
): boolean | null {
  if (!authenticatedDomain || !fromDomain) return null;
  const a = authenticatedDomain.toLowerCase().replace(/^\.+/, '');
  const b = fromDomain.toLowerCase();
  if (mode === 'STRICT') return a === b;
  return organisationalDomain(a) === organisationalDomain(b);
}

/* ------------------------------------------------------------------ */
/* DKIM signature inspection                                           */
/* ------------------------------------------------------------------ */

export interface DkimTags {
  domain: string | null;
  selector: string | null;
  algorithm: string | null;
  signedHeaders: string[];
  bodyHashTruncated: boolean;
}

/** Pull the tags an analyst cares about out of a DKIM-Signature header. */
export function parseDkimSignature(signature: string | null): DkimTags {
  if (!signature) {
    return { domain: null, selector: null, algorithm: null, signedHeaders: [], bodyHashTruncated: false };
  }
  const tag = (name: string): string | null => {
    const match = signature.match(new RegExp(`(?:^|[;\\s])${name}=([^;]+)`, 'i'));
    return match ? match[1].trim() : null;
  };
  const headers = tag('h');
  return {
    domain: tag('d')?.toLowerCase() ?? null,
    selector: tag('s'),
    algorithm: tag('a'),
    signedHeaders: headers ? headers.split(':').map((h) => h.trim().toLowerCase()).filter(Boolean) : [],
    // `l=` limits how much of the body is covered, allowing content to be appended.
    bodyHashTruncated: /(?:^|[;\s])l=\d+/i.test(signature),
  };
}

/* ------------------------------------------------------------------ */
/* DMARC                                                              */
/* ------------------------------------------------------------------ */

export interface DmarcRecordTags {
  policy: 'none' | 'quarantine' | 'reject';
  subdomainPolicy: 'none' | 'quarantine' | 'reject' | null;
  spfAlignment: AlignmentMode;
  dkimAlignment: AlignmentMode;
  percentage: number;
  reportingAddresses: string[];
}

export function parseDmarcRecord(record: string | null): DmarcRecordTags | null {
  if (!record) return null;
  const tag = (name: string): string | null => {
    const match = record.match(new RegExp(`(?:^|[;\\s])${name}=([^;]+)`, 'i'));
    return match ? match[1].trim().toLowerCase() : null;
  };
  const policy = tag('p');
  const subdomain = tag('sp');
  const rua = record.match(/rua=([^;]+)/i)?.[1] ?? '';

  return {
    policy: policy === 'reject' || policy === 'quarantine' ? policy : 'none',
    subdomainPolicy:
      subdomain === 'reject' || subdomain === 'quarantine' || subdomain === 'none' ? subdomain : null,
    spfAlignment: tag('aspf') === 's' ? 'STRICT' : 'RELAXED',
    dkimAlignment: tag('adkim') === 's' ? 'STRICT' : 'RELAXED',
    percentage: Number.parseInt(tag('pct') ?? '100', 10) || 100,
    reportingAddresses: rua
      .split(',')
      .map((entry) => entry.trim().replace(/^mailto:/i, ''))
      .filter(Boolean),
  };
}

export interface DmarcEvaluation {
  verdict: AuthVerdict;
  /** What a compliant receiver would do with this message. */
  disposition: 'NONE' | 'QUARANTINE' | 'REJECT' | 'NOT_APPLICABLE';
  spfAligned: boolean | null;
  dkimAligned: boolean | null;
  explanation: string;
}

/**
 * DMARC passes when at least one of SPF or DKIM both passes *and* is aligned
 * with the visible From domain. Alignment is the part attackers exploit: a
 * message can carry a valid signature for a domain they control.
 */
export function evaluateDmarc(params: {
  record: string | null;
  fromDomain: string;
  spfVerdict: AuthVerdict;
  spfDomain: string | null;
  dkimVerdict: AuthVerdict;
  dkimDomain: string | null;
}): DmarcEvaluation {
  const tags = parseDmarcRecord(params.record);

  if (!tags) {
    return {
      verdict: 'NONE',
      disposition: 'NOT_APPLICABLE',
      spfAligned: isAligned(params.spfDomain, params.fromDomain),
      dkimAligned: isAligned(params.dkimDomain, params.fromDomain),
      explanation: `No DMARC policy is published for ${params.fromDomain}, so a receiving server has no instruction on how to treat authentication failures for this domain.`,
    };
  }

  const spfAligned = isAligned(params.spfDomain, params.fromDomain, tags.spfAlignment);
  const dkimAligned = isAligned(params.dkimDomain, params.fromDomain, tags.dkimAlignment);
  const spfOk = params.spfVerdict === 'PASS' && spfAligned === true;
  const dkimOk = params.dkimVerdict === 'PASS' && dkimAligned === true;

  if (spfOk || dkimOk) {
    const via = spfOk && dkimOk ? 'both SPF and DKIM' : spfOk ? 'aligned SPF' : 'aligned DKIM';
    return {
      verdict: 'PASS',
      disposition: 'NONE',
      spfAligned,
      dkimAligned,
      explanation: `DMARC is satisfied through ${via}: the authenticated identifier aligns with the visible From domain ${params.fromDomain}.`,
    };
  }

  const reasons: string[] = [];
  if (params.spfVerdict !== 'PASS') reasons.push(`SPF did not pass (${params.spfVerdict})`);
  else if (spfAligned === false) reasons.push(`SPF passed for ${params.spfDomain} but that does not align with ${params.fromDomain}`);
  if (params.dkimVerdict !== 'PASS') reasons.push(`DKIM did not pass (${params.dkimVerdict})`);
  else if (dkimAligned === false) reasons.push(`DKIM signed for ${params.dkimDomain}, which does not align with ${params.fromDomain}`);

  const disposition = tags.policy === 'reject' ? 'REJECT' : tags.policy === 'quarantine' ? 'QUARANTINE' : 'NONE';

  // Absence of a pass is not the same as a failure. A mechanism that could not be
  // evaluated offline — an unresolvable `include:`, or a signature whose public
  // key we cannot fetch — leaves open the possibility of an aligned pass, so the
  // honest DMARC result is inconclusive. Declaring FAIL here would accuse
  // legitimate mail of spoofing purely because the evidence was incomplete, which
  // is the mirror image of the false-pass problem and just as damaging.
  const spfSettled = params.spfVerdict !== 'NEUTRAL' && params.spfVerdict !== 'ERROR';
  const dkimSettled = params.dkimVerdict !== 'NEUTRAL' && params.dkimVerdict !== 'ERROR';

  if (!spfSettled || !dkimSettled) {
    const unsettled = [!spfSettled ? 'SPF' : null, !dkimSettled ? 'DKIM' : null].filter(Boolean).join(' and ');
    return {
      verdict: 'NEUTRAL',
      disposition: 'NOT_APPLICABLE',
      spfAligned,
      dkimAligned,
      explanation: `DMARC could not be resolved offline: ${unsettled} produced no definitive result, so an aligned pass cannot be ruled out. ${params.fromDomain} publishes p=${tags.policy}. Re-run against live DNS to settle this before treating it as either authentic or spoofed.`,
    };
  }

  return {
    verdict: 'FAIL',
    disposition,
    spfAligned,
    dkimAligned,
    explanation: `DMARC fails because no authenticated identifier aligns with ${params.fromDomain} — ${reasons.join('; ')}. The published policy is p=${tags.policy}, so a compliant receiver would ${disposition === 'REJECT' ? 'reject the message outright' : disposition === 'QUARANTINE' ? 'quarantine the message' : 'still deliver it, which is why it reached the mailbox'}.`,
  };
}

/**
 * Narrow the backend's status strings to the cases where it genuinely reached a
 * conclusion. Returns `null` for "no conclusion — evaluate locally".
 *
 * This is deliberately conservative, because the backend's vocabulary is more
 * optimistic than its evidence:
 *
 *  - `check_spf_record` and `check_dmarc_record` report `status: "pass"` as soon as
 *    a record is *published*. Neither matches the connecting address against the
 *    mechanisms, and neither tests identifier alignment.
 *  - `validate_dkim` reports `"signed"` for the mere presence of a signature and
 *    never verifies the body hash.
 *
 * Treating any of those as an authentication PASS would tell an analyst that a
 * spoofed message was authenticated purely because the impersonated domain
 * publishes a policy — which is precisely backwards, and the most dangerous
 * mistake this tool could make. A phishing message from a lookalike of a
 * well-configured brand would come back green.
 *
 * `"domain_mismatch"` is also excluded: the backend compares the DKIM `d=` tag to
 * the sender domain with exact string equality, so it flags legitimate subdomain
 * signing (`d=mail.example.com` for `example.com`) as a mismatch. That check is
 * re-derived locally with relaxed alignment, per RFC 7489.
 *
 * What is left is real: an absent policy or signature, and a failed lookup.
 */
export function definitiveBackendVerdict(status: string | undefined): AuthVerdict | null {
  switch ((status ?? '').toLowerCase()) {
    // A genuine, actionable absence — the backend queried and found nothing.
    case 'missing':
    case 'no_spf':
    case 'no_dmarc':
      return 'NONE';
    // The lookup itself failed, so the backend established nothing either way.
    // Worth preserving: it is distinct from "no policy is published".
    case 'dns_unavailable':
    case 'dns_error':
    case 'error':
      return 'ERROR';
    default:
      return null;
  }
}

/** First published record the backend discovered, if any. */
export function firstRecord(records: string[] | undefined): string | null {
  return records?.find((record) => record.trim().length > 0)?.trim() ?? null;
}
