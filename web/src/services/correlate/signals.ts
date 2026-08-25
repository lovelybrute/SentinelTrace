/**
 * Signal assembly.
 *
 * The assessment engine in `services/assess.ts` is deliberately a pure function
 * of `AssessmentSignals`. This module is the only place that knows how to gather
 * those signals from a parsed message, so the scoring logic stays testable and
 * the extraction logic stays in one place.
 *
 * Identity inference (asserted role, impersonated organisation) is textual and
 * therefore fallible. It feeds the score as one weighted dimension among eight
 * and is always surfaced to the analyst as a cited finding rather than a silent
 * adjustment.
 */

import type { AssessmentSignals } from '../assess';
import type {
  AttachmentRecord,
  DomainIntelligence,
  EmailMetadata,
  IpIntelligence,
  OriginAssessment,
  RelayHop,
  UrlRecord,
} from '@/types';
import {
  detectLookalike,
  isConsumerMailProvider,
  isDisposableMailProvider,
  isProtectedBrand,
} from '@/lib/lookalike';
import type { LookalikeMatch } from '@/lib/lookalike';
import { analyseLanguage } from '@/lib/languageAnalysis';
import { domainOf } from '@/lib/format';
import type { WireAnalysis } from '../wire';
import type { AuthenticationResult, HeaderAnomaly } from './authentication';
import { registrableLabel, sameOrganisation } from './shared';

/**
 * Authority roles worth flagging when asserted by an unauthenticated sender.
 * Ordered most senior first so the strongest claim wins when several match.
 */
const ROLE_PATTERNS: { pattern: RegExp; label: string }[] = [
  { pattern: /\bchief executive officer\b|\bceo\b/i, label: 'Chief Executive Officer' },
  { pattern: /\bchief financial officer\b|\bcfo\b/i, label: 'Chief Financial Officer' },
  { pattern: /\bchief operating officer\b|\bcoo\b/i, label: 'Chief Operating Officer' },
  { pattern: /\bchief technology officer\b|\bcto\b/i, label: 'Chief Technology Officer' },
  { pattern: /\bmanaging director\b|\bmd\b(?=[\s,.])/i, label: 'Managing Director' },
  { pattern: /\bchairman\b|\bchairperson\b/i, label: 'Chairman' },
  { pattern: /\bvice president\b|\bsvp\b|\bevp\b/i, label: 'Vice President' },
  { pattern: /\bpresident\b/i, label: 'President' },
  { pattern: /\bcompany secretary\b/i, label: 'Company Secretary' },
  { pattern: /\bfinance (?:director|head|controller|manager)\b|\bhead of finance\b/i, label: 'Finance Director' },
  { pattern: /\bfinancial controller\b|\bcontroller\b/i, label: 'Financial Controller' },
  { pattern: /\baccounts payable\b|\bap team\b/i, label: 'Accounts Payable' },
  { pattern: /\btreasur(?:y|er)\b/i, label: 'Treasury' },
  { pattern: /\bpayroll\b/i, label: 'Payroll' },
  { pattern: /\bdirector\b/i, label: 'Director' },
];

export interface SignalInput {
  metadata: EmailMetadata;
  /** Plain-text body used for language and signature analysis. */
  bodyText: string;
  auth: AuthenticationResult;
  hops: RelayHop[];
  origin: OriginAssessment;
  urls: UrlRecord[];
  attachments: AttachmentRecord[];
  domainIntel: DomainIntelligence[];
  ipIntel: IpIntelligence[];
  headerAnomalies: HeaderAnomaly[];
  timestampAnomalies: string[];
  wire: WireAnalysis;
  /** Organisational domain of the recipient, used to detect internal claims. */
  recipientDomain: string | null;
}

export function buildSignals(input: SignalInput): AssessmentSignals {
  const { metadata, auth, wire } = input;

  const fromAddress = metadata.from;
  const fromDomain = domainOf(fromAddress);
  const replyToDomain = metadata.replyTo ? domainOf(metadata.replyTo) : null;
  const returnPathDomain = metadata.returnPath ? domainOf(metadata.returnPath) : null;
  const messageIdDomain = metadata.messageId
    ? (metadata.messageId.match(/@([^>\s]+)/)?.[1]?.toLowerCase() ?? null)
    : null;

  // The recipient's own domain is a lookalike target for this message even though
  // it is not a globally protected brand.
  const extraTargets = input.recipientDomain ? [input.recipientDomain] : [];

  const fromLookalike = lookalikeFor(fromDomain, extraTargets);
  const replyToLookalike = lookalikeFor(replyToDomain, extraTargets);

  const urlLookalikes: { host: string; match: LookalikeMatch }[] = [];
  const seenHosts = new Set<string>();
  for (const url of input.urls) {
    if (seenHosts.has(url.host)) continue;
    seenHosts.add(url.host);
    const match = lookalikeFor(url.host, extraTargets);
    if (match) urlLookalikes.push({ host: url.host, match });
  }

  const language = analyseLanguage(input.bodyText);

  const signature = signatureZone(input.bodyText);
  const assertedRole = detectRole(metadata.fromDisplayName, signature, metadata.subject);
  const claimsInternalIdentity = detectsInternalClaim({
    displayName: metadata.fromDisplayName,
    signature,
    fromDomain,
    recipientDomain: input.recipientDomain,
    fromLookalike,
  });
  const impersonatedOrganisation = pickImpersonatedOrganisation({
    claimsInternalIdentity,
    recipientDomain: input.recipientDomain,
    fromLookalike,
    replyToLookalike,
  });

  const fromIntel = input.domainIntel.find((entry) => entry.domain === fromDomain) ?? null;

  return {
    fromAddress,
    fromDomain,
    displayName: metadata.fromDisplayName,
    replyToDomain,
    returnPathDomain,
    messageIdDomain,
    subject: metadata.subject,
    fromLookalike,
    replyToLookalike,
    urlLookalikes,
    assertedRole,
    claimsInternalIdentity,
    impersonatedOrganisation,
    language,
    spf: auth.spf,
    dkim: auth.dkim,
    dmarc: auth.dmarc,
    spfAligned: auth.spfAligned,
    dkimAligned: auth.dkimAligned,
    dmarcEnforced: auth.dmarcEnforced,
    trustScore: auth.summary.trustScore,
    hops: input.hops,
    origin: input.origin,
    urls: input.urls,
    attachments: input.attachments,
    domainIntel: input.domainIntel,
    ipIntel: input.ipIntel,
    headerAnomalies: input.headerAnomalies,
    backendScore: wire.threat_assessment.threat_score,
    backendFactors: wire.threat_assessment.risk_factors,
    spoofingConfidence: wire.forensics?.spoofing_analysis.confidence ?? 0,
    spoofingFactors: wire.forensics?.spoofing_analysis.factors ?? [],
    timestampAnomalies: input.timestampAnomalies,
    chainLength: wire.forensics?.header_chain.chain_length ?? input.hops.length,
    fromDomainAgeDays: fromIntel?.ageDays ?? null,
    consumerSender: fromDomain ? isConsumerMailProvider(fromDomain) : false,
    disposableReplyTo: replyToDomain ? isDisposableMailProvider(replyToDomain) : false,
  };
}

/* ------------------------------------------------------------------ */
/* Identity inference                                                  */
/* ------------------------------------------------------------------ */

function lookalikeFor(domain: string | null, extraTargets: string[]): LookalikeMatch | null {
  if (!domain || !domain.includes('.')) return null;
  if (isProtectedBrand(domain)) return null;
  return detectLookalike(domain, extraTargets.filter((target) => target !== domain));
}

/**
 * The trailing portion of the body, where signature blocks live. Role claims in
 * a signature carry more weight than the same words in prose.
 */
function signatureZone(bodyText: string): string {
  const trimmed = bodyText.trimEnd();
  return trimmed.length <= 700 ? trimmed : trimmed.slice(-700);
}

function detectRole(displayName: string | null, signature: string, subject: string): string | null {
  // Display name is checked first: it is what the recipient actually sees.
  for (const source of [displayName ?? '', signature, subject]) {
    if (!source) continue;
    for (const role of ROLE_PATTERNS) {
      if (role.pattern.test(source)) return role.label;
    }
  }
  return null;
}

function detectsInternalClaim(params: {
  displayName: string | null;
  signature: string;
  fromDomain: string;
  recipientDomain: string | null;
  fromLookalike: LookalikeMatch | null;
}): boolean {
  const { displayName, signature, fromDomain, recipientDomain, fromLookalike } = params;
  if (!recipientDomain) return false;

  // Genuinely internal mail is not an impersonation claim.
  if (sameOrganisation(fromDomain, recipientDomain)) return false;

  // A sending domain built to imitate the recipient is an internal claim by
  // construction, whatever the display name says.
  if (fromLookalike && sameOrganisation(fromLookalike.target, recipientDomain)) return true;

  const label = registrableLabel(recipientDomain);
  if (label.length < 4) return false;

  const haystack = `${displayName ?? ''}\n${signature}`.toLowerCase();
  return haystack.includes(label.toLowerCase());
}

function pickImpersonatedOrganisation(params: {
  claimsInternalIdentity: boolean;
  recipientDomain: string | null;
  fromLookalike: LookalikeMatch | null;
  replyToLookalike: LookalikeMatch | null;
}): string | null {
  if (params.claimsInternalIdentity && params.recipientDomain) return params.recipientDomain;
  if (params.fromLookalike) return params.fromLookalike.target;
  if (params.replyToLookalike) return params.replyToLookalike.target;
  return null;
}
