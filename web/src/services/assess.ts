/**
 * The assessment engine: turns gathered signals into the eight score dimensions,
 * a classification, a confidence value, cited findings and recommended actions.
 *
 * Design principles:
 *  - Every dimension carries a written `summary`, so nothing is an unexplained
 *    number. If the interface shows 84%, the analyst can read why it is 84%.
 *  - Findings cite the evidence they came from. An analyst can disagree with the
 *    engine and check the header themselves.
 *  - Confidence saturates but never reaches certainty. The cap is deliberate:
 *    this platform supports attribution, it does not prove it.
 */

import type {
  AiAssessment,
  AttachmentRecord,
  AuthVerdict,
  Classification,
  DomainIntelligence,
  Finding,
  IpIntelligence,
  OriginAssessment,
  RecommendedAction,
  RelayHop,
  ScoreComponent,
  Severity,
  ThreatScore,
  UrlRecord,
} from '@/types';
import type { LanguageAssessment, PressureCategory } from '@/lib/languageAnalysis';
import { PRESSURE_LABELS } from '@/lib/languageAnalysis';
import type { LookalikeMatch } from '@/lib/lookalike';
import { clamp } from '@/lib/format';

export const MODEL_VERSION = 'SentinelTrace-Correlation/1.4.2';

/** Everything the engine needs, gathered once by `correlate.ts`. */
export interface AssessmentSignals {
  fromAddress: string;
  fromDomain: string;
  displayName: string | null;
  replyToDomain: string | null;
  returnPathDomain: string | null;
  messageIdDomain: string | null;
  subject: string;
  fromLookalike: LookalikeMatch | null;
  replyToLookalike: LookalikeMatch | null;
  urlLookalikes: { host: string; match: LookalikeMatch }[];
  /** Executive or authority role asserted by the display name or signature. */
  assertedRole: string | null;
  /** True when the message claims an identity inside the recipient organisation. */
  claimsInternalIdentity: boolean;
  impersonatedOrganisation: string | null;
  language: LanguageAssessment;
  spf: AuthVerdict;
  dkim: AuthVerdict;
  dmarc: AuthVerdict;
  spfAligned: boolean | null;
  dkimAligned: boolean | null;
  dmarcEnforced: boolean;
  trustScore: number;
  hops: RelayHop[];
  origin: OriginAssessment;
  urls: UrlRecord[];
  attachments: AttachmentRecord[];
  domainIntel: DomainIntelligence[];
  ipIntel: IpIntelligence[];
  headerAnomalies: { name: string; severity: Severity; reason: string }[];
  backendScore: number;
  backendFactors: string[];
  spoofingConfidence: number;
  spoofingFactors: string[];
  timestampAnomalies: string[];
  chainLength: number;
  fromDomainAgeDays: number | null;
  consumerSender: boolean;
  disposableReplyTo: boolean;
}

/**
 * Dimension weights. Authentication and identity signals dominate because they
 * are the hardest for an attacker to fake and the most reliable in practice;
 * attachment and URL risk are weighted lower because a message can be dangerous
 * with neither.
 */
const WEIGHTS: Record<ScoreComponent['id'], number> = {
  phishing: 0.18,
  spoofing: 0.16,
  domain_risk: 0.14,
  social_engineering: 0.14,
  header_anomaly: 0.12,
  ip_reputation: 0.1,
  attachment_risk: 0.08,
  url_risk: 0.08,
};

const LABELS: Record<ScoreComponent['id'], string> = {
  phishing: 'Phishing probability',
  spoofing: 'Spoofing probability',
  domain_risk: 'Domain risk',
  ip_reputation: 'IP reputation',
  header_anomaly: 'Header anomaly',
  social_engineering: 'Social engineering',
  attachment_risk: 'Attachment risk',
  url_risk: 'URL risk',
};

/* ------------------------------------------------------------------ */
/* Score dimensions                                                    */
/* ------------------------------------------------------------------ */

export function buildThreatScore(s: AssessmentSignals): ThreatScore {
  const components: ScoreComponent[] = [
    phishingDimension(s),
    spoofingDimension(s),
    domainDimension(s),
    socialEngineeringDimension(s),
    headerDimension(s),
    ipDimension(s),
    attachmentDimension(s),
    urlDimension(s),
  ];

  const total = Math.round(
    components.reduce((sum, component) => sum + component.value * component.weight, 0),
  );

  return {
    total: clamp(total, 0, 100),
    level: total >= 75 ? 'CRITICAL' : total >= 50 ? 'HIGH' : total >= 25 ? 'MEDIUM' : total > 0 ? 'LOW' : 'INFO',
    components,
  };
}

function component(
  id: ScoreComponent['id'],
  value: number,
  reasons: string[],
  fallback: string,
): ScoreComponent {
  return {
    id,
    label: LABELS[id],
    value: clamp(Math.round(value), 0, 100),
    weight: WEIGHTS[id],
    summary: reasons.length > 0 ? reasons.join(' ') : fallback,
  };
}

function phishingDimension(s: AssessmentSignals): ScoreComponent {
  let value = s.backendScore * 0.55;
  const reasons: string[] = [];

  if (s.backendScore > 0) {
    reasons.push(`Baseline risk of ${s.backendScore}/100 from ${s.backendFactors.length} rule-based indicator${s.backendFactors.length === 1 ? '' : 's'}.`);
  }
  if (s.language.categories.includes('CREDENTIAL_HARVESTING')) {
    value += 22;
    reasons.push('Body solicits authentication material or directs the reader to a sign-in action.');
  }
  if (s.fromLookalike) {
    value += 18;
    reasons.push(`Sending domain imitates ${s.fromLookalike.target}.`);
  }
  if (s.urls.some((url) => url.risk === 'CRITICAL' || url.risk === 'HIGH')) {
    value += 14;
    reasons.push('At least one embedded link scores high risk on its own.');
  }
  if (s.dmarc === 'FAIL' || s.spf === 'FAIL') {
    value += 12;
    reasons.push('Sender authentication does not hold, so the visible identity is unverified.');
  }
  if (s.language.categories.includes('CONSEQUENCE_THREAT')) {
    value += 8;
    reasons.push('Threatens an account or service consequence to force a response.');
  }

  return component('phishing', value, reasons, 'No phishing-specific indicators were matched.');
}

function spoofingDimension(s: AssessmentSignals): ScoreComponent {
  let value = s.spoofingConfidence * 0.5;
  const reasons: string[] = [];

  if (s.spoofingFactors.length > 0) {
    reasons.push(`${s.spoofingFactors.length} spoofing heuristic${s.spoofingFactors.length === 1 ? '' : 's'} matched during parsing.`);
  }
  if (s.returnPathDomain && s.returnPathDomain !== s.fromDomain) {
    value += 26;
    reasons.push(`Envelope return path uses ${s.returnPathDomain} while the visible sender claims ${s.fromDomain}.`);
  }
  if (s.replyToDomain && s.replyToDomain !== s.fromDomain) {
    value += 22;
    reasons.push(`Replies would be routed to ${s.replyToDomain}, not the apparent sender's domain.`);
  }
  if (s.dkim === 'FAIL' || s.dkimAligned === false) {
    value += 18;
    reasons.push('The DKIM signature does not authenticate the visible From domain.');
  }
  if (s.dmarc === 'FAIL') {
    value += 20;
    reasons.push('DMARC alignment fails, which is the specific control designed to catch this.');
  }
  if (s.assertedRole && s.claimsInternalIdentity) {
    value += 16;
    reasons.push(`Display name asserts an internal ${s.assertedRole} identity that the sending domain cannot support.`);
  }
  if (s.consumerSender && s.assertedRole) {
    value += 14;
    reasons.push('An executive instruction arriving from a consumer mailbox is inconsistent with corporate mail flow.');
  }

  return component('spoofing', value, reasons, 'The visible sender identity is consistent with the authenticated identity.');
}

function domainDimension(s: AssessmentSignals): ScoreComponent {
  const reasons: string[] = [];
  let value = 0;

  const sending = s.domainIntel.find((entry) => entry.domain === s.fromDomain);

  if (s.fromLookalike) {
    value += Math.min(96, s.fromLookalike.similarity);
    reasons.push(`${s.fromLookalike.similarity}% similarity to ${s.fromLookalike.target} via ${s.fromLookalike.technique.toLowerCase().replace(/_/g, ' ')}.`);
  }
  if (s.fromDomainAgeDays !== null && s.fromDomainAgeDays <= 30) {
    value += 30;
    reasons.push(`Registered ${s.fromDomainAgeDays} day${s.fromDomainAgeDays === 1 ? '' : 's'} before the message was sent.`);
  } else if (s.fromDomainAgeDays !== null && s.fromDomainAgeDays <= 180) {
    value += 12;
    reasons.push(`Domain is ${s.fromDomainAgeDays} days old, which is young for established correspondence.`);
  }
  if (sending?.reputation === 'MALICIOUS') {
    value += 24;
    reasons.push('Sending domain carries a malicious reputation in the bundled intelligence set.');
  } else if (sending?.reputation === 'SUSPICIOUS') {
    value += 12;
    reasons.push('Sending domain carries a suspicious reputation.');
  }
  const listed = sending?.blacklists.filter((entry) => entry.listed) ?? [];
  if (listed.length > 0) {
    value += 8 * listed.length;
    reasons.push(`Listed on ${listed.map((entry) => entry.source).join(', ')}.`);
  }
  if (sending?.mxRecords.some((mx) => mx.suspicious)) {
    value += 10;
    reasons.push('Mail exchanger points at infrastructure dedicated to this domain rather than a recognised provider.');
  }
  if (sending && sending.mxRecords.length === 0 && sending.registrar) {
    value += 8;
    reasons.push('No MX records are published, so the domain cannot receive replies it appears to invite.');
  }
  if (s.disposableReplyTo) {
    value += 20;
    reasons.push('Reply channel uses a disposable mail provider.');
  }

  return component('domain_risk', value, reasons, 'Sending domain shows no registration or reputation concerns.');
}

function socialEngineeringDimension(s: AssessmentSignals): ScoreComponent {
  const reasons: string[] = [];
  const value = s.language.score;

  if (s.language.categories.length > 0) {
    const named = s.language.categories.map((category) => PRESSURE_LABELS[category].toLowerCase());
    reasons.push(`${s.language.hits.length} manipulation cue${s.language.hits.length === 1 ? '' : 's'} across ${s.language.categories.length} technique${s.language.categories.length === 1 ? '' : 's'}: ${named.join(', ')}.`);
  }
  if (hasAll(s.language.categories, ['URGENCY', 'AUTHORITY'])) {
    reasons.push('Urgency combined with authority pressure is the standard pretext structure for payment fraud.');
  }
  if (s.language.categories.includes('PROCESS_BYPASS')) {
    reasons.push('The message pre-empts the verification step that would expose it.');
  }

  return component(
    'social_engineering',
    value,
    reasons,
    'Message language shows no recognised manipulation pattern.',
  );
}

function headerDimension(s: AssessmentSignals): ScoreComponent {
  const reasons: string[] = [];
  let value = 0;

  const weighted = s.headerAnomalies.reduce(
    (sum, anomaly) => sum + (anomaly.severity === 'CRITICAL' ? 30 : anomaly.severity === 'HIGH' ? 22 : anomaly.severity === 'MEDIUM' ? 12 : 5),
    0,
  );
  value += weighted;
  if (s.headerAnomalies.length > 0) {
    reasons.push(`${s.headerAnomalies.length} header field${s.headerAnomalies.length === 1 ? '' : 's'} deviate from expected structure: ${s.headerAnomalies.map((a) => a.name).join(', ')}.`);
  }
  if (s.timestampAnomalies.length > 0) {
    value += 18;
    reasons.push(`Relay chronology is inconsistent (${s.timestampAnomalies.length} anomal${s.timestampAnomalies.length === 1 ? 'y' : 'ies'}).`);
  }
  if (s.chainLength === 0) {
    value += 25;
    reasons.push('No Received headers are present, so the transport path cannot be reconstructed.');
  } else if (s.chainLength === 1) {
    value += 10;
    reasons.push('Only one Received header is present, which is unusually short for inter-organisation mail.');
  }
  if (!s.messageIdDomain) {
    value += 12;
    reasons.push('Message-ID is absent or malformed — most legitimate MTAs always generate one.');
  }

  return component('header_anomaly', value, reasons, 'Header structure is consistent with normal mail transport.');
}

function ipDimension(s: AssessmentSignals): ScoreComponent {
  const reasons: string[] = [];
  let value = 0;

  const malicious = s.ipIntel.filter((entry) => entry.reputation === 'MALICIOUS');
  const suspicious = s.ipIntel.filter((entry) => entry.reputation === 'SUSPICIOUS');

  if (malicious.length > 0) {
    value += 55;
    reasons.push(`${malicious.length} relay address${malicious.length === 1 ? '' : 'es'} carr${malicious.length === 1 ? 'ies' : 'y'} a malicious reputation.`);
  }
  if (suspicious.length > 0) {
    value += 28;
    reasons.push(`${suspicious.length} relay address${suspicious.length === 1 ? '' : 'es'} sit${suspicious.length === 1 ? 's' : ''} in networks associated with abuse.`);
  }
  const listed = s.ipIntel.flatMap((entry) => entry.blacklists.filter((b) => b.listed));
  if (listed.length > 0) {
    value += 6 * listed.length;
    reasons.push(`${listed.length} blocklist hit${listed.length === 1 ? '' : 's'} across the relay path.`);
  }
  if (s.origin.proxyOrVpnIndicator === 'DETECTED') {
    value += 18;
    reasons.push('The observed source sits in commercial VPN space, obscuring the true client network.');
  }
  if (s.origin.torIndicator === 'DETECTED') {
    value += 25;
    reasons.push('The observed source is a Tor exit relay.');
  }
  if (s.hops.some((hop) => hop.trust === 'SUSPICIOUS')) {
    value += 14;
    reasons.push('At least one hop could not be reconciled with legitimate mail infrastructure.');
  }
  if (s.origin.hostingType === 'DATACENTER' && s.assertedRole) {
    value += 10;
    reasons.push('An executive instruction originating from hosting infrastructure rather than corporate or consumer access is atypical.');
  }

  return component('ip_reputation', value, reasons, 'Relay addresses resolve to recognised, well-reputed infrastructure.');
}

function attachmentDimension(s: AssessmentSignals): ScoreComponent {
  const reasons: string[] = [];
  let value = 0;

  if (s.attachments.length === 0) {
    return component('attachment_risk', 0, [], 'No attachments are present.');
  }

  for (const attachment of s.attachments) {
    if (attachment.risk === 'CRITICAL') {
      value += 60;
      reasons.push(`${attachment.filename} is a directly executable or script file type.`);
    } else if (attachment.risk === 'HIGH') {
      value += 42;
      reasons.push(`${attachment.filename} can carry active content.`);
    } else if (attachment.risk === 'MEDIUM') {
      value += 18;
      reasons.push(`${attachment.filename} is an archive or container that hides its contents from inspection.`);
    }
  }
  if (s.attachments.length > 3) {
    value += 8;
    reasons.push(`${s.attachments.length} attachments in a single message.`);
  }

  return component('attachment_risk', value, reasons, `${s.attachments.length} attachment${s.attachments.length === 1 ? '' : 's'} present, none of a high-risk type.`);
}

function urlDimension(s: AssessmentSignals): ScoreComponent {
  const reasons: string[] = [];
  let value = 0;

  if (s.urls.length === 0) {
    return component('url_risk', 0, [], 'No links are present in the message body.');
  }

  const critical = s.urls.filter((url) => url.risk === 'CRITICAL').length;
  const high = s.urls.filter((url) => url.risk === 'HIGH').length;
  value += critical * 45 + high * 28;

  if (critical > 0) reasons.push(`${critical} link${critical === 1 ? '' : 's'} rated critical.`);
  if (high > 0) reasons.push(`${high} link${high === 1 ? '' : 's'} rated high risk.`);
  if (s.urls.some((url) => url.mismatchedAnchor)) {
    value += 22;
    reasons.push('Visible link text disguises a different destination.');
  }
  if (s.urlLookalikes.length > 0) {
    value += 20;
    reasons.push(`${s.urlLookalikes.length} link host${s.urlLookalikes.length === 1 ? '' : 's'} imitate${s.urlLookalikes.length === 1 ? 's' : ''} a known brand.`);
  }

  return component('url_risk', value, reasons, `${s.urls.length} link${s.urls.length === 1 ? '' : 's'} present, none matching a known abuse pattern.`);
}

function hasAll(categories: PressureCategory[], required: PressureCategory[]): boolean {
  return required.every((category) => categories.includes(category));
}

/* ------------------------------------------------------------------ */
/* Findings                                                            */
/* ------------------------------------------------------------------ */

const SEVERITY_MASS: Record<Severity, number> = {
  CRITICAL: 1,
  HIGH: 0.75,
  MEDIUM: 0.45,
  LOW: 0.2,
  INFO: 0.05,
};

function buildFindings(s: AssessmentSignals): Finding[] {
  const findings: Finding[] = [];
  const add = (
    id: string,
    label: string,
    severity: Severity,
    evidence: string,
    contribution: number,
  ) => findings.push({ id, label, severity, evidence, contribution });

  if (s.fromLookalike) {
    add(
      'lookalike-domain',
      'Lookalike sending domain detected',
      'CRITICAL',
      `${s.fromDomain} is ${s.fromLookalike.similarity}% similar to ${s.fromLookalike.target}. ${s.fromLookalike.explanation}`,
      0.95,
    );
  }
  if (s.assertedRole && s.claimsInternalIdentity) {
    add(
      'executive-impersonation',
      'Executive identity asserted without supporting authentication',
      'CRITICAL',
      `The display name presents ${s.displayName ?? 'an internal executive'}${s.assertedRole ? ` (${s.assertedRole})` : ''}${s.impersonatedOrganisation ? ` of ${s.impersonatedOrganisation}` : ''}, but the message is sent from ${s.fromDomain}, which is unrelated to that organisation.`,
      0.9,
    );
  }
  if (s.dmarc === 'FAIL') {
    add(
      'dmarc-failure',
      'DMARC alignment failure',
      'CRITICAL',
      `No authenticated identifier aligns with ${s.fromDomain}.${s.dmarcEnforced ? '' : ' The published policy is p=none, which is why the message was still delivered.'}`,
      0.85,
    );
  } else if (s.dmarc === 'NONE') {
    add(
      'dmarc-absent',
      'No DMARC policy published',
      'MEDIUM',
      `${s.fromDomain} publishes no DMARC record, so a receiving server has no instruction for handling authentication failures on this domain.`,
      0.5,
    );
  }
  if (s.spf === 'FAIL') {
    add(
      'spf-failure',
      'SPF authorisation failure',
      'HIGH',
      `The host that delivered this message is not authorised to send for ${s.fromDomain} by that domain's own published policy.`,
      0.8,
    );
  } else if (s.spf === 'SOFTFAIL') {
    add('spf-softfail', 'SPF soft failure', 'MEDIUM', `${s.fromDomain} marks the sending host as unauthorised but requests only soft handling.`, 0.45);
  }
  if (s.dkim === 'FAIL' || s.dkimAligned === false) {
    add(
      'dkim-failure',
      'DKIM signature does not cover the visible sender',
      'HIGH',
      s.dkimAligned === false
        ? `The signature authenticates a different domain to the one shown in the From header, so it proves nothing about ${s.fromDomain}.`
        : 'The DKIM signature is present but does not validate against the sending domain.',
      0.7,
    );
  } else if (s.dkim === 'NONE') {
    add('dkim-absent', 'Message is unsigned', 'MEDIUM', 'No DKIM signature is present, so message integrity and sender domain cannot be cryptographically confirmed.', 0.4);
  }
  if (s.replyToDomain && s.replyToDomain !== s.fromDomain) {
    add(
      'reply-to-mismatch',
      'Reply-To differs from sender domain',
      s.disposableReplyTo ? 'CRITICAL' : 'HIGH',
      `Replies are directed to ${s.replyToDomain} instead of ${s.fromDomain}, which routes the conversation to infrastructure the apparent sender does not control.`,
      0.8,
    );
  }
  if (s.returnPathDomain && s.returnPathDomain !== s.fromDomain) {
    add(
      'return-path-mismatch',
      'Envelope sender differs from visible sender',
      'MEDIUM',
      `Bounces return to ${s.returnPathDomain} rather than ${s.fromDomain}, indicating the message was injected through third-party infrastructure.`,
      0.6,
    );
  }
  if (s.language.categories.includes('PAYMENT_DIVERSION')) {
    add(
      'payment-diversion',
      'Payment diversion language detected',
      'CRITICAL',
      quoteEvidence(s.language, 'PAYMENT_DIVERSION') ?? 'The message requests a change to payment or beneficiary details.',
      0.95,
    );
  }
  if (s.language.categories.includes('CREDENTIAL_HARVESTING')) {
    add(
      'credential-harvesting',
      'Credential solicitation detected',
      'CRITICAL',
      quoteEvidence(s.language, 'CREDENTIAL_HARVESTING') ?? 'The message asks the recipient to supply or confirm authentication details.',
      0.9,
    );
  }
  const pressure = s.language.categories.filter((category) =>
    (['URGENCY', 'AUTHORITY', 'SECRECY', 'PROCESS_BYPASS', 'CONSEQUENCE_THREAT'] as PressureCategory[]).includes(category),
  );
  if (pressure.length >= 2) {
    add(
      'social-engineering',
      'Layered social-engineering pressure',
      pressure.length >= 3 ? 'HIGH' : 'MEDIUM',
      `The message combines ${pressure.map((category) => PRESSURE_LABELS[category].toLowerCase()).join(', ')}${s.language.keyPhrases[0] ? ` — for example: “${s.language.keyPhrases[0]}”` : ''}.`,
      pressure.length >= 3 ? 0.75 : 0.5,
    );
  }
  if (s.fromDomainAgeDays !== null && s.fromDomainAgeDays <= 30) {
    add(
      'new-domain',
      'Newly registered sending domain',
      'HIGH',
      `${s.fromDomain} was registered ${s.fromDomainAgeDays} day${s.fromDomainAgeDays === 1 ? '' : 's'} before this message was sent. Campaign infrastructure is typically used within weeks of registration.`,
      0.75,
    );
  }
  const dangerous = s.attachments.filter((a) => a.risk === 'CRITICAL' || a.risk === 'HIGH');
  if (dangerous.length > 0) {
    add(
      'attachment-risk',
      'Attachment capable of carrying active content',
      dangerous.some((a) => a.risk === 'CRITICAL') ? 'CRITICAL' : 'HIGH',
      dangerous.map((a) => `${a.filename}${a.note ? ` — ${a.note}` : ''}`).join('; '),
      0.8,
    );
  }
  const badUrls = s.urls.filter((url) => url.risk === 'CRITICAL' || url.risk === 'HIGH');
  if (badUrls.length > 0) {
    add(
      'suspicious-url',
      'Suspicious link destination',
      badUrls.some((url) => url.risk === 'CRITICAL') ? 'HIGH' : 'MEDIUM',
      badUrls.slice(0, 3).map((url) => `${url.host}${url.note ? ` — ${url.note}` : ''}`).join('; '),
      0.65,
    );
  }
  const suspiciousHops = s.hops.filter((hop) => hop.trust === 'SUSPICIOUS');
  if (suspiciousHops.length > 0) {
    add(
      'suspicious-relay',
      'Suspicious relay in transport path',
      'HIGH',
      suspiciousHops
        .map((hop) => `Hop ${hop.index}: ${hop.ip ?? hop.hostname ?? 'unresolved'}${hop.geo ? ` (${hop.geo.country})` : ''}${hop.notes[0] ? ` — ${hop.notes[0]}` : ''}`)
        .join('; '),
      0.7,
    );
  }
  if (s.origin.torIndicator === 'DETECTED' || s.origin.proxyOrVpnIndicator === 'DETECTED') {
    add(
      'anonymised-origin',
      s.origin.torIndicator === 'DETECTED' ? 'Origin traverses the Tor network' : 'Origin traverses anonymising infrastructure',
      'HIGH',
      `The earliest reliable node sits in ${s.origin.torIndicator === 'DETECTED' ? 'Tor exit' : 'commercial VPN'} address space, so the observed address is an egress point rather than the originating network.`,
      0.6,
    );
  }
  if (s.timestampAnomalies.length > 0) {
    add('timestamp-anomaly', 'Relay chronology inconsistent', 'MEDIUM', s.timestampAnomalies.join(' '), 0.5);
  }
  if (s.consumerSender && s.assertedRole) {
    add(
      'consumer-mailbox',
      'Corporate instruction from consumer mailbox',
      'HIGH',
      `An instruction attributed to ${s.assertedRole} arrived from ${s.fromDomain}, a consumer mail provider rather than a corporate domain.`,
      0.7,
    );
  }
  for (const anomaly of s.headerAnomalies) {
    if (findings.some((finding) => finding.evidence.includes(anomaly.name))) continue;
    if (anomaly.severity === 'LOW' || anomaly.severity === 'INFO') continue;
    add(
      `header-${anomaly.name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
      `Header anomaly: ${anomaly.name}`,
      anomaly.severity,
      anomaly.reason,
      anomaly.severity === 'CRITICAL' ? 0.7 : 0.45,
    );
  }

  if (findings.length === 0) {
    add(
      'no-adverse-findings',
      'No adverse indicators identified',
      'INFO',
      `Authentication holds for ${s.fromDomain}, the relay path resolves to recognised infrastructure, and the body contains no recognised manipulation pattern.`,
      0.05,
    );
  }

  return findings.sort(
    (a, b) => SEVERITY_MASS[b.severity] * b.contribution - SEVERITY_MASS[a.severity] * a.contribution,
  );
}

function quoteEvidence(language: LanguageAssessment, category: PressureCategory): string | null {
  const hit = language.hits.find((entry) => entry.category === category);
  if (!hit) return null;
  const phrase = language.keyPhrases.find((sentence) => sentence.toLowerCase().includes(hit.match.toLowerCase()));
  return phrase ? `“${phrase}”` : `Matched phrase: “${hit.match}”.`;
}

/* ------------------------------------------------------------------ */
/* Classification                                                      */
/* ------------------------------------------------------------------ */

function classify(s: AssessmentSignals, score: ThreatScore, findings: Finding[]): Classification {
  const has = (id: string) => findings.some((finding) => finding.id === id);
  const authBroken = s.dmarc === 'FAIL' || s.spf === 'FAIL' || s.dkim === 'FAIL' || s.dkimAligned === false;

  // Malware first: a weaponised attachment is the delivery mechanism regardless
  // of the pretext wrapped around it.
  if (s.attachments.some((a) => a.risk === 'CRITICAL')) return 'MALWARE';

  // Business email compromise is specifically financial fraud carried by an
  // impersonated internal identity.
  if (has('payment-diversion') && (has('executive-impersonation') || s.assertedRole !== null || authBroken)) {
    return 'BUSINESS_EMAIL_COMPROMISE';
  }
  if (has('credential-harvesting') || (has('suspicious-url') && (s.fromLookalike !== null || authBroken))) {
    return 'PHISHING';
  }
  if (has('lookalike-domain') || has('executive-impersonation')) return 'IMPERSONATION';
  if (has('payment-diversion') || s.language.categories.includes('REWARD_LURE')) return 'FRAUD';
  if (score.total >= 25 || findings.some((finding) => finding.severity === 'HIGH' || finding.severity === 'CRITICAL')) {
    return 'SUSPICIOUS';
  }
  return 'LEGITIMATE';
}

/**
 * Confidence in the assigned label, as a saturating function of accumulated
 * evidence. The 97.5 ceiling is intentional — the engine never claims certainty,
 * because a verdict of this kind is an investigative conclusion, not a proof.
 */
function confidenceFor(classification: Classification, findings: Finding[]): number {
  const mass = findings.reduce(
    (total, finding) => total + finding.contribution * SEVERITY_MASS[finding.severity],
    0,
  );
  const adverse = 100 * (1 - Math.exp(-mass / 2.8));

  if (classification === 'LEGITIMATE') {
    return Math.round(clamp(100 - adverse, 45, 96) * 10) / 10;
  }
  return Math.round(clamp(adverse, 35, 97.5) * 10) / 10;
}

/* ------------------------------------------------------------------ */
/* Narrative, techniques and actions                                   */
/* ------------------------------------------------------------------ */

const CLASSIFICATION_OPENERS: Record<Classification, string> = {
  BUSINESS_EMAIL_COMPROMISE:
    'This message shows the structure of a business email compromise attempt: an impersonated position of authority instructing a change to payment details.',
  PHISHING: 'This message is structured to harvest credentials or account access.',
  IMPERSONATION: 'This message impersonates a trusted identity without attempting credential capture in the body.',
  FRAUD: 'This message is structured to induce a financial transfer under a false pretext.',
  MALWARE: 'This message carries an attachment capable of executing code on the recipient host.',
  SUSPICIOUS: 'This message carries indicators that warrant analyst review but does not match a single attack pattern cleanly.',
  LEGITIMATE: 'No adverse indicators were identified for this message.',
};

function buildNarrative(s: AssessmentSignals, classification: Classification, findings: Finding[]): string {
  const parts: string[] = [CLASSIFICATION_OPENERS[classification]];

  const leading = findings
    .filter((finding) => finding.severity === 'CRITICAL' || finding.severity === 'HIGH')
    .slice(0, 4)
    .map((finding) => finding.label.toLowerCase());

  if (leading.length > 0) {
    parts.push(`The verdict rests primarily on ${joinWithAnd(leading)}.`);
  }

  const authNote = describeAuthentication(s);
  if (authNote) parts.push(authNote);

  if (s.origin.estimatedLocation) {
    parts.push(
      `The earliest reliable node in the relay chain places the associated infrastructure in ${s.origin.estimatedLocation.country}${s.origin.isp ? ` on ${s.origin.isp}` : ''}, at ${s.origin.confidence}% confidence — an investigative lead about infrastructure, not an identification of a person.`,
    );
  }

  if (classification === 'LEGITIMATE') {
    parts.push('Routine handling applies; no containment action is indicated.');
  }

  return parts.join(' ');
}

function describeAuthentication(s: AssessmentSignals): string | null {
  const verdicts = [`SPF ${s.spf}`, `DKIM ${s.dkim}`, `DMARC ${s.dmarc}`];
  const failing = [s.spf, s.dkim, s.dmarc].filter((verdict) => verdict === 'FAIL' || verdict === 'SOFTFAIL').length;
  if (failing === 0) return `Authentication results are ${verdicts.join(', ')}.`;
  return `Authentication results are ${verdicts.join(', ')}, so the visible sender identity is unverified and cannot be relied upon.`;
}

function joinWithAnd(items: string[]): string {
  if (items.length === 1) return items[0];
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}

/** MITRE ATT&CK technique references matched by the engine. */
function techniquesFor(s: AssessmentSignals, classification: Classification, findings: Finding[]): string[] {
  const techniques = new Set<string>();
  const has = (id: string) => findings.some((finding) => finding.id === id);

  if (has('attachment-risk')) techniques.add('T1566.001 — Phishing: Spearphishing Attachment');
  if (has('suspicious-url') || has('credential-harvesting')) techniques.add('T1566.002 — Phishing: Spearphishing Link');
  if (has('credential-harvesting')) techniques.add('T1598 — Phishing for Information');
  if (has('lookalike-domain')) techniques.add('T1583.001 — Acquire Infrastructure: Domains');
  if (has('executive-impersonation') || has('reply-to-mismatch') || s.dmarc === 'FAIL') {
    techniques.add('T1656 — Impersonation');
  }
  if (classification === 'BUSINESS_EMAIL_COMPROMISE' || classification === 'FRAUD') {
    techniques.add('T1657 — Financial Theft');
  }
  if (has('anonymised-origin')) techniques.add('T1090.003 — Proxy: Multi-hop Proxy');
  if (has('consumer-mailbox')) techniques.add('T1585.002 — Establish Accounts: Email Accounts');

  return [...techniques];
}

function actionsFor(
  s: AssessmentSignals,
  classification: Classification,
  score: ThreatScore,
  findings: Finding[],
): RecommendedAction[] {
  if (classification === 'LEGITIMATE' && score.total < 25) {
    return [
      {
        kind: 'NO_ACTION',
        label: 'No containment action required',
        rationale: 'Authentication holds and no adverse indicator was raised. Retain the analysis record for the configured retention period.',
        priority: 'INFO',
      },
    ];
  }

  const actions: RecommendedAction[] = [];
  const urgent = score.level === 'CRITICAL' || score.level === 'HIGH';

  actions.push({
    kind: 'QUARANTINE_EMAIL',
    label: 'Quarantine the message and any copies in other mailboxes',
    rationale: `Classified ${classification.replace(/_/g, ' ').toLowerCase()} at ${score.total}/100. Removing the message prevents further interaction while the investigation proceeds.`,
    priority: urgent ? 'CRITICAL' : 'MEDIUM',
  });

  const blockDomains = [s.fromDomain, s.replyToDomain, s.returnPathDomain]
    .filter((domain): domain is string => Boolean(domain))
    .filter((domain, index, all) => all.indexOf(domain) === index);
  if (blockDomains.length > 0 && classification !== 'LEGITIMATE') {
    actions.push({
      kind: 'BLOCK_DOMAIN',
      label: `Block ${blockDomains.join(', ')} at the mail gateway`,
      rationale: 'All three sender-identity fields resolve to attacker-controlled or unverified domains; blocking them removes the reply channel as well as the send path.',
      priority: urgent ? 'CRITICAL' : 'HIGH',
    });
  }

  const blockIps = s.ipIntel
    .filter((entry) => entry.reputation === 'MALICIOUS' || entry.reputation === 'SUSPICIOUS')
    .map((entry) => entry.ip);
  if (blockIps.length > 0) {
    actions.push({
      kind: 'BLOCK_IP',
      label: `Add ${blockIps.slice(0, 3).join(', ')} to the perimeter blocklist`,
      rationale: 'These relay addresses carry adverse reputation and appear in the transport path for this message.',
      priority: 'HIGH',
    });
  }

  actions.push({
    kind: 'INVESTIGATE_RELATED',
    label: 'Search mail flow for related messages sharing this infrastructure',
    rationale: 'Campaign infrastructure is reused. Pivoting on the sending domain, reply-to domain and relay addresses will surface other recipients targeted by the same operation.',
    priority: urgent ? 'HIGH' : 'MEDIUM',
  });

  if (findings.some((finding) => finding.id === 'payment-diversion')) {
    actions.push({
      kind: 'NOTIFY_RECIPIENT',
      label: 'Contact the recipient and the finance approver out of band',
      rationale: 'The message requests a beneficiary change. Confirm through a known telephone number that no payment has been actioned, and verify any recent beneficiary updates against the original vendor record.',
      priority: 'CRITICAL',
    });
  }

  if (urgent) {
    actions.push({
      kind: 'CREATE_INCIDENT',
      label: 'Raise an incident and assign an investigator',
      rationale: 'Severity and financial exposure justify a tracked case with chain-of-custody records rather than closing at triage.',
      priority: 'HIGH',
    });
  }

  actions.push({
    kind: 'EXPORT_REPORT',
    label: 'Export the forensic report for the case file',
    rationale: 'Preserves the authentication results, relay reconstruction and indicator set with evidence hashes while the underlying infrastructure is still live.',
    priority: 'MEDIUM',
  });

  return actions;
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

export function buildAssessment(s: AssessmentSignals, score: ThreatScore): AiAssessment {
  const findings = buildFindings(s);
  const classification = classify(s, score, findings);

  return {
    classification,
    confidence: confidenceFor(classification, findings),
    narrative: buildNarrative(s, classification, findings),
    findings,
    recommendedActions: actionsFor(s, classification, score, findings),
    modelVersion: MODEL_VERSION,
    techniques: techniquesFor(s, classification, findings),
  };
}
