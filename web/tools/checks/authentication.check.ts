/**
 * Runtime checks for the authentication evaluator and its correlation wrapper.
 *
 * These execute the real `src/lib/authEval.ts` and
 * `src/services/correlate/authentication.ts` — not a reimplementation — under
 * Node's type stripping. Run with:
 *
 *     python3 tools/tsrun.py tools/checks/authentication.check.ts
 *
 * The property under test throughout is that a verdict is only ever as strong as
 * the evidence behind it. The engine must not report PASS for a policy that is
 * merely published, and equally must not report FAIL for a mechanism it simply
 * could not resolve offline.
 */

import {
  evaluateDmarc,
  evaluateSpf,
  definitiveBackendVerdict,
  firstRecord,
  ipv4InCidr,
  isAligned,
  organisationalDomain,
  parseDkimSignature,
  parseDmarcRecord,
} from '@/lib/authEval';
import { correlateAuthentication } from '@/services/correlate/authentication';
import { lookupDomain } from '@/services/intel/domainDatabase';
import type { WireForensics } from '@/services/wire';

let failures = 0;
let checks = 0;

function expect(label: string, actual: unknown, expected: unknown): void {
  checks += 1;
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a === e) {
    console.log(`  ok   ${label}`);
  } else {
    failures += 1;
    console.log(`  FAIL ${label}\n         expected ${e}\n         actual   ${a}`);
  }
}

function section(title: string): void {
  console.log(`\n${title}`);
}

/* ------------------------------------------------------------------ */
section('CIDR membership');

expect('address inside /24', ipv4InCidr('203.0.113.47', '203.0.113.0/24'), true);
expect('address outside /24', ipv4InCidr('198.51.100.77', '203.0.113.0/24'), false);
expect('boundary low', ipv4InCidr('203.0.113.0', '203.0.113.0/24'), true);
expect('boundary high', ipv4InCidr('203.0.113.255', '203.0.113.0/24'), true);
expect('just past boundary', ipv4InCidr('203.0.114.0', '203.0.113.0/24'), false);
expect('bare address is /32', ipv4InCidr('203.0.113.47', '203.0.113.47'), true);
expect('/32 rejects neighbour', ipv4InCidr('203.0.113.48', '203.0.113.47/32'), false);
expect('/0 matches everything', ipv4InCidr('8.8.8.8', '0.0.0.0/0'), true);
// A /31 exercises the mask shift at its widest, where a naive `<<` overflows.
expect('/31 pair member', ipv4InCidr('192.0.2.1', '192.0.2.0/31'), true);
expect('/31 non-member', ipv4InCidr('192.0.2.2', '192.0.2.0/31'), false);
expect('malformed octet is not a match', ipv4InCidr('203.0.113.999', '203.0.113.0/24'), false);

/* ------------------------------------------------------------------ */
section('SPF evaluation');

const attackerSpf = 'v=spf1 ip4:203.0.113.0/24 -all';

// The heart of the demo: the message originates inside the authorised range but
// is relayed in from outside it. Evaluating at the boundary must fail.
expect('boundary outside range fails', evaluateSpf(attackerSpf, '198.51.100.77').verdict, 'FAIL');
expect('boundary failure is definitive', evaluateSpf(attackerSpf, '198.51.100.77').definitive, true);
expect('origin inside range passes', evaluateSpf(attackerSpf, '203.0.113.47').verdict, 'PASS');
expect(
  'matched mechanism is reported',
  evaluateSpf(attackerSpf, '203.0.113.47').matchedMechanism,
  'ip4:203.0.113.0/24',
);
expect('no policy is NONE', evaluateSpf(null, '198.51.100.77').verdict, 'NONE');
expect('no observed IP is inconclusive', evaluateSpf(attackerSpf, null).definitive, false);
expect('softfail honoured', evaluateSpf('v=spf1 ip4:10.0.0.0/8 ~all', '198.51.100.77').verdict, 'SOFTFAIL');
expect('neutral qualifier honoured', evaluateSpf('v=spf1 ?all', '198.51.100.77').verdict, 'NEUTRAL');

// An unresolvable include must not be reported as a confirmed failure: the
// delegated record could well authorise the sender.
const delegated = evaluateSpf('v=spf1 include:spf.protection.outlook.com -all', '40.107.20.55');
expect('unresolved include is not FAIL', delegated.verdict, 'NEUTRAL');
expect('unresolved include is not definitive', delegated.definitive, false);
expect('unresolved mechanism is named', delegated.unresolved, ['include:spf.protection.outlook.com']);

// An explicit match ahead of the include still decides the result.
const early = evaluateSpf('v=spf1 ip4:198.51.100.0/24 include:example.net -all', '198.51.100.77');
expect('explicit match wins over later include', early.verdict, 'PASS');
expect('explicit match is definitive', early.definitive, true);

/* ------------------------------------------------------------------ */
section('Organisational domain and alignment');

expect('two-label domain', organisationalDomain('paypal.com'), 'paypal.com');
expect('subdomain reduced', organisationalDomain('mail.paypal.com'), 'paypal.com');
expect('multi-part suffix', organisationalDomain('nexoragroup.co.in'), 'nexoragroup.co.in');
expect('subdomain of multi-part suffix', organisationalDomain('mail.nexoragroup.co.in'), 'nexoragroup.co.in');

expect('relaxed alignment accepts subdomain', isAligned('mail.example.com', 'example.com'), true);
expect('strict alignment rejects subdomain', isAligned('mail.example.com', 'example.com', 'STRICT'), false);
expect('unrelated domains never align', isAligned('paypal.com', 'paypa1-security.com'), false);
expect('lookalike does not align', isAligned('paypa1-security.com', 'paypal.com'), false);
expect('unknown identifier is null', isAligned(null, 'example.com'), null);

/* ------------------------------------------------------------------ */
section('DKIM signature parsing');

const attackerDkim =
  'v=1; a=rsa-sha256; c=relaxed/relaxed; d=paypal.com; s=selector1; ' +
  'h=from:to:subject:date; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; b=dGVzdA==';

expect('signing domain extracted', parseDkimSignature(attackerDkim).domain, 'paypal.com');
expect('selector extracted', parseDkimSignature(attackerDkim).selector, 'selector1');
expect('algorithm extracted', parseDkimSignature(attackerDkim).algorithm, 'rsa-sha256');
expect('signed headers listed', parseDkimSignature(attackerDkim).signedHeaders, [
  'from',
  'to',
  'subject',
  'date',
]);
expect('body hash not truncated', parseDkimSignature(attackerDkim).bodyHashTruncated, false);
expect('l= flags truncation', parseDkimSignature(`${attackerDkim}; l=42`).bodyHashTruncated, true);
// `d=` must not be matched inside another tag's value.
expect(
  'd= not matched inside bh=',
  parseDkimSignature('v=1; bh=abcd=efg; d=real.example; s=s1').domain,
  'real.example',
);
expect('absent signature yields nulls', parseDkimSignature(null).domain, null);

/* ------------------------------------------------------------------ */
section('DMARC record parsing');

const quarantine = parseDmarcRecord('v=DMARC1; p=quarantine; rua=mailto:d@x.in; adkim=s; aspf=s');
expect('policy read', quarantine?.policy, 'quarantine');
expect('strict dkim alignment read', quarantine?.dkimAlignment, 'STRICT');
expect('strict spf alignment read', quarantine?.spfAlignment, 'STRICT');
expect('reporting address read', quarantine?.reportingAddresses, ['d@x.in']);
expect('default alignment is relaxed', parseDmarcRecord('v=DMARC1; p=none')?.dkimAlignment, 'RELAXED');
expect('default percentage', parseDmarcRecord('v=DMARC1; p=none')?.percentage, 100);
// `p=` must be read from the policy tag, not from `sp=`.
expect('sp= does not shadow p=', parseDmarcRecord('v=DMARC1; p=none; sp=reject')?.policy, 'none');
expect('sp= captured separately', parseDmarcRecord('v=DMARC1; p=none; sp=reject')?.subdomainPolicy, 'reject');

/* ------------------------------------------------------------------ */
section('DMARC evaluation');

const spoofed = evaluateDmarc({
  record: 'v=DMARC1; p=none; rua=mailto:dmarc@paypa1-security.com; pct=100',
  fromDomain: 'paypa1-security.com',
  spfVerdict: 'FAIL',
  spfDomain: 'paypa1-security.com',
  dkimVerdict: 'FAIL',
  dkimDomain: 'paypal.com',
});
expect('two settled failures give FAIL', spoofed.verdict, 'FAIL');
expect('p=none means delivered', spoofed.disposition, 'NONE');

// The mirror-image error: an unverifiable mechanism must not manufacture a FAIL.
const unresolvable = evaluateDmarc({
  record: 'v=DMARC1; p=reject',
  fromDomain: 'nexoragroup.in',
  spfVerdict: 'NEUTRAL',
  spfDomain: 'nexoragroup.in',
  dkimVerdict: 'NEUTRAL',
  dkimDomain: 'nexoragroup.in',
});
expect('unresolved mechanisms give NEUTRAL', unresolvable.verdict, 'NEUTRAL');
expect('inconclusive carries no disposition', unresolvable.disposition, 'NOT_APPLICABLE');

const aligned = evaluateDmarc({
  record: 'v=DMARC1; p=reject',
  fromDomain: 'example.com',
  spfVerdict: 'PASS',
  spfDomain: 'mail.example.com',
  dkimVerdict: 'NONE',
  dkimDomain: null,
});
expect('aligned SPF pass satisfies DMARC', aligned.verdict, 'PASS');

// A pass for infrastructure the attacker owns must not satisfy DMARC.
const misaligned = evaluateDmarc({
  record: 'v=DMARC1; p=reject',
  fromDomain: 'paypal.com',
  spfVerdict: 'PASS',
  spfDomain: 'paypa1-security.com',
  dkimVerdict: 'NONE',
  dkimDomain: null,
});
expect('unaligned SPF pass still fails DMARC', misaligned.verdict, 'FAIL');
expect('enforcing policy rejects', misaligned.disposition, 'REJECT');

expect('no DMARC record is NONE', evaluateDmarc({
  record: null,
  fromDomain: 'example.com',
  spfVerdict: 'PASS',
  spfDomain: 'example.com',
  dkimVerdict: 'PASS',
  dkimDomain: 'example.com',
}).verdict, 'NONE');

/* ------------------------------------------------------------------ */
section('Backend status handling');

// The regression this whole exercise exists to prevent: the backend says "pass"
// when a record is merely published. That must never become a PASS verdict.
expect('backend pass is not a verdict', definitiveBackendVerdict('pass'), null);
expect('backend signed is not a verdict', definitiveBackendVerdict('signed'), null);
expect('backend domain_mismatch is re-derived', definitiveBackendVerdict('domain_mismatch'), null);
expect('genuine absence is NONE', definitiveBackendVerdict('no_spf'), 'NONE');
expect('missing is NONE', definitiveBackendVerdict('missing'), 'NONE');
expect('failed lookup is ERROR', definitiveBackendVerdict('dns_unavailable'), 'ERROR');
expect('undefined status is not a verdict', definitiveBackendVerdict(undefined), null);

expect('first non-empty record wins', firstRecord(['', '  ', 'v=spf1 -all']), 'v=spf1 -all');
expect('absent records yield null', firstRecord(undefined), null);
expect('all-empty records yield null', firstRecord(['', '   ']), null);

/* ------------------------------------------------------------------ */
section('Correlated authentication — the §32 demo message');

/** The backend reporting its optimistic "everything is published" result. */
const optimisticForensics: WireForensics = {
  authentication: {
    sender: 'finance@paypa1-security.com',
    sender_domain: 'paypa1-security.com',
    dkim: { valid: true, status: 'signed', message: 'Email is DKIM signed' },
    spf: {
      found: true,
      status: 'pass',
      message: 'Valid SPF record found',
      records: ['v=spf1 ip4:203.0.113.0/24 -all'],
    },
    dmarc: {
      found: true,
      status: 'pass',
      message: 'DMARC policy: none',
      policy: 'none',
      records: ['v=DMARC1; p=none; rua=mailto:dmarc@paypa1-security.com; pct=100'],
    },
    // High trust purely because records exist — the figure that must be ignored.
    overall_trust_score: 100,
  },
  spoofing_analysis: { detected: true, confidence: 0.9, factors: [] },
  header_chain: { chain_length: 3, anomalies: [] },
};

const demo = correlateAuthentication({
  fromDomain: 'paypa1-security.com',
  dkimSignature: attackerDkim,
  returnPathDomain: 'bounce.paypa1-security.com',
  senderDomainRecord: lookupDomain('paypa1-security.com'),
  // The boundary hop — Frankfurt — not the Singapore origin.
  observedIp: '198.51.100.77',
  wireForensics: optimisticForensics,
  origin: 'LIVE_BACKEND',
});

expect('SPF FAIL despite backend "pass"', demo.spf, 'FAIL');
expect('DKIM FAIL despite backend "signed"', demo.dkim, 'FAIL');
expect('DMARC FAIL despite backend "pass"', demo.dmarc, 'FAIL');
expect('DKIM does not align', demo.dkimAligned, false);
expect('p=none is not enforcement', demo.dmarcEnforced, false);
// 50 − 20 (SPF) − 15 (DKIM) − 15 (DMARC) = 0.
expect('trust score ignores backend 100', demo.summary.trustScore, 0);
expect('three checks reported', demo.summary.checks.length, 3);
expect(
  'SPF row cites the real record',
  demo.summary.checks[0]?.raw,
  'v=spf1 ip4:203.0.113.0/24 -all',
);

// Evaluating at the origin instead of the boundary is the inversion the
// correlation layer must never reintroduce.
const atOrigin = correlateAuthentication({
  fromDomain: 'paypa1-security.com',
  dkimSignature: attackerDkim,
  returnPathDomain: 'bounce.paypa1-security.com',
  senderDomainRecord: lookupDomain('paypa1-security.com'),
  observedIp: '203.0.113.47',
  wireForensics: optimisticForensics,
  origin: 'LIVE_BACKEND',
});
expect('origin IP would have passed SPF (documents the trap)', atOrigin.spf, 'PASS');

/* ------------------------------------------------------------------ */
section('Correlated authentication — legitimate sender');

const legitimate = correlateAuthentication({
  fromDomain: 'nexoragroup.in',
  dkimSignature:
    'v=1; a=rsa-sha256; d=nexoragroup.in; s=selector1; h=from:to:subject; bh=abc=; b=def=',
  returnPathDomain: 'nexoragroup.in',
  senderDomainRecord: lookupDomain('nexoragroup.in'),
  observedIp: '40.107.20.55',
  wireForensics: null,
  origin: 'SIMULATED',
});
expect('unresolvable include is not a FAIL', legitimate.spf, 'NEUTRAL');
expect('aligned signature is not falsely PASS', legitimate.dkim, 'NEUTRAL');
expect('aligned signature is aligned', legitimate.dkimAligned, true);
expect('inconclusive SPF+DKIM leaves DMARC open', legitimate.dmarc, 'NEUTRAL');
expect('quarantine policy is enforcement', legitimate.dmarcEnforced, true);
expect('legitimate sender is not scored at zero', legitimate.summary.trustScore, 50);

/* ------------------------------------------------------------------ */
section('Provenance labelling');

const simulated = correlateAuthentication({
  fromDomain: 'unknown-domain-not-in-corpus.test',
  dkimSignature: '',
  returnPathDomain: null,
  senderDomainRecord: null,
  observedIp: '198.51.100.77',
  wireForensics: {
    ...optimisticForensics,
    authentication: {
      ...optimisticForensics.authentication,
      spf: { found: true, status: 'pass', message: '', records: ['v=spf1 -all'] },
    },
  },
  origin: 'SIMULATED',
});
expect(
  'simulated mode never claims live DNS',
  simulated.summary.checks[0]?.detail.includes('resolved from live DNS'),
  false,
);
expect(
  'live backend does claim live DNS',
  demo.summary.checks[0]?.detail.includes('offline intelligence set'),
  true,
);

/* ------------------------------------------------------------------ */
console.log(`\n${checks - failures}/${checks} checks passed.`);
if (failures > 0) {
  console.log(`${failures} FAILED`);
  process.exit(1);
}
