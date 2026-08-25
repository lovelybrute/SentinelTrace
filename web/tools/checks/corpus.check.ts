/**
 * Runs every message in the demonstration corpus through the real pipeline and
 * compares the result against the `expected` block declared alongside it.
 *
 *     python3 tools/tsrun.py tools/checks/corpus.check.ts
 *
 * This is not a unit test of a helper — it executes `analyseLocally`, `parseEmail`
 * and `correlate` exactly as the browser will, so a change anywhere in the engine
 * that alters a demonstration verdict fails here rather than on stage.
 *
 * The `expected` values are a contract in both directions. If the engine and the
 * corpus disagree, one of them is wrong: either the sample's headers do not
 * actually support the claim being made about them, or a regression has been
 * introduced. Neither is resolved by editing `expected` until it matches — the
 * question to answer is which side is defensible from the evidence.
 */

import { DEMO_MESSAGES } from '@/demo/messages';
import { parseEmail } from '@/lib/emailParser';
import { sha256 } from '@/lib/hash';
import { analyseLocally } from '@/services/localAnalysis';
import { correlate } from '@/services/correlate';

let failures = 0;
let checks = 0;

function expect(label: string, actual: unknown, expected: unknown): void {
  checks += 1;
  if (JSON.stringify(actual) === JSON.stringify(expected)) {
    console.log(`  ok   ${label}  →  ${JSON.stringify(actual)}`);
  } else {
    failures += 1;
    console.log(`  FAIL ${label}\n         expected ${JSON.stringify(expected)}\n         actual   ${JSON.stringify(actual)}`);
  }
}

const ANALYZED_AT = '2026-08-24T09:20:00.000Z';

for (const message of DEMO_MESSAGES) {
  console.log(`\n${message.id} — ${message.label}`);

  const digest = await sha256(message.raw);
  const parsed = parseEmail(message.raw);
  const wire = analyseLocally({
    raw: message.raw,
    filename: message.filename,
    contentHash: digest.hex,
    analyzedAt: ANALYZED_AT,
  });

  const analysis = correlate({
    wire,
    parsed,
    raw: message.raw,
    filename: message.filename,
    origin: 'SIMULATED',
    analyzedAt: ANALYZED_AT,
    contentHash: digest.hex,
    analystId: 'demo.analyst',
    acquisitionSource: 'Bundled demonstration corpus',
  });

  const verdictOf = (mechanism: string): string | undefined =>
    analysis.authentication.checks.find((check) => check.mechanism === mechanism)?.verdict;

  expect('classification', analysis.assessment.classification, message.expected.classification);
  expect('level', analysis.score.level, message.expected.level);
  expect('SPF', verdictOf('SPF'), message.expected.spf);
  expect('DKIM', verdictOf('DKIM'), message.expected.dkim);
  expect('DMARC', verdictOf('DMARC'), message.expected.dmarc);
  expect(
    'probable origin',
    analysis.originAssessment.estimatedLocation?.country ?? null,
    message.expected.origin,
  );

  // Context for reading a failure above, and a sanity view of what the demo will
  // actually put on screen.
  console.log(
    `       score ${analysis.score.total}/100 · confidence ${analysis.assessment.confidence}% · ` +
      `${analysis.relayChain.length} hops · observed source ${analysis.originAssessment.observedSourceIp ?? 'none'} · ` +
      `${analysis.iocs.length} indicators · ${analysis.assessment.findings.length} findings`,
  );
  console.log(`       leading finding: ${analysis.assessment.findings[0]?.label ?? 'none'}`);
  if (analysis.warnings.length > 0) {
    console.log(`       warnings: ${analysis.warnings.join(' | ')}`);
  }
}

/* ------------------------------------------------------------------ */
/* The primary demonstration carries additional guarantees.            */
/* ------------------------------------------------------------------ */

console.log('\nprimary demonstration — §32 acceptance criteria');

{
  const message = DEMO_MESSAGES[0];
  const digest = await sha256(message.raw);
  const parsed = parseEmail(message.raw);
  const wire = analyseLocally({
    raw: message.raw,
    filename: message.filename,
    contentHash: digest.hex,
    analyzedAt: ANALYZED_AT,
  });
  const analysis = correlate({
    wire,
    parsed,
    raw: message.raw,
    filename: message.filename,
    origin: 'SIMULATED',
    analyzedAt: ANALYZED_AT,
    contentHash: digest.hex,
    analystId: 'demo.analyst',
    acquisitionSource: 'Bundled demonstration corpus',
  });

  expect('sender address', analysis.metadata.from.includes('finance@paypa1-security.com'), true);
  // The boundary hop decides SPF; the origin hop decides geolocation. Both must
  // be recovered, and they must be different addresses, or the sample no longer
  // demonstrates the distinction it exists to teach.
  expect('observed source is the Singapore origin', analysis.originAssessment.observedSourceIp, '203.0.113.47');
  expect(
    'Frankfurt boundary hop is present',
    analysis.relayChain.some((hop) => hop.ip === '198.51.100.77'),
    true,
  );
  expect('evidence digest verified', analysis.evidence.integrity, 'VERIFIED');
  expect('chain of custody recorded', analysis.evidence.custody.length >= 3, true);
  expect(
    'geolocation is worded as an estimate, not an identification',
    /probable|estimated|associated infrastructure/i.test(analysis.assessment.narrative),
    true,
  );
  expect(
    'payment diversion is cited',
    analysis.assessment.findings.some((finding) => finding.id === 'payment-diversion'),
    true,
  );
  expect(
    'a containment action is recommended',
    analysis.assessment.recommendedActions.some((action) => action.kind === 'QUARANTINE_EMAIL'),
    true,
  );
}

console.log(`\n${checks - failures}/${checks} checks passed.`);
if (failures > 0) {
  console.log(`${failures} FAILED`);
  process.exit(1);
}
