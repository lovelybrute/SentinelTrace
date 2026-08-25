import { DEMO_MESSAGES } from '@/demo/messages';
import { parseEmail } from '@/lib/emailParser';
import { sha256 } from '@/lib/hash';
import { analyseLocally } from '@/services/localAnalysis';
import { correlate } from '@/services/correlate';
import { domainOf } from '@/lib/format';

const ANALYZED_AT = '2026-08-24T09:20:00.000Z';

for (const message of DEMO_MESSAGES) {
  const digest = await sha256(message.raw);
  const parsed = parseEmail(message.raw);
  const wire = analyseLocally({ raw: message.raw, filename: message.filename, contentHash: digest.hex, analyzedAt: ANALYZED_AT });
  const analysis = correlate({
    wire, parsed, raw: message.raw, filename: message.filename, origin: 'SIMULATED',
    analyzedAt: ANALYZED_AT, contentHash: digest.hex, analystId: 'demo.analyst', acquisitionSource: 'x',
  });
  console.log(`\n=== ${message.id} ===`);
  console.log(`from header: ${JSON.stringify(analysis.metadata.from)}  → domainOf=${domainOf(analysis.metadata.from)}`);
  console.log(`class=${analysis.assessment.classification} level=${analysis.score.level} total=${analysis.score.total}`);
  for (const c of analysis.score.components) {
    console.log(`   ${c.id.padEnd(20)} value=${String(c.value).padStart(3)} weight=${c.weight}  contrib=${(c.value*c.weight).toFixed(1)}`);
  }
  console.log(`findings: ${analysis.assessment.findings.map((f) => `${f.id}(${f.severity})`).join(', ')}`);
}
