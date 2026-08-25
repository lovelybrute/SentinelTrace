/**
 * Social-engineering language analysis.
 *
 * A lexicon-and-pattern model over the message body. It is deliberately
 * transparent rather than a black box: every hit records the exact matched span
 * so the interface can highlight the phrase in the original text and the analyst
 * can judge the finding instead of trusting a score.
 */

export type PressureCategory =
  | 'URGENCY'
  | 'AUTHORITY'
  | 'SECRECY'
  | 'PAYMENT_DIVERSION'
  | 'CREDENTIAL_HARVESTING'
  | 'CONSEQUENCE_THREAT'
  | 'REWARD_LURE'
  | 'PROCESS_BYPASS';

export interface PressureHit {
  category: PressureCategory;
  /** The exact text that matched, as it appears in the body. */
  match: string;
  /** Character offset into the analysed text. */
  start: number;
  end: number;
  weight: number;
}

export interface LanguageAssessment {
  hits: PressureHit[];
  /** Distinct categories triggered. */
  categories: PressureCategory[];
  /** 0–100 risk contribution from language alone. */
  score: number;
  /** Sentences that carry the highest concentration of pressure signals. */
  keyPhrases: string[];
  wordCount: number;
}

export const PRESSURE_LABELS: Record<PressureCategory, string> = {
  URGENCY: 'Artificial urgency',
  AUTHORITY: 'Authority pressure',
  SECRECY: 'Secrecy request',
  PAYMENT_DIVERSION: 'Payment diversion',
  CREDENTIAL_HARVESTING: 'Credential harvesting',
  CONSEQUENCE_THREAT: 'Threatened consequence',
  REWARD_LURE: 'Reward lure',
  PROCESS_BYPASS: 'Process bypass',
};

export const PRESSURE_DESCRIPTIONS: Record<PressureCategory, string> = {
  URGENCY: 'Compresses the recipient’s decision window so verification feels impossible.',
  AUTHORITY: 'Invokes seniority or institutional power to discourage questioning.',
  SECRECY: 'Discourages the recipient from consulting colleagues who would catch the fraud.',
  PAYMENT_DIVERSION: 'Attempts to redirect funds to attacker-controlled account details.',
  CREDENTIAL_HARVESTING: 'Solicits authentication material or directs to a credential capture page.',
  CONSEQUENCE_THREAT: 'Threatens loss, penalty or suspension to force compliance.',
  REWARD_LURE: 'Offers an unexpected benefit to motivate an unsafe action.',
  PROCESS_BYPASS: 'Asks the recipient to circumvent a normal control or approval step.',
};

/**
 * Patterns are word-boundary anchored and case-insensitive. Weights are tuned so
 * that a single generic word cannot on its own produce a high score — the model
 * rewards *combinations*, which is what real pretexting looks like.
 */
const LEXICON: { category: PressureCategory; pattern: RegExp; weight: number }[] = [
  // Urgency
  { category: 'URGENCY', pattern: /\burgent(?:ly)?\b/gi, weight: 6 },
  { category: 'URGENCY', pattern: /\bimmediate(?:ly)?\b/gi, weight: 6 },
  { category: 'URGENCY', pattern: /\bas soon as possible\b/gi, weight: 4 },
  { category: 'URGENCY', pattern: /\bwithin\s+(?:the\s+next\s+)?\d+\s*(?:minutes?|hours?|hrs?)\b/gi, weight: 8 },
  { category: 'URGENCY', pattern: /\bbefore (?:close of business|end of day|cob|eod)\b/gi, weight: 7 },
  { category: 'URGENCY', pattern: /\btime[- ]sensitive\b/gi, weight: 6 },
  { category: 'URGENCY', pattern: /\bexpires? (?:today|in|within)\b/gi, weight: 7 },
  { category: 'URGENCY', pattern: /\blast (?:chance|warning|reminder)\b/gi, weight: 7 },
  { category: 'URGENCY', pattern: /\bright away\b/gi, weight: 4 },
  { category: 'URGENCY', pattern: /\bdo not delay\b/gi, weight: 7 },

  // Authority
  { category: 'AUTHORITY', pattern: /\b(?:ceo|cfo|coo|cto|managing director|chairman|director)\b/gi, weight: 6 },
  { category: 'AUTHORITY', pattern: /\bon behalf of (?:the )?(?:ceo|cfo|management|board|director)\b/gi, weight: 8 },
  { category: 'AUTHORITY', pattern: /\b(?:i am|this is) (?:writing|contacting you) (?:on|at) the (?:instruction|request|direction) of\b/gi, weight: 8 },
  { category: 'AUTHORITY', pattern: /\bapproved by (?:the )?(?:board|management|finance|director)\b/gi, weight: 5 },
  { category: 'AUTHORITY', pattern: /\b(?:income tax|it department|police|cyber cell|enforcement directorate|reserve bank)\b/gi, weight: 6 },
  { category: 'AUTHORITY', pattern: /\bcompliance (?:team|department|requirement)\b/gi, weight: 4 },

  // Secrecy
  { category: 'SECRECY', pattern: /\b(?:strictly )?confidential(?:ly)?\b/gi, weight: 6 },
  { category: 'SECRECY', pattern: /\bdo not (?:discuss|share|forward|mention) this\b/gi, weight: 10 },
  { category: 'SECRECY', pattern: /\bkeep this (?:between us|discreet|private|quiet)\b/gi, weight: 10 },
  { category: 'SECRECY', pattern: /\bwithout (?:informing|involving|notifying) (?:anyone|others|the team)\b/gi, weight: 10 },
  { category: 'SECRECY', pattern: /\bdiscreet(?:ly|ion)?\b/gi, weight: 5 },

  // Payment diversion
  { category: 'PAYMENT_DIVERSION', pattern: /\b(?:updated?|new|revised|changed?|alternate) (?:bank(?:ing)?|account|remittance|payment) (?:details?|information|instructions?|coordinates)\b/gi, weight: 14 },
  { category: 'PAYMENT_DIVERSION', pattern: /\bchange (?:of|the) (?:bank|account|beneficiary)\b/gi, weight: 13 },
  { category: 'PAYMENT_DIVERSION', pattern: /\b(?:wire|remit|transfer) (?:the )?(?:funds?|payment|amount|balance)\b/gi, weight: 10 },
  { category: 'PAYMENT_DIVERSION', pattern: /\bbeneficiary (?:name|account|details?)\b/gi, weight: 9 },
  { category: 'PAYMENT_DIVERSION', pattern: /\b(?:ifsc|swift|iban|routing|sort) (?:code|number)?\b/gi, weight: 8 },
  { category: 'PAYMENT_DIVERSION', pattern: /\baccount (?:number|no\.?)\s*[:#]?\s*[\dxX*]{6,}/gi, weight: 12 },
  { category: 'PAYMENT_DIVERSION', pattern: /\bredirect (?:the )?payment\b/gi, weight: 13 },
  { category: 'PAYMENT_DIVERSION', pattern: /\b(?:outstanding|pending) invoice\b/gi, weight: 6 },
  { category: 'PAYMENT_DIVERSION', pattern: /\bvendor (?:payment|account) (?:update|change)\b/gi, weight: 12 },

  // Credential harvesting
  { category: 'CREDENTIAL_HARVESTING', pattern: /\b(?:verify|confirm|validate|re-?enter) your (?:account|identity|credentials?|password|login|details)\b/gi, weight: 12 },
  { category: 'CREDENTIAL_HARVESTING', pattern: /\b(?:click|tap) (?:here|the link|below) to (?:verify|confirm|log ?in|sign ?in|unlock|restore)\b/gi, weight: 12 },
  { category: 'CREDENTIAL_HARVESTING', pattern: /\b(?:username|password|otp|one[- ]time password|pin|cvv|mpin)\b/gi, weight: 10 },
  { category: 'CREDENTIAL_HARVESTING', pattern: /\bupdate your (?:kyc|pan|aadhaar|payment method)\b/gi, weight: 11 },
  { category: 'CREDENTIAL_HARVESTING', pattern: /\bsign in (?:to|and) (?:review|confirm|continue)\b/gi, weight: 8 },
  { category: 'CREDENTIAL_HARVESTING', pattern: /\breset your password\b/gi, weight: 7 },

  // Consequence threats
  { category: 'CONSEQUENCE_THREAT', pattern: /\baccount (?:will be |has been )?(?:suspend|lock|block|disabl|clos|terminat)\w*\b/gi, weight: 11 },
  { category: 'CONSEQUENCE_THREAT', pattern: /\b(?:legal action|prosecution|penalt(?:y|ies))\b/gi, weight: 9 },
  // "fine" is a threat only in a monetary or statutory frame. Unqualified, it is
  // one of the most common words in ordinary business mail — "Thursday is fine"
  // must not read as a threatened penalty, so a qualifier or amount is required.
  { category: 'CONSEQUENCE_THREAT', pattern: /\b(?:fined\b|(?:heavy|monetary|statutory|punitive|late[- ]payment|additional)\s+fines?\b|fines?\s+(?:of|up to|will|shall|may)\b)/gi, weight: 9 },
  { category: 'CONSEQUENCE_THREAT', pattern: /\bfailure to (?:comply|respond|act)\b/gi, weight: 10 },
  { category: 'CONSEQUENCE_THREAT', pattern: /\bpermanent(?:ly)? (?:delet|lost|clos|disabl)\w*\b/gi, weight: 9 },
  { category: 'CONSEQUENCE_THREAT', pattern: /\bservice (?:interruption|will be discontinued)\b/gi, weight: 7 },
  { category: 'CONSEQUENCE_THREAT', pattern: /\bunauthorised|unauthorized (?:access|login|transaction)\b/gi, weight: 6 },

  // Reward lures
  { category: 'REWARD_LURE', pattern: /\b(?:you(?:'ve| have) )?won\b/gi, weight: 8 },
  { category: 'REWARD_LURE', pattern: /\b(?:refund|cashback|reward|prize|lottery|bonus) (?:of|worth|amount)?\b/gi, weight: 6 },
  { category: 'REWARD_LURE', pattern: /\bclaim your (?:refund|reward|prize|payment)\b/gi, weight: 10 },
  { category: 'REWARD_LURE', pattern: /\bcongratulations\b/gi, weight: 5 },
  { category: 'REWARD_LURE', pattern: /\bunclaimed (?:funds?|amount|balance)\b/gi, weight: 9 },

  // Process bypass
  { category: 'PROCESS_BYPASS', pattern: /\b(?:skip|bypass|waive|override) (?:the )?(?:usual |normal |standard )?(?:process|procedure|approval|verification|protocol)\b/gi, weight: 13 },
  { category: 'PROCESS_BYPASS', pattern: /\bno need to (?:verify|confirm|check|call)\b/gi, weight: 12 },
  { category: 'PROCESS_BYPASS', pattern: /\b(?:i am|i'm) (?:currently )?(?:in a meeting|travelling|traveling|unavailable|unreachable)\b/gi, weight: 9 },
  { category: 'PROCESS_BYPASS', pattern: /\b(?:cannot|can't|unable to) (?:talk|speak|take calls?)\b/gi, weight: 9 },
  { category: 'PROCESS_BYPASS', pattern: /\breply (?:only )?(?:to this email|to me directly)\b/gi, weight: 8 },
  { category: 'PROCESS_BYPASS', pattern: /\bhandle this (?:personally|yourself)\b/gi, weight: 8 },
];

/** Strip HTML so the lexicon runs against readable text, not markup. */
export function toPlainText(input: string): string {
  return input
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/[ \t]+/g, ' ')
    .trim();
}

export function analyseLanguage(body: string): LanguageAssessment {
  const text = toPlainText(body);
  const hits: PressureHit[] = [];

  for (const entry of LEXICON) {
    // Fresh regex per pass so lastIndex never leaks between calls.
    const pattern = new RegExp(entry.pattern.source, entry.pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text)) !== null) {
      if (match[0].trim().length === 0) {
        pattern.lastIndex += 1;
        continue;
      }
      hits.push({
        category: entry.category,
        match: match[0],
        start: match.index,
        end: match.index + match[0].length,
        weight: entry.weight,
      });
    }
  }

  // Overlapping matches (a broad pattern inside a specific one) would double
  // count, so keep the heaviest hit for any overlapping span.
  const deduped = dedupeOverlaps(hits);
  const categories = [...new Set(deduped.map((hit) => hit.category))];

  const rawWeight = deduped.reduce((total, hit) => total + hit.weight, 0);
  // Diminishing returns on repetition; a breadth bonus for multiple distinct
  // manipulation techniques appearing together.
  const breadthBonus = Math.max(0, categories.length - 1) * 7;
  const score = Math.min(100, Math.round(Math.sqrt(rawWeight) * 9 + breadthBonus));

  return {
    hits: deduped.sort((a, b) => a.start - b.start),
    categories,
    score,
    keyPhrases: rankSentences(text, deduped),
    wordCount: text ? text.split(/\s+/).filter(Boolean).length : 0,
  };
}

function dedupeOverlaps(hits: PressureHit[]): PressureHit[] {
  const sorted = [...hits].sort((a, b) => (b.end - b.start) - (a.end - a.start) || b.weight - a.weight);
  const kept: PressureHit[] = [];
  for (const hit of sorted) {
    const overlaps = kept.some(
      (existing) => hit.start < existing.end && hit.end > existing.start && hit.category === existing.category,
    );
    if (!overlaps) kept.push(hit);
  }
  return kept;
}

/** The three sentences carrying the most pressure weight, for the AI summary. */
function rankSentences(text: string, hits: PressureHit[]): string[] {
  if (hits.length === 0) return [];

  const sentences: { text: string; start: number; end: number }[] = [];
  const pattern = /[^.!?\n]+[.!?]?/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    const value = match[0].trim();
    if (value.length < 12) continue;
    sentences.push({ text: value, start: match.index, end: match.index + match[0].length });
  }

  const scored = sentences.map((sentence) => ({
    text: sentence.text,
    weight: hits
      .filter((hit) => hit.start >= sentence.start && hit.start < sentence.end)
      .reduce((total, hit) => total + hit.weight, 0),
  }));

  return scored
    .filter((entry) => entry.weight > 0)
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 3)
    .map((entry) => (entry.text.length > 220 ? `${entry.text.slice(0, 217)}…` : entry.text));
}

/** Split text into highlightable segments for rendering. */
export function segmentByHits(
  text: string,
  hits: PressureHit[],
): { text: string; category: PressureCategory | null }[] {
  if (hits.length === 0) return [{ text, category: null }];

  const segments: { text: string; category: PressureCategory | null }[] = [];
  const ordered = [...hits].sort((a, b) => a.start - b.start);
  let cursor = 0;

  for (const hit of ordered) {
    if (hit.start < cursor) continue;
    if (hit.start > cursor) {
      segments.push({ text: text.slice(cursor, hit.start), category: null });
    }
    segments.push({ text: text.slice(hit.start, hit.end), category: hit.category });
    cursor = hit.end;
  }
  if (cursor < text.length) {
    segments.push({ text: text.slice(cursor), category: null });
  }

  return segments;
}
