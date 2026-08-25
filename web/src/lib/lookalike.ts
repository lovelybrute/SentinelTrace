/**
 * Lookalike / impersonation domain analysis.
 *
 * Runs entirely offline: no reputation API is required, which matters because the
 * demonstration must work without external services. The output is a similarity
 * score plus the *reason* it matched, so the UI can explain itself instead of
 * showing an unexplained number.
 */

export type LookalikeTechnique =
  | 'CHARACTER_SUBSTITUTION'
  | 'HOMOGLYPH'
  | 'TYPO'
  | 'BRAND_IN_SUBDOMAIN'
  | 'BRAND_WITH_SUFFIX'
  | 'TLD_SWAP'
  | 'HYPHEN_INSERTION'
  | 'EXACT';

export interface LookalikeMatch {
  /** The legitimate domain being imitated. */
  target: string;
  /** 0–100. */
  similarity: number;
  technique: LookalikeTechnique;
  /** Analyst-readable justification. */
  explanation: string;
}

/**
 * Brands commonly impersonated against Indian and global users. A production
 * deployment would load this from threat intelligence; it is a static list here
 * so the analyser stays fully offline.
 */
const PROTECTED_DOMAINS = [
  'paypal.com',
  'microsoft.com',
  'office365.com',
  'outlook.com',
  'google.com',
  'gmail.com',
  'apple.com',
  'amazon.com',
  'netflix.com',
  'linkedin.com',
  'facebook.com',
  'instagram.com',
  'whatsapp.com',
  'dhl.com',
  'fedex.com',
  'dropbox.com',
  'adobe.com',
  'hdfcbank.com',
  'icicibank.com',
  'axisbank.com',
  'sbi.co.in',
  'kotak.com',
  'rbi.org.in',
  'incometax.gov.in',
  'npci.org.in',
  'uidai.gov.in',
  'irctc.co.in',
  'nic.in',
];

/** Digits and glyphs routinely swapped in for letters. */
const SUBSTITUTIONS: Record<string, string> = {
  '0': 'o',
  '1': 'l',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '7': 't',
  '8': 'b',
  '9': 'g',
  '$': 's',
  '@': 'a',
};

/** Cyrillic and Greek characters that render almost identically to Latin. */
const HOMOGLYPHS: Record<string, string> = {
  а: 'a', с: 'c', е: 'e', о: 'o', р: 'p', х: 'x', у: 'y', ѕ: 's', і: 'i', ј: 'j',
  ο: 'o', ρ: 'p', ν: 'v', τ: 't', κ: 'k', ι: 'i',
};

/** Words appended to a brand to make a plausible-looking domain. */
const LURE_SUFFIXES = [
  'security',
  'secure',
  'verify',
  'verification',
  'support',
  'account',
  'accounts',
  'login',
  'signin',
  'service',
  'services',
  'update',
  'alert',
  'billing',
  'payment',
  'payments',
  'invoice',
  'refund',
  'kyc',
  'helpdesk',
  'portal',
  'online',
  'auth',
  'confirm',
];

/** Strip `www.` and trailing dots, lower-case. */
export function normaliseDomain(domain: string): string {
  return domain.trim().toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
}

/** Registrable label, e.g. `paypa1-security.com` → `paypa1-security`. */
function registrableLabel(domain: string): string {
  const parts = domain.split('.');
  // Handle two-part public suffixes such as co.in / org.in / gov.in / co.uk.
  if (parts.length >= 3 && ['co', 'org', 'gov', 'net', 'ac'].includes(parts[parts.length - 2])) {
    return parts[parts.length - 3];
  }
  return parts.length >= 2 ? parts[parts.length - 2] : domain;
}

function publicSuffix(domain: string): string {
  const parts = domain.split('.');
  if (parts.length >= 3 && ['co', 'org', 'gov', 'net', 'ac'].includes(parts[parts.length - 2])) {
    return parts.slice(-2).join('.');
  }
  return parts.slice(-1).join('.');
}

/** Fold digit substitutions and homoglyphs back to their Latin letters. */
function canonicalise(value: string): string {
  return [...value]
    .map((char) => SUBSTITUTIONS[char] ?? HOMOGLYPHS[char] ?? char)
    .join('')
    .replace(/rn/g, 'm'); // rn/m is the classic narrow-glyph confusion
}

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;

  let previous = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i += 1) {
    const current = [i];
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      current[j] = Math.min(current[j - 1] + 1, previous[j] + 1, previous[j - 1] + cost);
    }
    previous = current;
  }
  return previous[b.length];
}

function similarityOf(a: string, b: string): number {
  const distance = levenshtein(a, b);
  const longest = Math.max(a.length, b.length);
  return longest === 0 ? 0 : Math.round(((longest - distance) / longest) * 1000) / 10;
}

/** Does the string contain a homoglyph or digit standing in for a letter? */
function hasVisualTrickery(label: string): boolean {
  return [...label].some((char) => char in HOMOGLYPHS) ||
    [...label].some((char) => char in SUBSTITUTIONS);
}

/**
 * Compare a domain against the protected-brand list and return the strongest
 * match, or null when nothing looks like impersonation.
 */
export function detectLookalike(domain: string, extraTargets: string[] = []): LookalikeMatch | null {
  const subject = normaliseDomain(domain);
  if (!subject) return null;

  const targets = [...new Set([...PROTECTED_DOMAINS, ...extraTargets.map(normaliseDomain)])];
  const subjectLabel = registrableLabel(subject);
  const subjectSuffix = publicSuffix(subject);
  const folded = canonicalise(subjectLabel);
  const candidates: LookalikeMatch[] = [];

  for (const target of targets) {
    if (!target || target === subject) continue;
    const targetLabel = registrableLabel(target);
    const targetSuffix = publicSuffix(target);
    if (targetLabel.length < 4) continue;

    // 1. Same registrable label, different public suffix (paypal.com → paypal.support).
    if (subjectLabel === targetLabel && subjectSuffix !== targetSuffix) {
      candidates.push({
        target,
        similarity: 97.5,
        technique: 'TLD_SWAP',
        explanation: `Reuses the exact brand label "${targetLabel}" under a different top-level domain (.${subjectSuffix} instead of .${targetSuffix}).`,
      });
      continue;
    }

    // 2. Digit/homoglyph substitution that folds back to the brand exactly.
    if (folded === targetLabel && subjectLabel !== targetLabel) {
      const isHomoglyph = [...subjectLabel].some((char) => char in HOMOGLYPHS);
      candidates.push({
        target,
        similarity: 96.2,
        technique: isHomoglyph ? 'HOMOGLYPH' : 'CHARACTER_SUBSTITUTION',
        explanation: isHomoglyph
          ? `Substitutes visually identical non-Latin characters into "${targetLabel}" — indistinguishable at a glance.`
          : `Substitutes look-alike characters for letters in "${targetLabel}" (e.g. digits standing in for letters).`,
      });
      continue;
    }

    // 3. Brand plus a lure word, with or without a separator.
    const separators = /[-_.]/g;
    const tokens = subjectLabel.split(separators).filter(Boolean);
    const foldedTokens = tokens.map(canonicalise);
    const brandTokenIndex = foldedTokens.findIndex((token) => token === targetLabel);
    if (brandTokenIndex !== -1 && tokens.length > 1) {
      const lure = tokens.filter((_, i) => i !== brandTokenIndex);
      const usesLureWord = lure.some((token) => LURE_SUFFIXES.includes(token));
      const mutatedBrand = tokens[brandTokenIndex] !== targetLabel;
      candidates.push({
        target,
        similarity: usesLureWord ? (mutatedBrand ? 96.2 : 94.1) : 88,
        technique: mutatedBrand ? 'CHARACTER_SUBSTITUTION' : 'HYPHEN_INSERTION',
        explanation: mutatedBrand
          ? `Combines a character-substituted form of "${targetLabel}" with the credibility term "${lure.join(' ')}".`
          : `Appends "${lure.join(' ')}" to the brand name "${targetLabel}" — the registrable domain is not owned by the brand.`,
      });
      continue;
    }

    // 4. Brand hidden in a subdomain (paypal.com.secure-check.net).
    const subdomainPart = subject.slice(0, subject.length - subjectSuffix.length - subjectLabel.length - 1);
    if (subdomainPart && canonicalise(subdomainPart).includes(targetLabel)) {
      candidates.push({
        target,
        similarity: 92.4,
        technique: 'BRAND_IN_SUBDOMAIN',
        explanation: `Places "${target}" in the subdomain while the controlling registrable domain is "${subjectLabel}.${subjectSuffix}".`,
      });
      continue;
    }

    // 5. Near-miss typo: one or two edits away.
    const distance = levenshtein(subjectLabel, targetLabel);
    if (distance > 0 && distance <= 2 && targetLabel.length >= 5) {
      candidates.push({
        target,
        similarity: similarityOf(subjectLabel, targetLabel),
        technique: hasVisualTrickery(subjectLabel) ? 'CHARACTER_SUBSTITUTION' : 'TYPO',
        explanation: `Within ${distance} character edit${distance === 1 ? '' : 's'} of "${target}" — consistent with typo-squatting registration.`,
      });
      continue;
    }

    // 6. Brand appended without a separator (paypalsecure.com).
    if (folded.includes(targetLabel) && folded !== targetLabel) {
      const remainder = folded.replace(targetLabel, '');
      if (remainder.length >= 3) {
        candidates.push({
          target,
          similarity: LURE_SUFFIXES.includes(remainder) ? 93.6 : 84,
          technique: 'BRAND_WITH_SUFFIX',
          explanation: `Contains the brand string "${targetLabel}" concatenated with "${remainder}".`,
        });
      }
    }
  }

  if (candidates.length === 0) return null;
  candidates.sort((a, b) => b.similarity - a.similarity);
  return candidates[0];
}

/** True when the domain is one of the protected brands itself. */
export function isProtectedBrand(domain: string): boolean {
  return PROTECTED_DOMAINS.includes(normaliseDomain(domain));
}

/**
 * Free/consumer mail providers. Corporate correspondence claiming an executive
 * identity from one of these is a meaningful signal.
 */
const CONSUMER_PROVIDERS = new Set([
  'gmail.com',
  'googlemail.com',
  'yahoo.com',
  'yahoo.in',
  'outlook.com',
  'hotmail.com',
  'live.com',
  'aol.com',
  'proton.me',
  'protonmail.com',
  'rediffmail.com',
  'zoho.com',
  'mail.com',
  'gmx.com',
  'yandex.com',
]);

export function isConsumerMailProvider(domain: string): boolean {
  return CONSUMER_PROVIDERS.has(normaliseDomain(domain));
}

/** Disposable / throwaway mail domains sometimes used for reply channels. */
const DISPOSABLE_PROVIDERS = new Set([
  'mailinator.com',
  'guerrillamail.com',
  '10minutemail.com',
  'tempmail.com',
  'yopmail.com',
  'trashmail.com',
  'sharklasers.com',
  'getnada.com',
]);

export function isDisposableMailProvider(domain: string): boolean {
  return DISPOSABLE_PROVIDERS.has(normaliseDomain(domain));
}

/** URL shorteners obscure the true destination of a link. */
const SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'rebrand.ly',
  'cutt.ly',
  'shorturl.at',
  'rb.gy',
  'tiny.cc',
  'bl.ink',
]);

export function isUrlShortener(host: string): boolean {
  return SHORTENERS.has(normaliseDomain(host));
}
