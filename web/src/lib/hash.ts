/**
 * SHA-256 over evidence bytes.
 *
 * Uses the Web Crypto API, which is available in every secure context including
 * `localhost`. Evidence integrity matters here — the chain-of-custody view is
 * only meaningful if the digest is real — so if Web Crypto is genuinely
 * unavailable we say the hash is unverified rather than substituting a
 * look-alike value.
 */

export interface Digest {
  hex: string;
  algorithm: 'SHA-256';
  verified: boolean;
}

const CRYPTO_UNAVAILABLE = 'unavailable';

export async function sha256(input: string | ArrayBuffer): Promise<Digest> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    return { hex: CRYPTO_UNAVAILABLE, algorithm: 'SHA-256', verified: false };
  }
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input);
  try {
    const buffer = await subtle.digest('SHA-256', bytes);
    return { hex: toHex(buffer), algorithm: 'SHA-256', verified: true };
  } catch {
    return { hex: CRYPTO_UNAVAILABLE, algorithm: 'SHA-256', verified: false };
  }
}

export function isDigestVerified(hex: string): boolean {
  return /^[0-9a-f]{64}$/i.test(hex);
}

function toHex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
