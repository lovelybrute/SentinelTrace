/**
 * Client-side RFC 5322 / MIME reader.
 *
 * The FastAPI backend returns a curated subset of headers (From/To/Subject/Date/
 * Message-ID). Header forensics needs more than that — Reply-To, Return-Path,
 * X-Originating-IP, the full Received stack — so when the analyst gives us the
 * raw message we parse it here for completeness and merge the result with the
 * backend's authenticated verdict. The backend stays the source of truth for
 * scoring, DNS and geolocation; this only recovers fields it does not return.
 */

export interface ParsedMimePart {
  contentType: string;
  disposition: string | null;
  filename: string | null;
  charset: string | null;
  encoding: string | null;
  /** Decoded text for textual parts; null for binary attachments. */
  text: string | null;
  /** Byte length after decoding, best-effort. */
  sizeBytes: number;
}

export interface ParsedEmail {
  /** Header names preserved in original order, values unfolded. */
  headerOrder: { name: string; value: string }[];
  /** Lower-cased header name → all values (headers may repeat). */
  headers: Map<string, string[]>;
  rawHeaderBlock: string;
  textBody: string;
  htmlBody: string;
  parts: ParsedMimePart[];
  /** Links with their anchor text, so mismatched anchors can be detected. */
  links: { url: string; anchorText: string | null }[];
}

/** Read the first value of a header, or null. */
export function header(email: ParsedEmail, name: string): string | null {
  const values = email.headers.get(name.toLowerCase());
  return values && values.length > 0 ? values[0] : null;
}

/** Read every value of a repeated header, in document order. */
export function headerAll(email: ParsedEmail, name: string): string[] {
  return email.headers.get(name.toLowerCase()) ?? [];
}

export function parseEmail(raw: string): ParsedEmail {
  const normalised = raw.replace(/\r\n/g, '\n');
  const separator = normalised.indexOf('\n\n');
  const rawHeaderBlock = separator === -1 ? normalised : normalised.slice(0, separator);
  const rawBody = separator === -1 ? '' : normalised.slice(separator + 2);

  const headerOrder = unfoldHeaders(rawHeaderBlock);
  const headers = new Map<string, string[]>();
  for (const entry of headerOrder) {
    const key = entry.name.toLowerCase();
    const existing = headers.get(key);
    if (existing) existing.push(entry.value);
    else headers.set(key, [entry.value]);
  }

  const contentType = headers.get('content-type')?.[0] ?? 'text/plain';
  const parts = parseParts(rawBody, contentType, headers.get('content-transfer-encoding')?.[0] ?? null);

  const textBody = parts.find((p) => p.contentType.startsWith('text/plain'))?.text ?? '';
  const htmlBody = parts.find((p) => p.contentType.startsWith('text/html'))?.text ?? '';

  return {
    headerOrder,
    headers,
    rawHeaderBlock,
    textBody,
    htmlBody,
    parts,
    links: extractLinks(htmlBody, textBody),
  };
}

/* ------------------------------------------------------------------ */
/* Headers                                                             */
/* ------------------------------------------------------------------ */

function unfoldHeaders(block: string): { name: string; value: string }[] {
  const result: { name: string; value: string }[] = [];
  const lines = block.split('\n');
  let current: { name: string; value: string } | null = null;

  for (const line of lines) {
    if (!line.trim()) continue;
    // A leading space or tab continues the previous header (RFC 5322 folding).
    if (/^[ \t]/.test(line) && current) {
      current.value += ` ${line.trim()}`;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    if (current) result.push(current);
    current = {
      name: line.slice(0, colon).trim(),
      value: line.slice(colon + 1).trim(),
    };
  }
  if (current) result.push(current);

  return result.map((entry) => ({ name: entry.name, value: decodeEncodedWords(entry.value) }));
}

/**
 * Decode RFC 2047 encoded words, e.g.
 * `=?UTF-8?B?SGVsbG8=?=` and `=?utf-8?Q?Hi_there?=`.
 * Falls back to the original token if decoding fails.
 */
export function decodeEncodedWords(value: string): string {
  return value.replace(
    /=\?([A-Za-z0-9_-]+)\?([BbQq])\?([^?]*)\?=/g,
    (whole, _charset: string, encoding: string, payload: string) => {
      try {
        if (encoding.toUpperCase() === 'B') {
          return decodeUtf8(atob(payload.replace(/\s/g, '')));
        }
        const qp = payload
          .replace(/_/g, ' ')
          .replace(/=([0-9A-Fa-f]{2})/g, (__, hex: string) =>
            String.fromCharCode(Number.parseInt(hex, 16)),
          );
        return decodeUtf8(qp);
      } catch {
        return whole;
      }
    },
  );
}

/** Reinterpret a byte string as UTF-8. */
function decodeUtf8(bytes: string): string {
  try {
    const array = Uint8Array.from(bytes, (c) => c.charCodeAt(0));
    return new TextDecoder('utf-8').decode(array);
  } catch {
    return bytes;
  }
}

/* ------------------------------------------------------------------ */
/* MIME parts                                                          */
/* ------------------------------------------------------------------ */

function parseParts(
  body: string,
  contentType: string,
  topEncoding: string | null,
): ParsedMimePart[] {
  const boundary = readParameter(contentType, 'boundary');

  if (!boundary) {
    const type = contentType.split(';')[0].trim().toLowerCase() || 'text/plain';
    const decoded = decodeBody(body, topEncoding);
    return [
      {
        contentType: type,
        disposition: null,
        filename: null,
        charset: readParameter(contentType, 'charset'),
        encoding: topEncoding,
        text: type.startsWith('text/') ? decoded : null,
        sizeBytes: decoded.length,
      },
    ];
  }

  const parts: ParsedMimePart[] = [];
  const chunks = body.split(new RegExp(`--${escapeRegex(boundary)}(?:--)?\\s*\\n?`));

  for (const chunk of chunks) {
    if (!chunk.trim()) continue;
    const separator = chunk.indexOf('\n\n');
    if (separator === -1) continue;

    const partHeaders = new Map<string, string>();
    for (const entry of unfoldHeaders(chunk.slice(0, separator))) {
      partHeaders.set(entry.name.toLowerCase(), entry.value);
    }
    const partBody = chunk.slice(separator + 2);
    const partType = (partHeaders.get('content-type') ?? 'text/plain').split(';')[0].trim().toLowerCase();
    const disposition = partHeaders.get('content-disposition') ?? null;
    const encoding = partHeaders.get('content-transfer-encoding') ?? null;

    // Nested multipart (e.g. multipart/alternative inside multipart/mixed).
    const nestedBoundary = readParameter(partHeaders.get('content-type') ?? '', 'boundary');
    if (partType.startsWith('multipart/') && nestedBoundary) {
      parts.push(...parseParts(partBody, partHeaders.get('content-type') ?? '', encoding));
      continue;
    }

    const filename =
      readParameter(disposition ?? '', 'filename') ??
      readParameter(partHeaders.get('content-type') ?? '', 'name');

    const isText = partType.startsWith('text/') && !filename;
    const decoded = isText ? decodeBody(partBody, encoding) : null;

    parts.push({
      contentType: partType,
      disposition: disposition ? disposition.split(';')[0].trim().toLowerCase() : null,
      filename,
      charset: readParameter(partHeaders.get('content-type') ?? '', 'charset'),
      encoding,
      text: decoded,
      sizeBytes: estimateSize(partBody, encoding),
    });
  }

  return parts;
}

function decodeBody(body: string, encoding: string | null): string {
  const mode = (encoding ?? '').trim().toLowerCase();
  if (mode === 'base64') {
    try {
      return decodeUtf8(atob(body.replace(/\s/g, '')));
    } catch {
      return body;
    }
  }
  if (mode === 'quoted-printable') {
    return decodeUtf8(
      body
        .replace(/=\r?\n/g, '')
        .replace(/=([0-9A-Fa-f]{2})/g, (_, hex: string) =>
          String.fromCharCode(Number.parseInt(hex, 16)),
        ),
    );
  }
  return body;
}

function estimateSize(body: string, encoding: string | null): number {
  const stripped = body.replace(/\s/g, '');
  if ((encoding ?? '').trim().toLowerCase() === 'base64') {
    // 4 base64 chars encode 3 bytes; discount padding.
    const padding = (stripped.match(/=+$/)?.[0].length ?? 0);
    return Math.max(0, Math.floor((stripped.length * 3) / 4) - padding);
  }
  return body.length;
}

/** Read a MIME parameter, handling both quoted and bare forms. */
function readParameter(value: string, name: string): string | null {
  const quoted = value.match(new RegExp(`${name}\\s*=\\s*"([^"]*)"`, 'i'));
  if (quoted) return quoted[1];
  const bare = value.match(new RegExp(`${name}\\s*=\\s*([^;\\s]+)`, 'i'));
  return bare ? bare[1] : null;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/* ------------------------------------------------------------------ */
/* Links                                                               */
/* ------------------------------------------------------------------ */

const URL_PATTERN = /https?:\/\/[^\s<>"'\])]+/gi;

function extractLinks(html: string, text: string): { url: string; anchorText: string | null }[] {
  const links: { url: string; anchorText: string | null }[] = [];
  const seen = new Set<string>();

  // Anchors first, so we keep the visible text alongside the real destination.
  const anchor = /<a\b[^>]*href\s*=\s*["']?([^"'\s>]+)["']?[^>]*>([\s\S]*?)<\/a>/gi;
  let match: RegExpExecArray | null;
  while ((match = anchor.exec(html)) !== null) {
    const url = match[1].trim();
    if (!/^https?:/i.test(url)) continue;
    const anchorText = match[2].replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
    if (seen.has(url)) continue;
    seen.add(url);
    links.push({ url, anchorText: anchorText || null });
  }

  for (const source of [html.replace(/<a\b[\s\S]*?<\/a>/gi, ' '), text]) {
    const found = source.match(URL_PATTERN) ?? [];
    for (const url of found) {
      const cleaned = url.replace(/[.,;:)]+$/, '');
      if (seen.has(cleaned)) continue;
      seen.add(cleaned);
      links.push({ url: cleaned, anchorText: null });
    }
  }

  return links;
}

/** Host portion of a URL, or null when it cannot be parsed. */
export function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}
