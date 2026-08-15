/**
 * Detection of long base64 strings that decode to readable text.
 *
 * A naive /[A-Za-z0-9+/]{50,}={0,2}/ matches any long alphanumeric run:
 * URLs, hashes, JWTs, and package versions all false-positive as "hidden
 * instructions". The real signal is a string that DECODES to printable
 * text with spaces - i.e. an encoded message. Decoding a random path
 * segment or hash produces binary garbage and is ignored.
 */

const CANDIDATE = /[A-Za-z0-9+/]{56,}={0,2}/g;

function decodesToReadableText(candidate: string): boolean {
  if (candidate.length % 4 !== 0) return false;
  const decoded = Buffer.from(candidate.replace(/=+$/, ''), 'base64').toString('utf8');
  // Printable ASCII with at least one space and a meaningful length:
  // an encoded sentence. Binary or replacement-char output is ignored.
  return /^[\x20-\x7E\r\n\t]+$/.test(decoded) && decoded.includes(' ') && decoded.length >= 10;
}

/**
 * Returns the base64-looking substrings in `text` that decode to readable
 * text with spaces (likely encoded instructions).
 */
export function findEncodedInstruction(text: string): string[] {
  if (typeof text !== 'string' || text.length === 0) return [];
  const results: string[] = [];
  for (const match of text.match(CANDIDATE) || []) {
    if (decodesToReadableText(match)) results.push(match);
  }
  return results;
}
