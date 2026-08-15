export interface PiiPattern {
  name: string;
  regex: RegExp;
  mask: string;
  /**
   * Extra validation applied to a matched value before it counts as PII
   * (e.g. Luhn check for credit cards, RFC1918 exclusion for IPs). Values
   * that fail validation are ignored by detectors but may still be masked.
   */
  validate?: (value: string) => boolean;
  /**
   * When false, the pattern is only used for masking, not for detection.
   * Numeric-shape patterns (zip, NPI, driver license, passport, AWS
   * account) false-positive on ports, timestamps, and IDs, so they are
   * detected via keyword context in the scanner instead.
   */
  detect?: boolean;
}

/**
 * Luhn checksum validation for card numbers (ISO/IEC 7812).
 */
export function luhnCheck(digits: string): boolean {
  const clean = digits.replace(/[^0-9]/g, '');
  if (clean.length < 13 || clean.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = clean.length - 1; i >= 0; i--) {
    let d = clean.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/**
 * True when the IP is in a private/reserved range where "PII in the
 * config" is almost certainly a local endpoint (SSE servers use these).
 */
function isPrivateIp(ip: string): boolean {
  const octets = ip.split('.').map(Number);
  if (octets.length !== 4 || octets.some(o => Number.isNaN(o) || o < 0 || o > 255)) return true;
  const [a, b] = octets;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a === 169 && b === 254) return true; // link-local
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918
  if (a === 192 && b === 168) return true;
  if (a >= 224) return true; // multicast + reserved
  return false;
}

export const PII_PATTERNS: PiiPattern[] = [
  {
    name: 'Email',
    regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/,
    mask: '[EMAIL_MASKED]'
  },
  {
    name: 'Phone Number',
    // Area-code forms must start with 2-9 so bare 10-digit numbers
    // (timestamps, build IDs) are not flagged as phone numbers.
    regex: /(?<![a-zA-Z0-9])(?:\+?\d{1,3}[\s-]?)?\(?[2-9]\d{2}\)?[\s-]?\d{3}[\s-]?\d{4}\b/,
    mask: '[PHONE_MASKED]'
  },
  {
    name: 'Credit Card',
    regex: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b|\b\d{4}[\s-]?\d{6}[\s-]?\d{5}\b/,
    mask: '[CREDIT_CARD_MASKED]',
    validate: luhnCheck
  },
  {
    name: 'SSN',
    regex: /\b\d{3}-\d{2}-\d{4}\b/,
    mask: '[SSN_MASKED]'
  },
  {
    name: 'IPv4 Address',
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
    mask: '[IP_MASKED]',
    validate: (value: string) => !isPrivateIp(value)
  },
  {
    name: 'IBAN',
    regex: /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}[A-Z0-9]{0,16}\b/,
    mask: '[IBAN_MASKED]',
    validate: (value: string) => value.replace(/[^A-Z0-9]/gi, '').length >= 15
  },
  {
    name: 'Password',
    regex: /password[_-]?\b[A-Za-z0-9!@#$%^&*()_+]{8,}\b/i,
    mask: '[PASSWORD_MASKED]'
  },
  {
    name: 'IPv6 Address',
    regex: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/,
    mask: '[IPV6_MASKED]'
  },
  {
    name: 'MAC Address',
    regex: /\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b/,
    mask: '[MAC_MASKED]'
  },
  {
    name: 'UK National Insurance Number',
    regex: /\b[A-Z]{2}[0-9]{6}[ABCD]\b/,
    mask: '[NINO_MASKED]'
  },
  // Numeric-shape patterns below are masking-only (detect: false). The
  // data-controls scanner keys them to descriptive keywords instead of
  // flagging every 5/9/10-digit number as PII.
  {
    name: 'Zip Code',
    regex: /\b\d{5}(?:-\d{4})?\b/,
    mask: '[ZIP_MASKED]',
    detect: false
  },
  {
    name: 'VAT Number',
    regex: /\b[A-Z]{2}[0-9A-Z]{2,12}\b/,
    mask: '[VAT_MASKED]',
    detect: false
  },
  {
    name: 'Passport Number',
    regex: /\b[A-Z]{1,2}[0-9]{6,9}\b/,
    mask: '[PASSPORT_MASKED]',
    detect: false
  },
  {
    name: 'US Driver License',
    regex: /\b[A-Z][0-9]{7}\b|\b[0-9]{9}\b/,
    mask: '[DL_MASKED]',
    detect: false
  },
  {
    name: 'NPI Number',
    regex: /\b[0-9]{10}\b/,
    mask: '[NPI_MASKED]',
    detect: false
  },
  {
    name: 'AWS Account ID',
    regex: /\b\d{4}-\d{4}-\d{4}\b/,
    mask: '[AWS_ACCOUNT_MASKED]',
    detect: false
  },
];
