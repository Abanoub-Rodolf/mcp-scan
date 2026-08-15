import { ResolvedServer } from '../types/config.js';
import { Finding } from '../types/scan-result.js';
import { Severity } from '../types/severity.js';
import { findEncodedInstruction } from '../utils/encoded-text.js';
import { buildScanText } from '../utils/scan-text.js';

export function scanPromptInjection(server: ResolvedServer): Finding[] {
  const findings: Finding[] = [];

  // Phrases that are suspicious in any inflected form ('ignores previous
  // instructions', 'bypassing your safety') vs phrases that only count
  // verbatim ('act as' must not match the benign "acts as a proxy").
  const inflectedPatterns = [
    'ignore previous instructions', 'ignore all prior', 'disregard',
    'forget your instructions', 'override your', 'pretend you are',
    'roleplay as', 'simulate being', 'bypass your', 'disable safety',
  ];
  const strictPatterns = [
    'act as', 'you are now', 'new persona', 'jailbreak', 'dan mode',
    'developer mode', 'your true self',
  ];
  const inflect = (word: string) => `${word}(?:s|es|d|ed|ing)?`;

  const stringPatterns: Array<{ pattern: string; regex: RegExp }> = [
    ...inflectedPatterns.map(pattern => ({
      pattern,
      regex: new RegExp('\\b' + pattern.split(' ').map(inflect).join('\\s+') + '\\b', 'i'),
    })),
    ...strictPatterns.map(pattern => ({
      pattern,
      regex: new RegExp('\\b' + pattern.split(' ').join('\\s+') + '\\b', 'i'),
    })),
  ];
  const unicodePatterns = [
    { char: '\u200B', name: 'U+200B (Zero Width Space)' },
    { char: '\uFEFF', name: 'U+FEFF (Byte Order Mark)' },
    { char: '\u202E', name: 'U+202E (Right-to-Left Override)' },
    { char: '\u00AD', name: 'U+00AD (Soft Hyphen)' },
    { char: '\u2060', name: 'U+2060 (Word Joiner)' },
    { char: '\u180E', name: 'U+180E (Mongolian Vowel Separator)' },
    { char: '\u200C', name: 'U+200C (Zero Width Non-Joiner)' },
    { char: '\u200D', name: 'U+200D (Zero Width Joiner)' },
  ];
  const toolNamePatterns = [
    'bash', 'python', 'eval', 'exec', 'shell', 'terminal', 'run', 'system'
  ];

  // The tool catalog (names, descriptions, JSON schemas incl. nested
  // description/enum values) is part of the prompt at tools/list time.
  const textToScan = buildScanText(server);

  // String patterns. Joined with \s+ and word boundaries: the old
  // pattern.split(' ').join('.*') made 'act as' match the benign phrase
  // "this server acts as a proxy between tools".
  for (const { pattern, regex } of stringPatterns) {
    if (regex.test(textToScan)) {
      findings.push({
        id: 'prompt-injection-pattern',
        severity: 'HIGH' as Severity,
        description: `Potential prompt injection string pattern detected: "${pattern}".`,
        fixRecommendation: 'Review the server description and arguments for suspicious phrases that could lead to prompt injection.',
      });
    }
  }

  // Unicode patterns
  for (const { char, name } of unicodePatterns) {
    if (textToScan.includes(char)) {
      findings.push({
        id: 'unicode-injection',
        severity: 'HIGH' as Severity,
        description: `Potential unicode injection pattern detected: ${name}.`,
        fixRecommendation: 'Review the server description and arguments for suspicious unicode characters that could be used for obfuscation.',
      });
    }
  }

  // Encoded-instruction detection: long base64 strings that decode to
  // readable text. Plain long strings (URLs, hashes, JWTs) no longer
  // trigger this.
  const encoded = findEncodedInstruction(textToScan);
  if (encoded.length > 0) {
    findings.push({
      id: 'prompt-injection-pattern',
      severity: 'HIGH' as Severity,
      description: `Potential prompt injection (encoded instruction; Base64-like string > 50 chars) detected.`,
      fixRecommendation: 'Review the server description and arguments for long Base64-like encoded strings that could hide malicious instructions.',
    });
  }


  // Tool name shadows. Word-boundary matching: 'run' inside "server runs
  // on port 3000" is not shadowing.
  for (const toolName of toolNamePatterns) {
    // Check if toolName exists as a key in server.args, but it is not defined in server.schema
    // This requires schema analysis which is more complex.
    // For now, let's just check if the tool name appears as a standalone word.
    if (new RegExp('\\b' + toolName + '\\b', 'i').test(textToScan)) {
        findings.push({
            id: 'tool-name-shadow',
            severity: 'MEDIUM' as Severity,
            description: `Potential tool name shadowing detected: "${toolName}".`,
            fixRecommendation: 'Ensure tool names are not mimicked or used in a misleading way in descriptions or arguments.',
        });
    }
  }

  // Schema bypass risk: additionalProperties: true at schema root
  if (server.schema && server.schema.additionalProperties === true) {
    findings.push({
      id: 'schema-bypass-risk',
      severity: 'LOW' as Severity,
      description: 'Schema allows additional properties, which might pose a schema bypass risk.',
      fixRecommendation: 'Consider restricting additional properties in the schema to enhance security and prevent unexpected inputs.',
    });
  }

  return findings;
}
