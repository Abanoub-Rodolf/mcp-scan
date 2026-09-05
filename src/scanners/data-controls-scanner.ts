import { ResolvedServer } from '../types/config.js';
import { Finding } from '../types/scan-result.js';
import { PII_PATTERNS } from '../data/pii-patterns.js';
import fs from 'fs';
import os from 'os';

// Calibration: a tool exposing more properties than this looks like a
// broad-surface data risk; a temp dir holding more files than this
// suggests unmanaged retention.
const MANY_PROPERTIES_THRESHOLD = 10;
const MANY_TEMP_FILES_THRESHOLD = 100;

/**
 * Scanner for data controls, privacy, and PII handling.
 * Evaluates if a server follows best practices for data retention, encryption, and consent.
 */
export function scanDataControls(server: ResolvedServer, performRetentionScan: boolean = false): Finding[] {
  const findings: Finding[] = [];
  // configPath/toolName are filesystem metadata, not config content - a scan
  // path containing a digit run (e.g. a UUID) otherwise fabricates PII hits.
  const { configPath: _configPath, toolName: _toolName, ...scanTarget } = server;
  const serverStr = JSON.stringify(scanTarget).toLowerCase();

  const detectedPii = new Set<string>();

  // 1. Pattern-based PII detection over the server config. Patterns are
  // stored without /g so repeated .test() calls never hit the lastIndex
  // trap; validate() rejects shape-only matches (Luhn, private IPs).
  for (const pattern of PII_PATTERNS) {
    if (pattern.detect === false) continue;
    const validate = pattern.validate;
    const matches = JSON.stringify(scanTarget).match(pattern.regex);
    if (matches && (!validate || matches.some(m => validate(m)))) {
      detectedPii.add(pattern.name);
    }
  }

  // 2. Keyword-based PII detection. Restricted to descriptive text (server
  // name, description, tool names, tool descriptions) - env var keys and
  // raw values are credentials, not PII, and matching them made ordinary
  // configs look like PII processors. Terms match on word boundaries so
  // 'dob' no longer hits "adobe" and 'phi' no longer hits "phishing".
  const descriptiveText = [
    server.name,
    server.description,
    server.schema?.description,
    ...(server.schema?.tools || []).flatMap((tool: any) => [tool.name, tool.description]),
    server.command
  ].filter(Boolean).join('\n').toLowerCase();

  const piiTerms: Record<string, RegExp> = {
    'Email': /\b(?:email|e-mail)\b/i,
    'Phone Number': /\b(?:phone number|telephone|mobile number|cell phone|phone)\b/i,
    'Credit Card': /\b(?:credit card|ccnum|card number|cvv|expiry)\b/i,
    'SSN': /\b(?:ssn|social security|tax id|national id)\b/i,
    'IPv4 Address': /\b(?:ipv4|client ip|ip address)\b/i,
    'Password': /\b(?:password|pwd|passphrase|pin code)\b/i,
    'API Key': /\b(?:api[_-]?key|secret[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token|bearer[_-]?token|refresh[_-]?token|oauth[_-]?token)\b/i,
    'Address': /\b(?:street address|residential address|home address|mailing address)\b/i,
    'Date of Birth': /\b(?:date of birth|dob|birthday|birth date)\b/i,
    'Health Data': /\b(?:diagnosis|medical record|prescription|health data|hipaa)\b/i,
    'Biometric': /\b(?:fingerprint|face id|biometric|retina scan)\b/i,
    'Zip Code': /\b(?:zip code|zipcode|postal code)\b/i,
    'NPI Number': /\bnpi\b/i,
    'US Driver License': /\b(?:driver[’']?s? license|drivers license)\b/i,
    'Passport Number': /\bpassport\b/i,
    'VAT Number': /\bvat\b/i,
    'AWS Account ID': /\baws account\b/i,
    'PII': /\b(?:pii|personal data|personally identifiable)\b/i
  };
  
  for (const [name, termRe] of Object.entries(piiTerms)) {
    if (termRe.test(descriptiveText)) {
      detectedPii.add(name);
    }
  }

  if (detectedPii.size > 0) {
      const piiList = Array.from(detectedPii).join(', ');
      const isHighRisk = detectedPii.has('Credit Card') || detectedPii.has('SSN') || 
                         detectedPii.has('Password') || detectedPii.has('API Key');

      findings.push({
         id: 'data-controls-pii',
         severity: isHighRisk ? 'CRITICAL' : 'HIGH',
         description: `Server handles PII/Sensitive data: ${piiList}`,
         fixRecommendation: 'Implement strict data minimization. Ensure all PII is encrypted and handled according to privacy policies.'
      });
      
      // Consent Check. These keyword scans run over the full config so
      // env keys (CACHE_TTL, DB_ENCRYPT) count as evidence; substring
      // matching is intentional - the words are rare enough in configs
      // that boundary strictness would only cause false negatives.
      const hasConsentKeywords = /consent|opt-in|opt in|agree|privacy policy/i.test(serverStr);
      if (!hasConsentKeywords) {
         findings.push({
            id: 'data-controls-consent-gap',
            severity: 'MEDIUM',
            description: `Server handles PII but no consent mechanism or privacy policy reference detected.`,
            fixRecommendation: 'Implement explicit user consent for PII processing and link to a privacy policy.'
         });
      }

      // Retention Check
      const hasRetention = /ttl|expire|cleanup|retention|auto-delete|auto delete|purge/i.test(serverStr);
      if (!hasRetention) {
         findings.push({
            id: 'data-controls-retention-gap',
            severity: 'MEDIUM',
            description: `Server handles PII but no data retention policy or auto-cleanup detected.`,
            fixRecommendation: 'Implement data retention policies (e.g., TTL, automatic cleanup of old records).'
         });
      }

      // Deletion Check
      const hasDeletion = /delete|remove|forget|destroy|wipe|unlink/i.test(serverStr);
      if (!hasDeletion) {
         findings.push({
            id: 'data-controls-deletion-gap',
            severity: 'MEDIUM',
            description: `Server handles PII but no user-initiated data deletion capability detected.`,
            fixRecommendation: 'Provide a tool or endpoint that allows users to request the deletion of their personal data.'
         });
      }

      // Encryption Check
      const hasEncryption = /encrypt|aes|kms|crypto|vault|sealed|at rest/i.test(serverStr);
      if (!hasEncryption) {
         findings.push({
            id: 'data-controls-encryption-gap',
            severity: 'HIGH',
            description: `Server handles PII but no encryption at rest detected for stored data.`,
            fixRecommendation: 'Encrypt sensitive data at rest using strong cryptographic standards (e.g., AES-256).'
         });
      }

      // Data Minimization Check (Heuristic)
      // If a tool has many properties (>10) and the server was detected as
      // handling PII, it might be over-collecting.
      const tools = server.schema?.tools || [];
      for (const tool of tools) {
          const props = tool.inputSchema?.properties ? Object.keys(tool.inputSchema.properties) : [];
          if (props.length > MANY_PROPERTIES_THRESHOLD) {
              findings.push({
                  id: 'data-controls-minimization-risk',
                  severity: 'LOW',
                  description: `Tool '${tool.name}' requests a large number of properties while the server handles PII.`,
                  fixRecommendation: 'Audit tool properties and remove any that are not strictly necessary for the intended function.'
              });
          }
      }
  }
  
  // Prompt Logging Check - requires a logging verb in proximity to a
  // user-data noun; two independent substring matches flagged 'dialog'
  // and 'log in' on nearly every server.
  const isLoggingPrompts = /\b(?:log|record|store|capture|persist)\b.{0,60}\b(?:prompt|query|interaction|message|chat)\b/i.test(descriptiveText)
    || /\b(?:prompt|query|interaction|message|chat)\b.{0,60}\b(?:log|record|store|capture|persist)\b/i.test(descriptiveText);
  if (isLoggingPrompts) {
     findings.push({
        id: 'data-controls-prompt-logging',
        severity: 'MEDIUM',
        description: `Server appears to log raw user prompts or interactions.`,
        fixRecommendation: 'Anonymize logs, remove PII before logging, or provide a way to disable prompt logging.'
     });
  }

  // Retention Scan (Optional disk check)
  if (performRetentionScan) {
      const tmpPaths = [os.tmpdir(), '/tmp'];
      let foundTempFiles = false;
      for (const t of tmpPaths) {
          try {
              if (fs.existsSync(t)) {
                  const files = fs.readdirSync(t);
                  if (files.length > MANY_TEMP_FILES_THRESHOLD) {
                      foundTempFiles = true;
                      break;
                  }
              }
          } catch(_e) {}
      }
      if (foundTempFiles) {
          findings.push({
              id: 'data-controls-stale-temp-files',
              severity: 'LOW',
              description: `System contains a large number of temporary files, which may indicate a lack of proper cleanup.`,
              fixRecommendation: 'Verify that temporary files created by the server are properly cleaned up after use.'
          });
      }
  }

  return findings;
}
