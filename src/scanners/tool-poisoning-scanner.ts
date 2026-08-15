import { ResolvedServer } from '../types/config.js';
import { Finding } from '../types/scan-result.js';
import { findEncodedInstruction } from '../utils/encoded-text.js';

/**
 * Scanner for Tool Poisoning & Capability Injection attacks.
 * Detects patterns in tool descriptions and arguments that aim to influence model behavior maliciously.
 */
export function scanToolPoisoning(server: ResolvedServer): Finding[] {
  const findings: Finding[] = [];

  const textToScan = [
    server.description,
    ...(Array.isArray(server.args) ? server.args : (server.args ? Object.values(server.args) : []))
  ].filter(Boolean).join(' ');

  // 1. Hidden instructions (long padding followed by instructions)
  if (/\s{50,}.*(ignore|disregard|forget|rules|instructions)/i.test(textToScan)) {
    findings.push({
      id: 'hidden-instruction-risk',
      severity: 'HIGH',
      description: 'Hidden instructions detected in description via excessive whitespace padding.',
      fixRecommendation: 'Remove excessive whitespace. Instructions should be clear and non-conflicting.'
    });
  }

  // 2. Instructions calling other tools or exfiltrating data.
  // Strong signals are flagged directly; generic verbs (send, upload,
  // POST) only count when in proximity to a data noun, so ordinary
  // file/DB tool descriptions ("queries a postgres database") do not
  // produce HIGH findings.
  const strongExfil = /\b(?:exfiltrate|exfil|steal|leak|transmit credentials|send credentials|delete_everything|forward to)\b/i;
  const contextualExfil = /\b(?:send|upload|POST)\b.{0,50}\b(?:credentials|password|token|keys?|secrets|database|\bdb\b|files?)\b/i;
  const exfiltrationFound = strongExfil.test(textToScan) || contextualExfil.test(textToScan);
  
  if (exfiltrationFound) {
    findings.push({
      id: 'tool-exfiltration-risk',
      severity: 'HIGH',
      description: 'Potential exfiltration instructions detected in tool description.',
      fixRecommendation: 'Review tool descriptions for phrases that instruct the model to move data outside the intended scope.'
    });
  }

  const callOtherToolsKeywords = ['call tool', 'use tool', 'then call', 'follow by calling', 'invoke tool', 'chain to'];
  
  if (new RegExp('\\b(?:' + callOtherToolsKeywords.map(k => k.replace(' ', '\\s+')) + ')\\b', 'i').test(textToScan)) {
    findings.push({
        id: 'tool-exfiltration-risk',
        severity: 'MEDIUM',
        description: 'Instructions to call other tools detected in description.',
        fixRecommendation: 'Review if the tool should be allowed to chain calls to other tools via natural language instructions.'
    });
  }

  // 3. Tool name shadowing
  const builtInShadows = ['read_file', 'write_file', 'list_files', 'search', 'grep', 'bash', 'terminal', 'shell'];
  if (builtInShadows.includes(server.name.toLowerCase())) {
    findings.push({
      id: 'tool-name-shadow',
      severity: 'MEDIUM',
      description: `Tool name "${server.name}" shadows common built-in operations.`,
      fixRecommendation: 'Rename the tool to avoid conflicts with standard operations or built-in model tools.'
    });
  }

  // 4. Capability escalation. Only fires when the tool NAME claims a
  // read-only role and the description then claims write/modify actions:
  // a genuine claim-vs-description contradiction. "List and create
  // files" on a generic file manager is normal, not escalation. Names
  // are tokenized so 'read_file' and 'read-file' count as read-only.
  const nameTokens = server.name.toLowerCase().split(/[^a-z0-9]+/);
  const nameClaimsReadOnly = nameTokens.some(t => ['read', 'view', 'get', 'list', 'fetch', 'reader', 'viewer'].includes(t));
  const hasWriteAction = /\b(?:write|writes|wrote|written|writing|create|creates|created|creating|update|updates|updated|updating|delete|deletes|deleted|deleting|modify|modifies|modified|modifying|save|saves|saved|saving)\b/i.test(textToScan);
  
  if (nameClaimsReadOnly && hasWriteAction) {
    findings.push({
      id: 'capability-escalation-risk',
      severity: 'HIGH',
      description: 'Potential capability escalation: tool claims to be read-only but its description contains write/modify actions.',
      fixRecommendation: 'Ensure tool descriptions accurately reflect their capabilities and do not mislead the model into performing extra actions.'
    });
  }

  // 5. Unicode direction-reversal tricks
  const unicodeTricks = ['\u202E', '\u200F', '\u202B', '\u202D'];
  for (const char of unicodeTricks) {
    if (textToScan.includes(char)) {
      findings.push({
        id: 'unicode-injection',
        severity: 'HIGH',
        description: 'Unicode direction-reversal trick detected in tool description.',
        fixRecommendation: 'Remove hidden or misleading unicode characters that change how text is displayed vs how it is parsed.'
      });
      break;
    }
  }

  // 6. Encoded instructions: long base64 strings that decode to readable
  // text. Plain long strings (URLs, hashes, JWTs) no longer trigger this.
  if (findEncodedInstruction(textToScan).length > 0) {
    findings.push({
      id: 'prompt-injection-pattern',
      severity: 'HIGH',
      description: 'Long encoded string (potential hidden instructions) detected.',
      fixRecommendation: 'Decode and review any long opaque strings in tool descriptions or arguments.'
    });
  }

  // 7. References to environment variables not in scope. A reference to
  // an ambient process env var is standard configuration, not a leak.
  const envVarRefRegex = /\$\{([A-Z0-9_]+)\}/gi;
  let match;
  while ((match = envVarRefRegex.exec(textToScan)) !== null) {
    const envVarName = match[1];
    const inServerEnv = server.env && server.env[envVarName] !== undefined;
    const inProcessEnv = envVarName in process.env || envVarName.toUpperCase() in process.env;
    if (!inServerEnv && !inProcessEnv) {
      findings.push({
        id: 'env-var-scope-leak',
        severity: 'MEDIUM',
        description: `Reference to environment variable "\${${envVarName}}" not defined in this server's scope.`,
        fixRecommendation: 'Only reference environment variables that are explicitly provided to the server in its "env" configuration.'
      });
    }
  }

  return findings;
}
