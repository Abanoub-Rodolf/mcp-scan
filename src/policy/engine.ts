import path from 'path';
import os from 'os';
import { parse } from 'yaml';
import { Finding, ServerScanResult } from '../types/scan-result.js';
import { Severity, SEVERITY_ORDER, isSeverity } from '../types/severity.js';
import chalk from 'chalk';
import { PolicyError, policyFileExists, readPolicyFile } from '../utils/policy-file.js';

export interface PolicyRule {
  id: string;
  description?: string;
  scanner?: string;
  action: 'block' | 'warn' | 'skip' | 'override-severity';
  severity?: string;
  match?: {
      server_name?: string | string[];
      finding_id?: string | string[];
      severity?: string | string[];
      category?: string | string[];
      license_type?: string | string[];
  };
}

export interface SecurityPolicy {
  version: number;
  rules: PolicyRule[];
}

function readAndParsePolicy(policyPath: string): SecurityPolicy {
  return parse(readPolicyFile(policyPath)) as SecurityPolicy;
}

const VALID_ACTIONS = ['block', 'warn', 'skip', 'override-severity'] as const;

// First schema problem as the message to show, or null when the policy is sound.
function schemaProblem(parsed: SecurityPolicy | null): string | null {
  if (!parsed || parsed.version !== 1 || !Array.isArray(parsed.rules)) {
    return 'Invalid policy schema. Expected: { version: 1, rules: [...] }';
  }
  for (const rule of parsed.rules) {
    if (!rule || !rule.id || !rule.action) {
      return `Rule missing required fields (id, action): ${JSON.stringify(rule)}`;
    }
    if (!VALID_ACTIONS.includes(rule.action)) {
      return `Rule '${rule.id}' has invalid action '${rule.action}'. Valid: ${VALID_ACTIONS.join(', ')}`;
    }
    if (rule.action === 'override-severity' && !rule.severity) {
      return `Rule '${rule.id}' uses override-severity but is missing the 'severity' field.`;
    }
    const problem = ruleFieldProblem(rule);
    if (problem) return `Rule '${rule.id}': ${problem}`;
  }
  return null;
}

// Only keys ruleMatches reads. A key accepted here but never read makes a skip
// rule match every finding, so findings carry no PII field and pii_types is not here.
// Every key PolicyRule declares.
const RULE_KEYS = ['id', 'description', 'scanner', 'action', 'severity', 'match'];
const MATCH_KEYS = ['server_name', 'finding_id', 'severity', 'category', 'license_type'];
// Policy files may write severities in any case (applyAction uppercases them).
const isSeverityAnyCase = (v: unknown) => typeof v === 'string' && isSeverity(v.toUpperCase());
const SEVERITY_LIST = Object.keys(SEVERITY_ORDER).join(', ').toLowerCase();

// An unknown match key or severity does not error at scan time: the rule just
// never matches, or writes a severity the tally drops, and a block rule
// quietly stops blocking. So both are rejected when the file loads.
function ruleFieldProblem(rule: PolicyRule): string | null {
  // A typo'd top-level key (matcher, scaner) is ignored, and a rule with no
  // filter matches every finding.
  const unknown = Object.keys(rule).find(k => !RULE_KEYS.includes(k));
  if (unknown) return `unknown key '${unknown}'. Valid: ${RULE_KEYS.join(', ')}`;
  if (rule.scanner !== undefined && (typeof rule.scanner !== 'string' || !rule.scanner.trim())) {
    return `'scanner' must be a non-empty string`;
  }
  if (rule.severity !== undefined && !isSeverityAnyCase(rule.severity)) {
    return `invalid severity '${rule.severity}'. Valid: ${SEVERITY_LIST}`;
  }
  if (rule.match === undefined) return null;
  const m = rule.match as Record<string, unknown>;
  if (typeof m !== 'object' || m === null || Array.isArray(m)) return `'match' must be an object`;
  for (const [key, value] of Object.entries(m)) {
    if (!MATCH_KEYS.includes(key)) return `unknown match key '${key}'. Valid: ${MATCH_KEYS.join(', ')}`;
    const values = Array.isArray(value) ? value : [value];
    // '' is falsy in ruleMatches, so it would skip the filter and match everything.
    if (values.length === 0 || !values.every(v => typeof v === 'string' && v.trim() !== '')) {
      return `match.${key} must be a non-empty string or a non-empty list of non-empty strings`;
    }
    if (key === 'severity' && !values.every(isSeverityAnyCase)) {
      return `match.severity has an invalid severity. Valid: ${SEVERITY_LIST}`;
    }
  }
  return null;
}

/**
 * No file found: null. A file that exists but cannot be parsed or fails the
 * schema, or an explicit path that does not exist, throws PolicyError:
 * a scan that skips its policy must not look like a pass.
 */
export function loadYamlPolicy(customPath?: string): SecurityPolicy | null {
  let policyPath = customPath;

  if (!policyPath) {
    const cwdPath = path.join(process.cwd(), '.mcp-scan-policy.yml');
    const homePath = path.join(os.homedir(), '.mcp-scan-policy.yml');

    if (policyFileExists(cwdPath)) policyPath = cwdPath;
    else if (policyFileExists(homePath)) policyPath = homePath;
  }

  if (!policyPath) return null;
  if (!policyFileExists(policyPath)) {
    throw new PolicyError(`Policy file not found: ${policyPath}. Fix the --policy path; the scan will not run without it.`);
  }

  let parsed: SecurityPolicy;
  try {
    parsed = readAndParsePolicy(policyPath);
  } catch (e: any) {
    throw new PolicyError(`Cannot use policy file ${policyPath}: ${e.message}. Fix or remove the file; the scan will not run without it.`);
  }
  const problem = schemaProblem(parsed);
  if (problem) {
    throw new PolicyError(`Invalid policy file ${policyPath}: ${problem}. Fix or remove the file; the scan will not run without it.`);
  }
  return parsed;
}

export function validatePolicy(policyPath: string): boolean {
  if (!policyFileExists(policyPath)) {
      console.error(chalk.red(`Policy file not found: ${policyPath}`));
      return false;
  }
  try {
    const parsed = readAndParsePolicy(policyPath);
    const problem = schemaProblem(parsed);
    if (problem) {
      console.error(chalk.red(problem));
      return false;
    }
    console.log(chalk.green(`✓ Policy file valid: ${policyPath} (${parsed.rules.length} rules)`));
    return true;
  } catch (e: any) {
    console.error(chalk.red(`Policy validation failed: ${e.message}`));
    return false;
  }
}

function toArray<T>(value: T | T[] | undefined): T[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

function ruleMatches(rule: PolicyRule, result: ServerScanResult, finding: Finding): boolean {
  const m = rule.match;
  if (m) {
    if (m.server_name && !toArray(m.server_name).includes(result.serverName)) return false;
    if (m.finding_id && !toArray(m.finding_id).includes(finding.id)) return false;
    if (m.severity && !toArray(m.severity).map(s => s.toUpperCase()).includes(finding.severity.toUpperCase())) return false;
    // Server-level: the license the package registry reported for this server.
    // Exact (case-insensitive) so 'GPL' does not also cover 'LGPL'/'AGPL' by accident.
    if (m.license_type) {
      const license = result.metadata?.license;
      if (typeof license !== 'string' || !toArray(m.license_type).some(l => String(l).toLowerCase() === license.toLowerCase())) return false;
    }
    if (m.category && !toArray(m.category).some(c => finding.description.toLowerCase().includes(String(c).toLowerCase()))) return false;
  }
  if (rule.scanner && !finding.id.includes(rule.scanner)) return false;
  return true;
}

const WARN_PREFIX = '[POLICY WARN]';
const BLOCK_PREFIX = '[POLICY BLOCK]';

function applyAction(finding: Finding, rule: PolicyRule): void {
  if (rule.action === 'override-severity' && rule.severity) {
    finding.severity = rule.severity.toUpperCase() as Severity;
  }
  if (rule.action === 'warn') {
    finding.severity = 'MEDIUM';
    if (!finding.description.startsWith(WARN_PREFIX)) {
      finding.description = `${WARN_PREFIX} ${finding.description}`;
    }
  }
  if (rule.action === 'block') {
    finding.severity = 'CRITICAL';
    if (!finding.description.startsWith(BLOCK_PREFIX)) {
      finding.description = `${BLOCK_PREFIX} ${finding.description}`;
    }
  }
}

export function applyPolicy(results: ServerScanResult[], policy: SecurityPolicy | null): ServerScanResult[] {
  if (!policy || !policy.rules || policy.rules.length === 0) return results;

  for (const result of results) {
    const newFindings: Finding[] = [];

    for (const finding of result.findings) {
      let skip = false;

      for (const rule of policy.rules) {
        if (!ruleMatches(rule, result, finding)) continue;
        if (rule.action === 'skip') {
          skip = true;
          break;
        }
        applyAction(finding, rule);
      }

      if (!skip) newFindings.push(finding);
    }

    result.findings = newFindings;
  }

  return results;
}
