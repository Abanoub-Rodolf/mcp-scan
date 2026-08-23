import fs from 'fs';
import path from 'path';
import os from 'os';
import { parse } from 'yaml';
import { Finding, ServerScanResult } from '../types/scan-result.js';
import { Severity } from '../types/severity.js';
import chalk from 'chalk';

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
      pii_types?: string | string[];
  };
}

export interface SecurityPolicy {
  version: number;
  rules: PolicyRule[];
}

function readAndParsePolicy(policyPath: string): SecurityPolicy {
  const content = fs.readFileSync(policyPath, 'utf8');
  return parse(content) as SecurityPolicy;
}

export function loadYamlPolicy(customPath?: string): SecurityPolicy | null {
  let policyPath = customPath;

  if (!policyPath) {
    const cwdPath = path.join(process.cwd(), '.mcp-scan-policy.yml');
    const homePath = path.join(os.homedir(), '.mcp-scan-policy.yml');

    if (fs.existsSync(cwdPath)) policyPath = cwdPath;
    else if (fs.existsSync(homePath)) policyPath = homePath;
  }

  if (!policyPath || !fs.existsSync(policyPath)) return null;

  try {
    return readAndParsePolicy(policyPath);
  } catch (e: any) {
    console.warn(chalk.yellow(`Warning: Failed to parse policy file at ${policyPath}: ${e.message}`));
    return null;
  }
}

const VALID_ACTIONS = ['block', 'warn', 'skip', 'override-severity'] as const;

export function validatePolicy(policyPath: string): boolean {
  if (!fs.existsSync(policyPath)) {
      console.error(chalk.red(`Policy file not found: ${policyPath}`));
      return false;
  }
  try {
    const parsed = readAndParsePolicy(policyPath);
    if (!parsed || parsed.version !== 1 || !Array.isArray(parsed.rules)) {
      console.error(chalk.red('Invalid policy schema. Expected: { version: 1, rules: [...] }'));
      return false;
    }
    for (const rule of parsed.rules) {
      if (!rule.id || !rule.action) {
        console.error(chalk.red(`Rule missing required fields (id, action): ${JSON.stringify(rule)}`));
        return false;
      }
      if (!VALID_ACTIONS.includes(rule.action)) {
        console.error(chalk.red(`Rule '${rule.id}' has invalid action '${rule.action}'. Valid: ${VALID_ACTIONS.join(', ')}`));
        return false;
      }
      if (rule.action === 'override-severity' && !rule.severity) {
        console.error(chalk.red(`Rule '${rule.id}' uses override-severity but is missing the 'severity' field.`));
        return false;
      }
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
