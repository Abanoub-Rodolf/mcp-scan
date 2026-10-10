import fs from 'fs';
import path from 'path';
import os from 'os';
import { CustomRule } from '../types/rules.js';
import { ResolvedServer } from '../types/config.js';
import { Finding } from '../types/scan-result.js';
import { logger } from './logger.js';
import { auditDir } from './audit-logger.js';
import { PolicyError, policyFileExists, readPolicyFile } from './policy-file.js';
import { SEVERITY_ORDER, isSeverity } from '../types/severity.js';

function rulesDir(): string {
  return path.join(auditDir(), 'rules');
}

const RULE_TARGETS = ['env', 'args', 'command', 'url', 'name'];

// A rule that is skipped later (bad regex, unknown severity the tally drops)
// is a check that silently stops running, so it is rejected at load.
function ruleProblem(r: any): string | null {
  if (typeof r !== 'object' || r === null || Array.isArray(r)) return 'expected an object';
  if (typeof r.id !== 'string' || !r.id) return `'id' must be a non-empty string`;
  if (!isSeverity(r.severity)) return `rule '${r.id}': 'severity' must be one of ${Object.keys(SEVERITY_ORDER).join(', ')}`;
  if (!RULE_TARGETS.includes(r.target)) return `rule '${r.id}': 'target' must be one of ${RULE_TARGETS.join(', ')}`;
  if (typeof r.pattern !== 'string') return `rule '${r.id}': 'pattern' must be a string`;
  try {
    new RegExp(r.pattern, 'i');
  } catch (e: any) {
    return `rule '${r.id}': invalid pattern: ${e.message}`;
  }
  if (r.negate !== undefined && typeof r.negate !== 'boolean') return `rule '${r.id}': 'negate' must be true or false`;
  return null;
}

/**
 * Reads one rule file. An unreadable file, bad JSON or an invalid rule
 * throws PolicyError: running with only some of the user's rules would
 * look like a clean scan. The read and parse failures keep distinct
 * messages so a permissions problem is not misread as bad JSON.
 */
function readRuleFile(fullPath: string): CustomRule[] {
  const fail = (why: string) =>
    new PolicyError(`${why}. Fix or remove ${fullPath}; the scan will not run without it.`);

  let content: string;
  try {
    // fd-based and non-blocking open: a FIFO named *.json would hang a plain read.
    content = readPolicyFile(fullPath);
  } catch (e: any) {
    throw fail(`Cannot read custom rule file ${fullPath}: ${e.message}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch (e: any) {
    throw fail(`Cannot parse custom rule file ${fullPath}: ${e.message}`);
  }
  const list = Array.isArray(parsed) ? parsed : [parsed];
  for (const r of list) {
    const problem = ruleProblem(r);
    if (problem) throw fail(`Invalid custom rule in ${fullPath}: ${problem}`);
  }
  return list as CustomRule[];
}

export function loadCustomRules(): CustomRule[] {
  const rules: CustomRule[] = [];
  const dir = rulesDir();
  if (!policyFileExists(dir)) {
    // One-time migration hint: MCP_SCAN_HOME users whose rules loaded
    // from ~/.mcp-scan/rules before the home override existed.
    const legacy = path.join(os.homedir(), '.mcp-scan', 'rules');
    if (process.env.MCP_SCAN_HOME && fs.existsSync(legacy)) {
      logger.warn(`Custom rules not found in ${dir}, but ${legacy} exists. Move them there to keep loading them.`);
    }
    return rules;
  }

  let files: string[];
  try {
    files = fs.readdirSync(dir);
  } catch (e: any) {
    throw new PolicyError(`Cannot read custom rules directory ${dir}: ${e.message}. Fix or remove it; the scan will not run without it.`);
  }
  for (const file of files) {
    if (!file.endsWith('.json')) continue;
    rules.push(...readRuleFile(path.join(dir, file)));
  }
  return rules;
}

export function evaluateCustomRules(server: ResolvedServer, rules: CustomRule[]): Finding[] {
  const findings: Finding[] = [];

  for (const rule of rules) {
    try {
      const regex = new RegExp(rule.pattern, 'i');

      let matchFound = false;
      let matchSource = '';

      if (rule.target === 'command' && server.command && regex.test(server.command)) {
        matchFound = true;
        matchSource = `command '${server.command}'`;
      } else if (rule.target === 'args' && server.args) {
        const argsArray = Array.isArray(server.args) ? server.args : Object.values(server.args);
        const matchingArg = argsArray.find(a => typeof a === 'string' && regex.test(a));
        if (matchingArg) {
          matchFound = true;
          matchSource = `argument '${matchingArg}'`;
        }
      } else if (rule.target === 'env' && server.env) {
        const matchingKey = Object.keys(server.env).find(k => regex.test(k) || regex.test(server.env![k]));
        if (matchingKey) {
           matchFound = true;
           matchSource = `environment variable '${matchingKey}'`;
        }
      } else if (rule.target === 'url') {
        const url = server.url || '';
        if (url && regex.test(url)) {
          matchFound = true;
          matchSource = `url '${url}'`;
        }
      } else if (rule.target === 'name' && regex.test(server.name)) {
        matchFound = true;
        matchSource = `server name '${server.name}'`;
      }

      const triggered = rule.negate ? !matchFound : matchFound;
      if (triggered) {
        const source = rule.negate ? `(no match for '${rule.pattern}' in ${rule.target})` : matchSource;
        findings.push({
          id: rule.id,
          severity: rule.severity,
          description: `Custom rule '${rule.id}' triggered ${source}: ${rule.description}`,
          fixRecommendation: rule.fixRecommendation
        });
      }
    } catch (_e: any) {
      // Invalid regex, skip rule
    }
  }

  return findings;
}
