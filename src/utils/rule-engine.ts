import fs from 'fs';
import path from 'path';
import os from 'os';
import { CustomRule } from '../types/rules.js';
import { ResolvedServer } from '../types/config.js';
import { Finding } from '../types/scan-result.js';
import { logger } from './logger.js';
import { auditDir } from './audit-logger.js';

function rulesDir(): string {
  return path.join(auditDir(), 'rules');
}

/**
 * Reads one rule file. Returns null when the file cannot be read or does
 * not contain valid JSON; the two failure modes get distinct messages so
 * a permissions problem is not misread as bad JSON.
 */
function readRuleFile(fullPath: string): CustomRule[] | null {
  let content: string;
  try {
    content = fs.readFileSync(fullPath, 'utf8');
  } catch (e: any) {
    logger.warn(`Failed to read rule file ${fullPath}: ${e.message}`);
    return null;
  }

  try {
    const parsed = JSON.parse(content);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch (e: any) {
    logger.warn(`Failed to parse rule file ${fullPath}: ${e.message}`);
    return null;
  }
}

export function loadCustomRules(): CustomRule[] {
  const rules: CustomRule[] = [];
  const dir = rulesDir();
  if (!fs.existsSync(dir)) {
    // One-time migration hint: MCP_SCAN_HOME users whose rules loaded
    // from ~/.mcp-scan/rules before the home override existed.
    const legacy = path.join(os.homedir(), '.mcp-scan', 'rules');
    if (process.env.MCP_SCAN_HOME && fs.existsSync(legacy)) {
      logger.warn(`Custom rules not found in ${dir}, but ${legacy} exists. Move them there to keep loading them.`);
    }
    return rules;
  }

  for (const file of fs.readdirSync(dir)) {
    if (!file.endsWith('.json')) continue;
    const parsed = readRuleFile(path.join(dir, file));
    if (parsed) rules.push(...parsed);
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
