import { runScan } from './scan.js';
import { logger } from '../utils/logger.js';
import { atomicWriteConfig } from '../config/writer.js';
import { parseConfig } from '../config/parser.js';
import { RawMcpServerEntry } from '../types/config.js';
import { Finding } from '../types/scan-result.js';
import readline from 'readline';
import { SECRET_PATTERNS } from '../data/secret-patterns.js';
import chalk from 'chalk';

/**
 * Applies the automatic remediation for one finding to a raw config
 * server entry. Mutates the entry in place and returns whether anything
 * changed. Pure enough to unit test: no I/O, no prompting.
 */
export function applyAutoFix(finding: Finding, server: RawMcpServerEntry): boolean {
  let changed = false;

  switch (finding.id) {
    case 'exposed-secret': {
      if (!server.env) break;
      for (const [key, value] of Object.entries(server.env)) {
        const str = String(value);
        for (const pattern of SECRET_PATTERNS) {
          if (pattern.regex.test(str)) {
            server.env[key] = `\${${key}}`;
            changed = true;
            break;
          }
        }
      }
      break;
    }
    case 'http-transport-no-auth': {
      let argsChanged = false;
      if (Array.isArray(server.args)) {
        server.args = server.args.map(arg => {
          if (typeof arg === 'string' && arg.startsWith('http://')) {
            argsChanged = true;
            return arg.replace('http://', 'https://');
          }
          return arg;
        });
      }
      // Attempt BOTH surfaces independently: a server can carry http://
      // in an arg and in its url at the same time.
      const url = server.url;
      const urlChanged = typeof url === 'string' && url.startsWith('http://');
      if (urlChanged) {
        server.url = url.replace('http://', 'https://');
      }
      changed = argsChanged || urlChanged;
      break;
    }
    case 'outdated-transport': {
      if (Array.isArray(server.args)) {
        server.args = server.args.map(arg => {
          if (arg === '--transport=sse') {
            changed = true;
            return '--transport=streamable-http';
          }
          return arg;
        });
      }
      break;
    }
    case 'insecure-transport': {
      let argsChanged = false;
      if (Array.isArray(server.args)) {
        server.args = server.args.map(arg => {
          if (typeof arg === 'string' && arg.startsWith('ws://')) {
            argsChanged = true;
            return arg.replace('ws://', 'wss://');
          }
          return arg;
        });
      }
      const url = server.url;
      const urlChanged = typeof url === 'string' && url.startsWith('ws://');
      if (urlChanged) {
        server.url = url.replace('ws://', 'wss://');
      }
      changed = argsChanged || urlChanged;
      break;
    }
    default:
      break;
  }

  return changed;
}

export async function runFix() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  const question = (query: string): Promise<string> => new Promise((resolve) => rl.question(query, resolve));

  logger.brand('Starting interactive auto-fix with confidence scoring...');
  const initialReport = await runScan({ silent: true });

  let fixedCount = 0;
  let autoAppliedCount = 0;

  for (const result of initialReport.results) {
    const fixableFindings = result.findings.filter(f => f.fixable);

    if (fixableFindings.length === 0) continue;

    for (const finding of fixableFindings) {
      const confidence = finding.remediationConfidence || 50;
      const confidenceColor = confidence >= 90 ? chalk.green : confidence >= 70 ? chalk.yellow : chalk.red;

      logger.divider();
      logger.warn(`Issue in ${result.serverName} (${result.configPath})`);
      logger.log(`[${finding.severity}] ${finding.description}`);
      logger.log(`Confidence Score: ${confidenceColor(confidence + '%')}`);
      logger.fix(`Proposed Fix: ${finding.fixRecommendation}`);

      let shouldApply = false;
      if (confidence >= 95) {
        const answer = await question('High confidence fix. Auto-apply? (Y/n): ');
        shouldApply = !answer.toLowerCase().startsWith('n');
        if (shouldApply) autoAppliedCount++;
      } else {
        const answer = await question('Apply this fix? (y/N): ');
        shouldApply = answer.toLowerCase().startsWith('y');
      }

      if (shouldApply) {
        try {
           const config = parseConfig(result.configPath);
           if (!config || !config.mcpServers[result.serverName]) continue;

           const server = config.mcpServers[result.serverName];
           const changed = applyAutoFix(finding, server);

           if (changed) {
              atomicWriteConfig(result.configPath, JSON.stringify(config, null, 2));
              logger.pass('fix applied');
              fixedCount++;
           } else {
              logger.error('Could not apply fix automatically.');
           }
        } catch (e: any) {
           logger.error(`Failed to apply fix: ${e.message}`);
        }
      } else {
        logger.info('Skipped.');
      }
    }
  }

  rl.close();
  logger.divider();

  if (fixedCount > 0) {
    logger.brand(`Auto-fix complete. Applied ${fixedCount} fixes (${autoAppliedCount} auto-applied).`);
    logger.info('Re-scanning to verify fixes...');
    const finalReport = await runScan({ silent: true });
    const remaining = finalReport.criticalCount + finalReport.highCount + finalReport.mediumCount + finalReport.lowCount;
    const resolved = (initialReport.criticalCount + initialReport.highCount + initialReport.mediumCount + initialReport.lowCount) - remaining;
    logger.pass(`Verification complete: ${resolved} issues resolved, ${remaining} issues remaining.`);
  } else {
    logger.brand('Auto-fix complete. No changes made.');
  }
}
