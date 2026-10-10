import fs from 'fs';
import os from 'os';
import path from 'path';
import { runScan } from './scan.js';
import { logger } from '../utils/logger.js';
import { BaselineKeyError, keyFile } from '../utils/audit-logger.js';
import { EXIT_ERROR } from '../utils/exit-codes.js';
import { detectTools } from '../config/detector.js';
import { ScanReport, Finding, ServerScanResult } from '../types/scan-result.js';
import chalk from 'chalk';
import { sendWebhook, sendSlackWebhook } from '../utils/webhook.js';
import { PolicyError } from '../utils/policy-file.js';
import { EXIT_POLICY_ERROR } from '../utils/exit-codes.js';

export async function runWatch(options: { webhook?: string, slackWebhook?: string } = {}) {
  logger.brand('Starting enhanced watch mode...');

  const tools = await detectTools({ fs, os, process });
  const validPaths = tools.filter(t => t.exists).map(t => t.configPath);

  if (validPaths.length === 0) {
    logger.error('No config files found to watch.');
    process.exit(1);
  }

  logger.info(`Watching ${validPaths.length} configuration files for changes...`);

  let lastReport: ScanReport | null = null;
  let debounceTimeout: NodeJS.Timeout;
  const watchedDirs = new Set<string>();
  const keyPath = keyFile();
  let scanning = false;
  let keyDirty = false;
  // scan() clears the screen, so a watcher that died must be re-announced in
  // every footer or it stays invisible.
  const deadDirs = new Set<string>();
  const deadNote = () => {
    if (deadDirs.size > 0) logger.warn(`Not watching: ${[...deadDirs].join(', ')} (restart watch)`);
  };
  let keyTimeout: NodeJS.Timeout;

  // A scan can create or remove baseline.key itself (loadOrCreateKey, and the
  // cleanup after a failed store write). Compare against the state the last
  // scan left behind so only outside edits count as triggers, not our own.
  const keyState = () => {
    try {
      const st = fs.statSync(keyPath);
      return `${st.mtimeMs}:${st.size}:${st.isFile()}`;
    } catch {
      return 'missing';
    }
  };
  let keySnapshot = keyState();

  const performScan = async (changedPath?: string) => {
    scanning = true;
    const keyAtStart = keyState();
    try {
      await scan(changedPath);
    } finally {
      keySnapshot = keyState();
      scanning = false;
      // An outside edit that landed mid-scan was not seen by it. Our own
      // write also differs from the start state, but the rescan then ends on
      // the state it started from, so this converges after one extra scan.
      // Gap: an edit made late in the scan whose event is delivered after
      // this snapshot is taken sees an equal state and is dropped; the next
      // config or key change picks it up.
      if (keyDirty) {
        keyDirty = false;
        if (keySnapshot !== keyAtStart) enqueue(keyPath);
      }
    }
  };

  // One scan at a time, at most one waiting: overlapping scans would race on
  // exitCode, the key snapshot and the screen. Errors are caught here so a
  // timer-fired scan can't become an unhandled rejection that kills watch.
  let inflight: Promise<void> = Promise.resolve();
  let queued = false;
  let queuedPath: string | undefined;
  const enqueue = (changedPath?: string) => {
    queuedPath = changedPath;
    if (queued) return;
    queued = true;
    inflight = inflight.then(async () => {
      queued = false;
      try {
        await performScan(queuedPath);
      } catch (e) {
        logger.error(e instanceof Error ? e.message : String(e));
        process.exitCode = EXIT_ERROR;
      }
    }).catch(() => {}); // backstop: a rejected link would stop every later scan
  };

  const scan = async (changedPath?: string) => {
    process.stdout.write('\x1b[2J\x1b[0;0H');
    
    logger.brand('mcp-scan DASHBOARD (Watch Mode)');
    logger.detail(`Last update: ${new Date().toLocaleTimeString()}`);
    if (changedPath) logger.detail(`Triggered by change in: ${changedPath}`);
    logger.divider();

    let currentReport: ScanReport;
    try {
      currentReport = await runScan({ silent: true });
    } catch (e) {
      if (e instanceof BaselineKeyError) {
        // Rescans run from a timer, where a rejection would be unhandled and
        // dump a stack. Say it once and keep watching: the key file is a
        // trigger below, so fixing it rescans without a restart.
        logger.error(e.message);
        process.exitCode = EXIT_ERROR;
        logger.log(chalk.dim('Scan skipped. Fixing baseline.key rescans.'));
        deadNote();
        return;
      }
      if (!(e instanceof PolicyError)) throw e;
      logger.error(e.message);
      // First scan: nothing to watch without a trustworthy policy. Later
      // scans: keep watching, but never report "all clear" for a scan that
      // did not run.
      if (!lastReport) process.exit(EXIT_POLICY_ERROR);
      process.exitCode = EXIT_POLICY_ERROR;
      logger.log(chalk.dim('Scan skipped. Saving the fixed policy file rescans.'));
      deadNote();
      return;
    }
    process.exitCode = undefined;
    
    if (lastReport) {
      const { newFindings, resolvedFindings } = diffReports(lastReport, currentReport);
      
      if (newFindings.length > 0) {
        logger.high(`⚠ ${newFindings.length} NEW findings detected!`);
        newFindings.forEach(f => logger.log(chalk.red(`  [${f.finding.severity}] ${f.server}: ${f.finding.id}`)));
        
        if (options.webhook) await sendWebhook(options.webhook, currentReport);
        if (options.slackWebhook) await sendSlackWebhook(options.slackWebhook, currentReport);
      }
      
      if (resolvedFindings.length > 0) {
        logger.pass(`✓ ${resolvedFindings.length} findings resolved.`);
        resolvedFindings.forEach(f => logger.log(chalk.green(`  [FIXED] ${f.server}: ${f.finding.id}`)));
      }

      if (newFindings.length === 0 && resolvedFindings.length === 0) {
        logger.info('No changes in security findings.');
      }
    } else {
      const total = currentReport.criticalCount + currentReport.highCount + currentReport.mediumCount + currentReport.lowCount;
      if (total === 0) {
        logger.pass('✓ All clear. No findings.');
      } else {
        logger.warn(`Current state: ${total} total findings.`);
      }
    }

    logger.emptyLine();
    logger.log(chalk.dim('Watching for changes... (Press Ctrl+C to stop)'));
    deadNote();
    lastReport = currentReport;
  };

  await performScan();

  // A broken policy or baseline key skips every scan until it is fixed, so
  // saving either must rescan too.
  const triggers = [
    ...validPaths,
    path.join(process.cwd(), '.mcp-scan.json'),
    path.join(process.cwd(), '.mcp-scan-policy.yml'),
    path.join(os.homedir(), '.mcp-scan-policy.yml'),
    keyPath,
  ];

  for (const configPath of triggers) {
    const dir = path.dirname(configPath);
    if (watchedDirs.has(dir)) continue;
    // The audit dir can still be missing after the first scan; skip it. One
    // created later is not picked up until watch restarts.
    if (configPath === keyPath && !fs.existsSync(dir)) continue;
    watchedDirs.add(dir);

    try {
      const watcher = fs.watch(dir, (eventType, filename) => {
        const changedPath = filename ? path.join(dir, filename) : null;
        if (changedPath === keyPath) {
          if (scanning) { keyDirty = true; return; }
          clearTimeout(keyTimeout);
          keyTimeout = setTimeout(() => {
            if (scanning) keyDirty = true;
            else if (keyState() !== keySnapshot) enqueue(changedPath);
          }, 500);
          return;
        }
        if (changedPath && triggers.includes(changedPath)) {
          clearTimeout(debounceTimeout);
          debounceTimeout = setTimeout(() => enqueue(changedPath), 500);
        }
      });
      watcher.on('error', (e: Error) => {
        deadDirs.add(dir);
        logger.error(`Watch on ${dir} stopped: ${e.message}`);
      });
    } catch (error: any) {
      logger.error(`Failed to watch directory ${dir}: ${error.message}`);
    }
  }
  
  const onExit = () => {
    logger.info('Stopping watch mode.');
    // A broken policy or baseline key set exitCode; Ctrl+C must not erase it.
    process.exit(process.exitCode ?? 0);
  };
  process.on('SIGINT', onExit);
  process.on('SIGTERM', onExit);
}

function diffReports(oldReport: ScanReport, newReport: ScanReport) {
  const oldFindingsMap = new Map<string, string[]>();
  const oldResultsByKey = new Map<string, ServerScanResult>();
  for (const res of oldReport.results) {
    const key = `${res.toolName}:${res.serverName}`;
    oldFindingsMap.set(key, res.findings.map(f => `${f.id}:${f.severity}`));
    oldResultsByKey.set(key, res);
  }

  const newFindings: { server: string, finding: Finding }[] = [];
  const resolvedFindings: { server: string, finding: Finding }[] = [];

  for (const res of newReport.results) {
    const serverKey = `${res.toolName}:${res.serverName}`;
    const oldIds = oldFindingsMap.get(serverKey) || [];
    const newIds = res.findings.map(f => `${f.id}:${f.severity}`);

    for (const f of res.findings) {
      if (!oldIds.includes(`${f.id}:${f.severity}`)) {
        newFindings.push({ server: serverKey, finding: f });
      }
    }

    const oldResult = oldResultsByKey.get(serverKey);
    if (oldResult) {
            for (const f of oldResult.findings) {
                if (!newIds.includes(`${f.id}:${f.severity}`)) {
                    resolvedFindings.push({ server: serverKey, finding: f });
                }
            }
        }
  }

  return { newFindings, resolvedFindings };
}
