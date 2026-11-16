import os from 'os';
import fs from 'fs';
import path from 'path';
import { detectTools } from '../config/detector.js';
import { parseConfig, extractServers, loadPolicy, loadIgnoreList } from '../config/parser.js';
import { scanSecrets } from '../scanners/secret-scanner.js';
import { scanPermissions } from '../scanners/permission-scanner.js';
import { scanRegistry, isRegistryKey, configKey } from '../scanners/registry-scanner.js';
import { scanTyposquat } from '../scanners/typosquat-scanner.js';
import { scanTransport } from '../scanners/transport-scanner.js';
import { scanConfig } from '../scanners/config-scanner.js';
import { scanAst } from '../scanners/ast-scanner.js';
import { scanPromptInjection } from '../scanners/prompt-injection-scanner.js';
import { scanToolPoisoning } from '../scanners/tool-poisoning-scanner.js';
import { scanEnvLeak } from '../scanners/env-leak-scanner.js';
import { scanSupplyChain, SupplyChainResult } from '../scanners/supply-chain-scanner.js';
import { scanPackageDeep, npxPackageArg, npxPackageCandidates, parsePackageSpec, launcher, NPX_BOOL_OPTS } from '../scanners/package-scanner.js';
import { scanLicense } from '../scanners/license-scanner.js';
import { scanDataFlow } from '../scanners/data-flow-scanner.js';
import { scanNetworkEgress } from '../scanners/network-egress-scanner.js';
import { scanDataControls } from '../scanners/data-controls-scanner.js';
import { writeSarifReport } from '../utils/sarif-reporter.js';
import { applyPolicy, loadYamlPolicy } from '../policy/engine.js';
import { ScanReport, ServerScanResult, Finding } from '../types/scan-result.js';
import { ScanOptions } from '../types/scan-options.js';
import { DetectedTool } from '../types/config.js';
import { createSpinner } from '../utils/spinner.js';
import { printJsonReport } from '../utils/json-reporter.js';
import { printReport } from '../utils/reporter.js';
import { logScan, checkFingerprints, assertBaselineKeyUsable, fingerprintKey } from '../utils/audit-logger.js';
import { recalcSeverityCounts, countTotalFindings } from '../utils/severity-tally.js';
import { repoHint, reportHint, findReportablePackage } from '../utils/repo-hint.js';
import { loadCustomRules, evaluateCustomRules } from '../utils/rule-engine.js';
import { SEVERITY_ORDER, Severity, isSeverity } from '../types/severity.js';
import { logger } from '../utils/logger.js';
import { introspect, LiveCatalog } from '../utils/mcp-client.js';
import { scanLive, crossServerShadows } from '../scanners/live-scanner.js';
import { snapshotOf, loadSnapshots, saveSnapshots, diffSnapshots, snapshotFile, ServerSnapshot } from '../utils/live-snapshot.js';

export async function runScan(options: ScanOptions = {}): Promise<ScanReport> {
  const startTime = Date.now();

  // Before any work: a key path that is not a file cannot be fixed mid-scan.
  assertBaselineKeyUsable();
  
  // Both policies load before anything is scanned or written: a broken one
  // throws PolicyError and the scan never starts.
  const policy = loadPolicy();
  const yamlPolicy = loadYamlPolicy(options.policy);
  const ignoreList = loadIgnoreList(undefined, { silent: options.silent });
  const customRules = loadCustomRules();
  if (policy && !options.silent) {
    logger.detail(`Applied security policy from .mcp-scan.json`);
  }

  // Initialize logger based on options
  if (options.silent || options.json || options.ci) logger.isSilent = true;
  if (options.verbose) logger.isVerbose = true;

  const spinner = !logger.isSilent ? createSpinner('Detecting MCP configurations...', !options.ci).start() : null;

  if (options.verbose && spinner) {
    spinner.stop();
    logger.info('Verbose mode enabled. Printing detailed logs.');
  }

  let tools: DetectedTool[];

  if (options.config) {
    let resolvedPath = options.config;
    if (resolvedPath.startsWith('~')) {
      resolvedPath = path.join(os.homedir(), resolvedPath.slice(1));
    }
    const configPath = path.resolve(resolvedPath);
    const exists = fs.existsSync(configPath);
    const toolName = path.basename(configPath, path.extname(configPath));
    tools = [{ name: toolName, configPath, exists }];
    if (options.verbose) logger.detail(`Using config file: ${configPath}`);
  } else {
    tools = await detectTools({ fs, os, process });
  }
  if (options.verbose) logger.detail(`Detected ${tools.length} potential tool configs.`);
  const report: ScanReport = {
    results: [],
    totalScanned: 0,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    infoCount: 0,
    totalDurationMs: 0,
    version: options.version
  };

  const seenServers = new Set<string>();
  const liveCatalogs = new Map<string, { name: string; launch: string; configPath: string; catalog: LiveCatalog }>();
  
  const minSeverityLevel = (options.severity || policy?.maxSeverity || 'low').toUpperCase() as Severity;
  if (!isSeverity(minSeverityLevel)) {
    throw new Error(`Invalid severity '${options.severity}'. Valid values: ${Object.keys(SEVERITY_ORDER).join(', ').toLowerCase()}`);
  }
  const minSeverity = SEVERITY_ORDER[minSeverityLevel];

  for (const tool of tools) {
    if (!tool.exists) continue;

    const config = parseConfig(tool.configPath);
    if (!config) continue;

    const servers = extractServers(tool.name, tool.configPath, config);
    const activeServers = servers.filter(s => !s.disabled);
    
    for (const server of activeServers) {
      const serverStartTime = Date.now();
      
      // With --live the env decides which catalog a server serves (tokens, tenants),
      // so two entries that differ only in env are both introspected.
      const headers = (server as { headers?: Record<string, unknown> }).headers;
      const envKey = options.live ? ` ${JSON.stringify([Object.entries(server.env ?? {}).sort(), Object.entries(headers ?? {}).sort()])}` : '';
      const serverKey = (server.url
        ? server.url
        : `${server.command} ${server.args?.join(' ') || ''}`) + envKey;
      if (seenServers.has(serverKey)) {
        // Just note duplicate, not a full re-scan
        report.results.push({
          serverName: server.name,
          toolName: tool.name,
          configPath: server.configPath,
          scanDurationMs: 0,
          findings: [{
            id: 'duplicate-server',
            severity: 'MEDIUM',
            description: `Duplicate server definition found across tools.`,
          }]
        });
        report.mediumCount++;
        continue;
      }
      seenServers.add(serverKey);

      if (spinner) spinner.text = `Scanning ${server.name} in ${tool.name}...`;

      // A throwing scanner must not abort the whole scan. Each scanner runs
      // isolated; a failure surfaces as a LOW finding instead of killing the
      // run and hiding every other scanner's results.
      const runScanner = async (name: string, fn: () => Finding[] | Promise<Finding[]>): Promise<Finding[]> => {
        try {
          return await fn();
        } catch (err) {
          return [{
            id: 'scanner-error',
            severity: 'LOW',
            description: `Scanner ${name} failed on server '${server.name}': ${err instanceof Error ? err.message : String(err)}`,
            fixRecommendation: 'Internal error in mcp-scan. Please report it with the offending config.'
          }];
        }
      };

      const scannerRuns: Array<[string, () => Finding[] | Promise<Finding[]>]> = [
        ['secret', () => scanSecrets(server)],
        ['env-leak', () => scanEnvLeak(server, server.configPath)],
        ['prompt-injection', () => scanPromptInjection(server)],
        ['tool-poisoning', () => scanToolPoisoning(server)],
        ['permissions', () => scanPermissions(server)],
        ['registry', () => scanRegistry(server, options.offline)],
        ['typosquat', () => scanTyposquat(server)],
        ['transport', () => scanTransport(server, policy?.allowedDomains)],
        ['config', () => scanConfig(server)],
        ['ast', () => scanAst(server, policy?.allowedDomains)],
        ['policy', () => evaluateCustomRules(server, customRules)],
        ['data-flow', () => scanDataFlow(server, activeServers)],
        ['network-egress', () => scanNetworkEgress(server)],
        ['data-controls', () => scanDataControls(server)],
      ];

      let allFindings: Finding[] = [];
      for (const [name, fn] of scannerRuns) {
        allFindings.push(...await runScanner(name, fn));
      }

      // Simple heuristic for package name from supply-chain-scanner
      let packageName = '';
      let candidates: string[] = [];
      const cmd = launcher(server.command);
      if (cmd === 'npx' || cmd === 'npm') {
        const pkgArg = npxPackageArg(server.args, server.command);
        if (pkgArg) packageName = pkgArg;
        candidates = npxPackageCandidates(server.args, server.command);
      }
      // Keep the flags that pick where npm installs from, so an alternate
      // candidate is graded against the same registry as the real launch.
      const args = Array.isArray(server.args) ? server.args.filter((x): x is string => typeof x === 'string') : [];
      const where: string[] = [];
      // npx hands everything after the package to the server, so stop at the
      // first positional that isn't a flag's value (npx-cli's own rule).
      let valued = false;
      for (let i = 0; i < args.length; i++) {
        const a = args[i];
        if (a === '--') break;
        if (!a.startsWith('-')) {
          if (cmd === 'npx' && !valued) break;
          valued = false;
          continue;
        }
        valued = !a.includes('=') && !NPX_BOOL_OPTS.has(a) && !a.startsWith('--no-') && !/^-[a-z]{2,}$/i.test(a);
        const m = /^--([^=]+)(=|$)/.exec(a);
        if (!m || !(isRegistryKey(m[1]) || configKey(m[1]))) continue;
        where.push(a);
        if (!m[2] && args[i + 1] !== undefined && !args[i + 1].startsWith('-')) { where.push(args[++i]); valued = false; }
      }

      // An unknown flag can swallow the package as its value, leaving several
      // candidates. The scanners above graded the riskiest one; grade the
      // rest too so a flag value can never hide the package that runs.
      for (const cand of candidates.filter(c => c !== packageName)) {
        const alt = { ...server, command: 'npx', args: [...where, cand] };
        const seen = new Set(allFindings.map(f => `${f.id}|${f.description}`));
        for (const [name, fn] of [['registry', () => scanRegistry(alt, options.offline)], ['typosquat', () => scanTyposquat(alt)]] as Array<[string, () => Finding[] | Promise<Finding[]>]>) {
          allFindings.push(...(await runScanner(name, fn)).filter(f => !seen.has(`${f.id}|${f.description}`)));
        }
      }

      // Apply policy: Blocked Packages
      if (policy && policy.blockedPackages && (candidates.some(c => policy.blockedPackages!.includes(c) || policy.blockedPackages!.includes(parsePackageSpec(c).name)) || policy.blockedPackages.includes(parsePackageSpec(packageName).name) || policy.blockedPackages.includes(packageName) || policy.blockedPackages.includes(server.name))) {
        allFindings.push({
          id: 'blocked-package-policy',
          severity: 'CRITICAL',
          description: `Package '${packageName || server.name}' is explicitly blocked by company policy.`,
          fixRecommendation: 'Remove this server or replace it with an approved alternative.'
        });
      }

      // --live: the only place we execute the configured server. What it
      // serves is the text the model actually reads.
      let liveCatalog: LiveCatalog | undefined;
      // A server the policy blocks, a known-malicious or typosquatted package, or one the user told us to ignore is never started.
      const skipLive = allFindings.some(f => f.id === 'blocked-package-policy' || f.id === 'known-malicious' || f.id === 'typosquat-detection')
        || ignoreList.includes(server.name) || ignoreList.some(i => server.configPath.endsWith(i));
      if (options.live && skipLive) {
        allFindings.push({ id: 'live-skipped', severity: 'INFO', description: `Server '${server.name}' was not started for --live: it is blocked, known malicious, a typosquat, or ignored.` });
      } else if (options.live) {
        if (spinner) spinner.text = `Connecting to ${server.name}...`;
        try {
          liveCatalog = await introspect(server, { timeoutMs: options.liveTimeout, noNetwork: options.offline });
          allFindings.push(...await runScanner('live', () => scanLive(liveCatalog!)));
        } catch (err) {
          allFindings.push({
            id: 'live-unreachable',
            // A server that needs credentials we deliberately do not hand over is expected, not alarming.
            severity: /HTTP 40[13]|--offline/.test(err instanceof Error ? err.message : '') ? 'LOW' : 'MEDIUM',
            description: `Could not introspect server '${server.name}': ${err instanceof Error ? err.message : String(err)}. Its tool descriptions were not checked.`,
            fixRecommendation: 'Run the server command by hand to see why it does not answer, or scan it without --live. A server that fails only under a scanner deserves a look.',
          });
        }
      }

      // Apply policy: Required Env Var Prefix
      if (policy && policy.requiredEnvVarPrefix && server.env) {
        for (const key of Object.keys(server.env)) {
          if (!key.startsWith(policy.requiredEnvVarPrefix)) {
            allFindings.push({
              id: 'env-var-prefix-risk',
              severity: 'LOW',
              description: `Environment variable '${key}' does not match required prefix '${policy.requiredEnvVarPrefix}'.`,
              fixRecommendation: `Rename the environment variable to use the '${policy.requiredEnvVarPrefix}' prefix.`
            });
          }
        }
      }

      let trustScore: number | undefined;
      let metadata: SupplyChainResult['metadata'];
      // Package/CVE, supply-chain trust, and license checks always run; the
      // README documents that supply-chain scanning makes registry lookups,
      // disabled with --offline. Previously these were silently skipped for
      // plain `mcp-scan` runs, so "Outdated Package" and "Supply Chain Risk"
      // findings never appeared without --verbose/--ci/--sbom/--submit.
      const packageFindings = await runScanner('package', () => scanPackageDeep(server, options.offline));
      allFindings.push(...packageFindings);

      const supplyChainResult = await runScanner('supply-chain', async () => {
        const result = await scanSupplyChain(server, options.offline);
        trustScore = result.trustScore;
        metadata = result.metadata;
        return result.findings;
      });
      allFindings.push(...supplyChainResult);

      // Same for the deeper package checks on the non-primary candidates.
      for (const cand of candidates.filter(c => c !== packageName)) {
        const alt = { ...server, command: 'npx', args: [...where, cand] };
        const seen = new Set(allFindings.map(f => `${f.id}|${f.description}`));
        const extra = [
          ...await runScanner('package', () => scanPackageDeep(alt, options.offline)),
          ...await runScanner('supply-chain', async () => (await scanSupplyChain(alt, options.offline)).findings),
        ];
        allFindings.push(...extra.filter(f => !seen.has(`${f.id}|${f.description}`)));
      }
      
      const licenseFindings = await runScanner('license', () => scanLicense(metadata));
      allFindings.push(...licenseFindings);

      // Apply policy: Suppress Rules
      if (policy && policy.suppressRules) {
        allFindings = allFindings.filter(f => !policy.suppressRules?.includes(f.id));
      }

      // Apply policy: Allowed Packages (skip all severity < critical)
      if (policy && policy.allowedPackages && (policy.allowedPackages.includes(packageName) || policy.allowedPackages.includes(server.name))) {
        allFindings = allFindings.filter(f => f.severity === 'CRITICAL');
      }

      // Apply ignore list
      const processedFindings = allFindings.map(f => {
        const isIgnored = ignoreList.includes(f.id) || 
                          ignoreList.includes(server.name) || 
                          ignoreList.some(i => server.configPath.endsWith(i));
        
        if (isIgnored) {
          return {
            ...f,
            severity: 'INFO' as Severity,
            description: `[SUPPRESSED] ${f.description}`
          };
        }
        return f;
      });

      const findings = processedFindings.filter(f => SEVERITY_ORDER[f.severity] >= minSeverity);

      const serverResult: ServerScanResult = {
        serverName: server.name,
        toolName: tool.name,
        configPath: server.configPath,
        findings,
        scanDurationMs: Date.now() - serverStartTime,
        trustScore,
        connection: {
          command: server.command || undefined,
          args: server.args,
          url: server.url || undefined,
          type: server.type || undefined,
          env: server.env ? Object.keys(server.env).sort() : undefined,
        },
        metadata
      };

      report.results.push(serverResult);
      report.totalScanned++;
      if (liveCatalog) liveCatalogs.set(fingerprintKey(serverResult), { launch: serverKey.slice(0, serverKey.length - envKey.length), name: server.name, configPath: server.configPath, catalog: liveCatalog });

      for (const finding of findings) {
        if (finding.severity === 'CRITICAL') report.criticalCount++;
        else if (finding.severity === 'HIGH') report.highCount++;
        else if (finding.severity === 'MEDIUM') report.mediumCount++;
        else if (finding.severity === 'LOW') report.lowCount++;
        else if (finding.severity === 'INFO') report.infoCount++;
      }
    }
  }

  // 17. Server Fingerprinting (Mutation Check)
  const mutations = checkFingerprints(report.results);
  for (const result of report.results) {
    const serverKey = fingerprintKey(result);
    if (mutations[serverKey]) {
      result.findings.push(...mutations[serverKey]);
    }
  }

  // Runs after the mutation check: creating the snapshot signing key first would make
  // a fresh install look like one whose baseline was deleted.
  // Live: tool-definition snapshots (rug pulls) and cross-server shadowing.
  if (options.live && liveCatalogs.size > 0) {
    const extra = new Map<string, Finding[]>();
    const add = (key: string, ...f: Finding[]) => extra.set(key, [...(extra.get(key) ?? []), ...f]);

    for (const [key, fs_] of crossServerShadows([...liveCatalogs].map(([id, v]) => ({ id, name: v.name, launch: v.launch, tools: v.catalog.tools.map(t => String(t.name)) })))) add(key, ...fs_);

    const marker = `${snapshotFile()}.seen`;
    let store = loadSnapshots(fs.existsSync(marker));
    // Recovery: after review, --accept-tool-changes starts a fresh baseline from what
    // the servers serve now (older baselines are not trusted, so they are dropped).
    if (store.status === 'tampered' && options.acceptToolChanges) store = { status: 'missing', servers: {} };
    const next: Record<string, ServerSnapshot> = { ...store.servers };
    let dirty = false;
    const fresh: Array<{ key: string; name: string; count: number }> = [];
    if (store.status === 'tampered') {
      for (const key of liveCatalogs.keys()) {
        add(key, {
          id: 'live-snapshot-tampered',
          severity: 'HIGH',
          description: `Tool snapshots could not be trusted: ${store.reason}. Rug-pull checks for this server did not run; treat the baseline as possibly modified.`,
          fixRecommendation: 'Review what these servers serve now, then run mcp-scan --live --accept-tool-changes to discard the old baseline and record a new one.',
        });
      }
    } else {
      for (const [key, { name, catalog }] of liveCatalogs) {
        let cur: ServerSnapshot;
        try {
          cur = snapshotOf(catalog);
        } catch (e) {
          // One hostile definition must not take the rest of the scan down with it.
          add(key, { id: 'live-incomplete', severity: 'HIGH', description: `Server '${name}' serves a definition that cannot be fingerprinted (${e instanceof Error ? e.message : String(e)}), so rug-pull detection did not run for it.`, fixRecommendation: 'Schemas nested this deep are not legitimate. Do not use this server.' });
          continue;
        }
        if (catalog.truncated) {
          // Never baseline a partial list. With a baseline already on file, what was
          // read is still compared (a rug pull must not hide behind a flood of tools).
          const prev = store.servers[key];
          add(key, { id: 'live-incomplete', severity: prev ? 'HIGH' : 'MEDIUM', description: `Server '${name}' served more than the scan reads (page or item cap hit), so only part of its catalog was checked${prev ? ' although an earlier scan saw it complete' : ''}. No baseline was ${prev ? 'changed' : 'recorded'}.`, fixRecommendation: 'A server with thousands of tools is unusual. Review it by hand.' });
          if (prev && !options.acceptToolChanges) add(key, ...diffSnapshots(name, prev, cur).filter(f => f.id !== 'tool-removed'));
          continue;
        }
        const prev = store.servers[key];
        if (!prev) {
          next[key] = cur;
          dirty = true;
          fresh.push({ key, name, count: Object.keys(cur.items).length });
        } else if (options.acceptToolChanges) {
          next[key] = cur;
          dirty = true;
        } else {
          add(key, ...diffSnapshots(name, prev, cur));
        }
      }
      const saved = dirty ? saveSnapshots(next) : true;
      if (dirty && saved) {
        try { fs.writeFileSync(marker, 'tool snapshots have been recorded on this install\n'); } catch (_e) { /* the store still works */ }
      }
      for (const f of fresh) {
        add(f.key, saved
          ? { id: 'live-baseline-recorded', severity: 'INFO', description: `Recorded a baseline of ${f.count} tool, prompt and resource definitions for '${f.name}'. Later --live scans report any change.` }
          : { id: 'live-snapshot-unsaved', severity: 'MEDIUM', description: `Could not save the tool baseline for '${f.name}' (is ${snapshotFile()} writable?). Rug-pull detection is off for it until a scan can save.`, fixRecommendation: 'Fix the permissions on the mcp-scan audit directory, then scan again.' });
      }
    }

    const ignored = (key: string) => { const v = liveCatalogs.get(key); return !!v && (ignoreList.includes(v.name) || ignoreList.some(i => v.configPath.endsWith(i))); };
    for (const result of report.results) {
      const found = (ignored(fingerprintKey(result)) ? [] : extra.get(fingerprintKey(result)) ?? [])
        .filter(f => SEVERITY_ORDER[f.severity] >= minSeverity)
        .filter(f => !(policy?.suppressRules ?? []).includes(f.id) && !ignoreList.includes(f.id));
      result.findings.push(...found);
    }
  }

  // 18. Apply YAML Policy
  if (yamlPolicy) {
    applyPolicy(report.results, yamlPolicy);
    if (!options.silent) {
      logger.detail(`Applied security policy from ${options.policy || '.mcp-scan-policy.yml'}`);
    }
  }

  // 19. Recalculate summary counts after policy application
  recalcSeverityCounts(report);

  report.totalDurationMs = Date.now() - startTime;
  
  if (spinner) {
    spinner.succeed(`Scan complete in ${report.totalDurationMs}ms`);
  }

  if (!options.silent) {
    if (options.json) {
      printJsonReport(report);
    } else {
      printReport(report, { ugig: options.ugig });
      // Human path only. --json takes the branch above, --ci forces --json
      // in the CLI handler (but runScan is also exported for embedders who
      // may call it with ci:true directly, so guard it here too), and
      // --sarif is excluded here explicitly since it can run alongside
      // this branch in a TTY.
      if (!options.sarif && !options.ci) {
        repoHint(countTotalFindings(report) > 0);
        reportHint(findReportablePackage(report));
      }
    }
  }

  logScan(report);

  if (options.sarif) {
    writeSarifReport(report, options.sarif);
    if (!options.silent) {
      logger.info(`SARIF report written to ${options.sarif}`);
    }
  }

  return report;
}
