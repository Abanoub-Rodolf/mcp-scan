import os from 'os';
import fs from 'fs';
import path from 'path';
import { detectTools } from '../config/detector.js';
import { parseConfig, extractServers, loadPolicy, loadIgnoreList } from '../config/parser.js';
import { scanSecrets } from '../scanners/secret-scanner.js';
import { scanPermissions } from '../scanners/permission-scanner.js';
import { scanRegistry } from '../scanners/registry-scanner.js';
import { scanTyposquat } from '../scanners/typosquat-scanner.js';
import { scanTransport } from '../scanners/transport-scanner.js';
import { scanConfig } from '../scanners/config-scanner.js';
import { scanAst } from '../scanners/ast-scanner.js';
import { scanPromptInjection } from '../scanners/prompt-injection-scanner.js';
import { scanToolPoisoning } from '../scanners/tool-poisoning-scanner.js';
import { scanEnvLeak } from '../scanners/env-leak-scanner.js';
import { scanSupplyChain, SupplyChainResult } from '../scanners/supply-chain-scanner.js';
import { scanPackageDeep } from '../scanners/package-scanner.js';
import { scanLicense } from '../scanners/license-scanner.js';
import { scanDataFlow } from '../scanners/data-flow-scanner.js';
import { scanNetworkEgress } from '../scanners/network-egress-scanner.js';
import { scanDataControls } from '../scanners/data-controls-scanner.js';
import { writeSarifReport } from '../utils/sarif-reporter.js';
import { applyPolicy, loadYamlPolicy } from '../policy/engine.js';
import { ScanReport, ServerScanResult, Finding } from '../types/scan-result.js';
import { DetectedTool } from '../types/config.js';
import { createSpinner } from '../utils/spinner.js';
import { printJsonReport } from '../utils/json-reporter.js';
import { printReport } from '../utils/reporter.js';
import { logScan, checkFingerprints } from '../utils/audit-logger.js';
import { loadCustomRules, evaluateCustomRules } from '../utils/rule-engine.js';
import { runFix } from './fix.js';
import { SEVERITY_ORDER, Severity } from '../types/severity.js';
import { logger } from '../utils/logger.js';

export async function runScan(options: { silent?: boolean, json?: boolean, verbose?: boolean, severity?: string, fix?: boolean, config?: string, version?: string, ugig?: boolean, ci?: boolean, sbom?: string, sarif?: string, policy?: string, offline?: boolean, submit?: boolean } = {}): Promise<ScanReport> {
  const startTime = Date.now();
  
  const policy = loadPolicy();
  const ignoreList = loadIgnoreList();
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
  
  const minSeverityLevel = (options.severity || policy?.maxSeverity || 'low').toUpperCase() as Severity;
  if (!(minSeverityLevel in SEVERITY_ORDER)) {
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
      
      const serverKey = server.url
        ? server.url
        : `${server.command} ${server.args?.join(' ') || ''}`;
      if (seenServers.has(serverKey)) {
        // Just note duplicate, not a full re-scan
        report.results.push({
          serverName: server.name,
          toolName: tool.name,
          configPath: tool.configPath,
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
        ['env-leak', () => scanEnvLeak(server, tool.configPath)],
        ['prompt-injection', () => scanPromptInjection(server)],
        ['tool-poisoning', () => scanToolPoisoning(server)],
        ['permissions', () => scanPermissions(server)],
        ['registry', () => scanRegistry(server)],
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
      if (server.command === 'npx' || server.command === 'npm') {
        const pkgArg = (Array.isArray(server.args) ? server.args : (server.args ? Object.values(server.args) : [])).find(a => typeof a === 'string' && !a.startsWith('-'));
        if (pkgArg) packageName = pkgArg as string;
      }

      // Apply policy: Blocked Packages
      if (policy && policy.blockedPackages && (policy.blockedPackages.includes(packageName) || policy.blockedPackages.includes(server.name))) {
        allFindings.push({
          id: 'blocked-package-policy',
          severity: 'CRITICAL',
          description: `Package '${packageName || server.name}' is explicitly blocked by company policy.`,
          fixRecommendation: 'Remove this server or replace it with an approved alternative.'
        });
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
                          ignoreList.some(i => tool.configPath.endsWith(i));
        
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
        configPath: tool.configPath,
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
    const serverKey = `${result.toolName}:${result.serverName}`;
    if (mutations[serverKey]) {
      result.findings.push(...mutations[serverKey]);
    }
  }

  // 18. Apply YAML Policy
  const yamlPolicy = loadYamlPolicy(options.policy);
  if (yamlPolicy) {
    applyPolicy(report.results, yamlPolicy);
    if (!options.silent) {
      logger.detail(`Applied security policy from ${options.policy || '.mcp-scan-policy.yml'}`);
    }
  }

  // 19. Recalculate summary counts after policy application
  report.criticalCount = 0;
  report.highCount = 0;
  report.mediumCount = 0;
  report.lowCount = 0;
  report.infoCount = 0;

  for (const result of report.results) {
    for (const finding of result.findings) {
      if (finding.severity === 'CRITICAL') report.criticalCount++;
      else if (finding.severity === 'HIGH') report.highCount++;
      else if (finding.severity === 'MEDIUM') report.mediumCount++;
      else if (finding.severity === 'LOW') report.lowCount++;
      else if (finding.severity === 'INFO') report.infoCount++;
    }
  }

  report.totalDurationMs = Date.now() - startTime;
  
  if (spinner) {
    spinner.succeed(`Scan complete in ${report.totalDurationMs}ms`);
  }

  if (!options.silent) {
    if (options.json) {
      printJsonReport(report);
    } else {
      printReport(report, { ugig: options.ugig });
    }
  }
  
  logScan(report);
  
  if (options.fix) {
    await runFix();
  }

  if (options.sarif) {
    writeSarifReport(report, options.sarif);
    if (!options.silent) {
      logger.info(`SARIF report written to ${options.sarif}`);
    }
  }

  return report;
}
