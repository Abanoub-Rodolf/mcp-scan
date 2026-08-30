import { runScan } from './scan.js';
import { logger } from '../utils/logger.js';
import { ScanReport } from '../types/scan-result.js';
import glob from 'fast-glob';
import path from 'path';
import fs from 'fs';
import { printJsonReport } from '../utils/json-reporter.js';
import { printReport } from '../utils/reporter.js';
import { generateHtmlReport } from '../utils/html-reporter.js';
import { recalcSeverityCounts } from '../utils/severity-tally.js';

/**
 * Scans all config files in a directory and aggregates them into one report.
 */
export async function runMultiConfigReport(options: { configs?: string, html?: string, json?: boolean }) {
  const targetDir = options.configs || process.cwd();
  logger.brand(`Aggregating reports from: ${targetDir}`);

  // dot:true is required - fast-glob's default excludes dotfiles/dot-dirs,
  // which silently dropped the single most common MCP config filename,
  // ".mcp.json", from every result. Without it, `report` could tell you
  // "found N config files" and still scan zero of the servers those
  // configs define, with no error - a security tool reporting false
  // assurance. See regression test in tests/commands/report.test.ts.
  const configFiles = await glob(['**/*.json', '**/*.toml', '**/*.yaml', '**/*.yml'], {
    cwd: targetDir,
    absolute: true,
    dot: true,
    ignore: [
      '**/node_modules/**',
      '**/package.json',
      '**/package-lock.json',
      '**/tsconfig.json',
      '**/.mcp-scan.json',
      '**/.mcp-scan-policy.yml',
      '**/.github/**',
      '**/.git/**',
      '**/dist/**',
    ]
  });

  if (configFiles.length === 0) {
    logger.error(`No config files found in ${targetDir}`);
    return;
  }

  logger.info(`Found ${configFiles.length} potential config files.`);

  const aggregatedReport: ScanReport = {
    results: [],
    totalScanned: 0,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    infoCount: 0,
    totalDurationMs: 0
  };

  const startTime = Date.now();
  const seenServers = new Set<string>();
  let notMcpConfigCount = 0;
  let failedFileCount = 0;

  for (const file of configFiles) {
    // Basic check if it looks like an MCP config
    try {
        const content = fs.readFileSync(file, 'utf8');
        if (!content.includes('mcpServers') && !content.includes('mcp_servers')) {
          notMcpConfigCount++;
          continue;
        }

        logger.detail(`Scanning: ${path.relative(targetDir, file)}`);
        const report = await runScan({ silent: true, config: file });

        for (const result of report.results) {
            const key = `${result.serverName}:${JSON.stringify(result.findings)}`;
        if (!seenServers.has(key)) {
            seenServers.add(key);
            aggregatedReport.results.push(result);
            aggregatedReport.totalScanned++;
        }
        }
    } catch (err) {
      // Silently swallowed per-file failures made configs vanish from the
      // aggregated report with no way to know they were skipped.
      failedFileCount++;
      logger.warn(`Skipping ${file}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  recalcSeverityCounts(aggregatedReport);
  aggregatedReport.totalDurationMs = Date.now() - startTime;

  // A report that finds files but scans nothing must say so loudly - a
  // silent "0 servers, 0 findings" reads as a clean bill of health when
  // it may actually mean every candidate file failed or was skipped.
  if (aggregatedReport.totalScanned === 0) {
    logger.error(
      `Found ${configFiles.length} file(s) but scanned 0 MCP servers ` +
      `(${notMcpConfigCount} did not look like MCP configs, ${failedFileCount} failed to scan). ` +
      `This is not a clean result - it means nothing was actually checked.`
    );
  } else if (failedFileCount > 0) {
    logger.warn(`${failedFileCount} config file(s) failed to scan and are missing from this report.`);
  }

  if (options.json) {
    printJsonReport(aggregatedReport);
  } else {
    printReport(aggregatedReport);
  }

  if (options.html) {
    const htmlContent = generateHtmlReport(aggregatedReport);
    fs.writeFileSync(options.html, htmlContent);
    logger.pass(`Aggregated HTML report generated: ${options.html}`);
  }
}
