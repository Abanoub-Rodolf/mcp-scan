
import { ScanReport, ServerScanResult } from '../types/scan-result.js';
import { logger } from './logger.js';
import { SEVERITY_ORDER, BRAND_COLOR, SEVERITY_COLORS } from '../types/severity.js';
import { countTotalFindings } from './severity-tally.js';

import chalk from 'chalk';

const brand = chalk.hex(BRAND_COLOR);
const accentGray = chalk.hex(SEVERITY_COLORS.INFO);
const criticalBg = chalk.bgHex(SEVERITY_COLORS.CRITICAL).white.bold;
const highBg = chalk.bgHex(SEVERITY_COLORS.HIGH).white.bold;
const mediumBg = chalk.bgHex(SEVERITY_COLORS.MEDIUM).white.bold;
const lowBg = chalk.bgHex(SEVERITY_COLORS.LOW).white;
const infoBg = chalk.bgHex(BRAND_COLOR).white;
const passGreen = chalk.hex('#3FB950').bold;
const dim = chalk.dim;

function severityBadge(severity: string): string {
  switch (severity) {
    case 'CRITICAL': return criticalBg(` CRITICAL `);
    case 'HIGH':     return highBg(` HIGH     `);
    case 'MEDIUM':   return mediumBg(` MEDIUM   `);
    case 'LOW':      return lowBg(` LOW      `);
    case 'INFO':     return infoBg(` INFO     `);
    default:         return severity;
  }
}

function printBanner(version: string): void {
  const boxWidth = 50;
  const innerWidth = boxWidth - 4; // 46 visible chars between │ and │
  const border = brand;

  // Compute padding by measuring visible width (strip ANSI, count emoji as 2 cols)
  function pad(content: string, visibleLen: number): string {
    return content + ' '.repeat(Math.max(0, innerWidth - visibleLen));
  }

  // 🛡️ = 2 cols, rest ASCII: 3 + 2 + 2 + 8 + 2 + 1 + version.length
  const titleVisLen = 18 + version.length;
  const titleContent = `   🛡️  ${chalk.white.bold('mcp-scan')}  ${dim('v' + version)}`;

  // subtitle is pure ASCII: 3 + 39 = 42. If the subtitle text changes,
  // update subtitleVisLen AND boxWidth together or the right rail drifts.
  const subtitleVisLen = 42;
  const subtitleContent = `   ${accentGray('Security scanner for MCP server configs')}`;

  logger.log(border('  ╭' + '─'.repeat(innerWidth) + '╮'));
  logger.log(border('  │') + ' '.repeat(innerWidth) + border('│'));
  logger.log(border('  │') + pad(titleContent, titleVisLen) + border('│'));
  logger.log(border('  │') + pad(subtitleContent, subtitleVisLen) + border('│'));
  logger.log(border('  │') + ' '.repeat(innerWidth) + border('│'));
  logger.log(border('  ╰' + '─'.repeat(innerWidth) + '╯'));
  logger.emptyLine();
}

export function printReport(report: ScanReport, options: { ugig?: boolean } = {}) {
  logger.emptyLine();

  printBanner(report.version || 'unknown');

  if (report.results.length === 0) {
    logger.info('No MCP servers detected to scan.');
    logger.emptyLine();
    logger.log(dim('  Built by Rodolf · thynkq.com'));
    logger.emptyLine();
    return;
  }

  // Group results: issues first, then clean
  const withFindings = report.results.filter(r => r.findings.length > 0);
  const clean = report.results.filter(r => r.findings.length === 0);

  for (const result of withFindings) {
    printResultSection(result);
    logger.emptyLine();
  }

  printCleanServers(clean);

  printSummary(report, options);
}

function printResultSection(result: ServerScanResult): void {
  const sortedFindings = [...result.findings].sort(
    (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]
  );

  const rail = brand.dim('  │ ');

  logger.log(brand('  ┌ ') + brand.bold(result.toolName) + accentGray(' › ') + chalk.white.bold(result.serverName));
  logger.log(rail + dim(result.configPath));
  logger.log(rail);

  for (const finding of sortedFindings) {
    logger.log(rail + ` ${severityBadge(finding.severity)}  ${chalk.bold(finding.id)}`);
    logger.log(rail + `           ${chalk.white(finding.description)}`);
    if (finding.fixRecommendation) {
      logger.log(rail + dim(`           ↳ ${finding.fixRecommendation}`));
    }
    logger.log(rail);
  }

  logger.log(brand.dim('  └' + '─'.repeat(55)));
}

function printCleanServers(clean: ServerScanResult[]): void {
  if (clean.length === 0) return;
  const maxNameLength = Math.max(...clean.map(r => `${r.toolName} › ${r.serverName}`.length));

  for (const result of clean) {
    const name = `${result.toolName} › ${result.serverName}`;
    logger.log(passGreen(`  ✓ `) + name.padEnd(maxNameLength + 2) + dim('0 issues'));
  }
  logger.emptyLine();
}

function printSummary(report: ScanReport, options: { ugig?: boolean }): void {
  const total = report.totalScanned;
  const ms = report.totalDurationMs;
  const uniqueClients = new Set(report.results.map(r => r.toolName)).size;
  
  const divider = brand.dim('  ' + '─'.repeat(50));
  
  logger.log(divider);
  logger.emptyLine();

  const isAllClear = countTotalFindings(report) === 0;

  if (isAllClear) {
    logger.log(passGreen(`   ✓ All clear`) + dim(` (${total} server${total !== 1 ? 's' : ''} scanned in ${ms}ms)`));
  } else {
    logger.log(chalk.white(`   Scanned ${chalk.bold(total)} server${total !== 1 ? 's' : ''} across ${chalk.bold(uniqueClients)} client${uniqueClients !== 1 ? 's' : ''} in ${ms}ms`));
    logger.emptyLine();
    
    const parts = [
      report.criticalCount > 0 ? chalk.hex(SEVERITY_COLORS.CRITICAL).bold(`    ${report.criticalCount} critical`) : dim(`    0 critical`),
      report.highCount > 0     ? chalk.hex(SEVERITY_COLORS.HIGH).bold(`    ${report.highCount} high`)     : dim(`    0 high`),
      report.mediumCount > 0   ? chalk.hex(SEVERITY_COLORS.MEDIUM).bold(`    ${report.mediumCount} medium`) : dim(`    0 medium`),
      report.lowCount > 0      ? dim.bold(`    ${report.lowCount} low`) : dim(`    0 low`),
    ];
    logger.log(parts.join(''));
  }

  if (total > 0) {
    if (isAllClear) {
      logger.emptyLine();
      logger.log(dim('   All servers verified clean. List them on ') + brand.dim('ugig.net/mcp') + dim(' →'));
    } else if (options.ugig) {
      logger.emptyLine();
      logger.log(dim('   List your servers on ') + brand.dim('ugig.net/mcp') + dim(' →'));
    }
  }

  logger.emptyLine();
  logger.log(divider);
  logger.emptyLine();
  // Interactive-only paid next step: this function is only called in non-json
  // mode (CI forces json and takes printJsonReport instead), so the guard is
  // findings-present + not the ugig listing flow. One line, no spam — the free
  // scanner stays the whole product.
  if (
    !options.ugig &&
    report.criticalCount + report.highCount + report.mediumCount > 0
  ) {
    logger.log(
      dim('  Need a human call on these? ') +
      accentGray('MCP Risk Review (48h, fixed scope) at ') +
      brand.dim.underline('thynkq.com/pricing#specialist-review')
    );
    logger.emptyLine();
  }
  logger.log(
    dim('  by ') +
    chalk.white.bold('Rodolf') +
    accentGray(' · ') +
    accentGray('thynk') +
    brand.bold('Q') +
    accentGray('  ') +
    brand.dim.underline('thynkq.com')
  );
  logger.emptyLine();
}
