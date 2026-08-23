import { Finding, ScanReport } from '../types/scan-result.js';
import { Severity } from '../types/severity.js';

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
  for (const finding of findings) {
    counts[finding.severity]++;
  }
  return counts;
}

/**
 * Total across all five severities. One definition so "any findings?"
 * cannot mean different things in the terminal report vs HTML/Slack.
 */
export function countTotalFindings(report: ScanReport): number {
  return report.criticalCount + report.highCount + report.mediumCount + report.lowCount + report.infoCount;
}

/**
 * Recomputes the five summary counters on a report from its results.
 * Single source for tallying so every command agrees on the numbers,
 * including after policy rules have mutated severities.
 */
export function recalcSeverityCounts(report: ScanReport): void {
  const totals: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
  for (const result of report.results) {
    const counts = countBySeverity(result.findings);
    totals.CRITICAL += counts.CRITICAL;
    totals.HIGH += counts.HIGH;
    totals.MEDIUM += counts.MEDIUM;
    totals.LOW += counts.LOW;
    totals.INFO += counts.INFO;
  }
  report.criticalCount = totals.CRITICAL;
  report.highCount = totals.HIGH;
  report.mediumCount = totals.MEDIUM;
  report.lowCount = totals.LOW;
  report.infoCount = totals.INFO;
}
