import { runScan } from './scan.js';
import { printJsonReport } from '../utils/json-reporter.js';
import { SEVERITY_ORDER, Severity } from '../types/severity.js';
import fs from 'fs';

export async function runCi(options: {
  maxSeverity?: string,
  json?: boolean,
  output?: string,
  config?: string,
  policy?: string,
  offline?: boolean,
}) {
  const maxSeverityStr = (options.maxSeverity || 'high').toUpperCase() as Severity;
  if (!(maxSeverityStr in SEVERITY_ORDER)) {
    throw new Error(`Invalid max severity '${options.maxSeverity}'. Valid values: ${Object.keys(SEVERITY_ORDER).join(', ').toLowerCase()}`);
  }
  const maxSeverityThreshold = SEVERITY_ORDER[maxSeverityStr];

  // Forward scan options so `ci` can target a config, use a policy file,
  // or run fully offline - previously every flag except --max-severity
  // was silently ignored.
  const report = await runScan({
    silent: true,
    ci: true,
    config: options.config,
    policy: options.policy,
    offline: options.offline,
  });

  if (options.output) {
    fs.writeFileSync(options.output, JSON.stringify(report, null, 2));
  } else {
    printJsonReport(report);
  }

  let shouldFail = false;
  if (report.criticalCount > 0 && maxSeverityThreshold <= SEVERITY_ORDER.CRITICAL) shouldFail = true;
  if (report.highCount > 0 && maxSeverityThreshold <= SEVERITY_ORDER.HIGH) shouldFail = true;
  if (report.mediumCount > 0 && maxSeverityThreshold <= SEVERITY_ORDER.MEDIUM) shouldFail = true;

  const exitCode = shouldFail ? 1 : 0;

  // Print summary to stderr so CI systems can capture it separately from JSON stdout
  const totalFindings = report.criticalCount + report.highCount + report.mediumCount + report.lowCount;
  process.stderr.write(`mcp-scan: ${totalFindings} finding(s), exit code ${exitCode}\n`);

  process.exitCode = exitCode;
}
