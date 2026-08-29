import { runScan } from './scan.js';
import { printJsonReport } from '../utils/json-reporter.js';
import { SEVERITY_ORDER, Severity } from '../types/severity.js';
import { EXIT_OK, EXIT_FINDINGS } from '../utils/exit-codes.js';
import fs from 'fs';
import { proHint } from '../utils/pro-hint.js';

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

  const countsBySeverity: Record<Severity, number> = {
    CRITICAL: report.criticalCount,
    HIGH: report.highCount,
    MEDIUM: report.mediumCount,
    LOW: report.lowCount,
    INFO: report.infoCount,
  };
  let shouldFail = false;
  for (const severity of Object.keys(countsBySeverity) as Severity[]) {
    if (countsBySeverity[severity] > 0 && SEVERITY_ORDER[severity] >= maxSeverityThreshold) {
      shouldFail = true;
      break;
    }
  }

  const exitCode = shouldFail ? EXIT_FINDINGS : EXIT_OK;

  // Print summary to stderr so CI systems can capture it separately from JSON stdout
  const totalFindings = report.criticalCount + report.highCount + report.mediumCount + report.lowCount;
  process.stderr.write(`mcp-scan: ${totalFindings} finding(s), exit code ${exitCode}\n`);

  if (shouldFail) proHint(process.stderr);

  process.exitCode = exitCode;
}
