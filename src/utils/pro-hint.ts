import chalk from 'chalk';

// One muted line, shown only after high-intent human-facing output
// (compliance, sbom, policy, or a failed ci gate). Never in JSON or
// SARIF streams. MCP_SCAN_NO_HINTS=1 silences it permanently.
export function proHint(stream: NodeJS.WriteStream = process.stdout): void {
  if (process.env.MCP_SCAN_NO_HINTS) return;
  if (!stream.isTTY) return;
  stream.write(chalk.dim('\nNeed this as a report for a customer, auditor, or teammate? thynkq.com/products/mcp-scan\n'));
}
