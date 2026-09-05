import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import { auditDir } from './audit-logger.js';
import { validatePackageName } from '../scanners/package-scanner.js';
import type { ScanReport } from '../types/scan-result.js';

// 1,123 people/week run this via npx and never see the GitHub repo behind
// it. One dim line, shown once per machine ever, right after a scan that
// actually found something (the moment the tool just proved its worth).
// Same TTY gate and MCP_SCAN_NO_HINTS opt-out as proHint.
const MARKER_FILE = 'repo-hint-shown';

// Belt-and-suspenders for a read-only home: if the marker write fails, the
// hint would otherwise print on every findings scan forever. This flag
// caps it at once per process even then.
let shownThisProcess = false;

export function repoHint(hasFindings: boolean, stream: NodeJS.WriteStream = process.stdout): void {
  if (process.env.MCP_SCAN_NO_HINTS) return;
  if (!hasFindings) return;
  if (!stream.isTTY) return;
  if (shownThisProcess) return;

  const markerPath = path.join(auditDir(), MARKER_FILE);
  if (fs.existsSync(markerPath)) return;

  stream.write(chalk.dim('\nmcp-scan is MIT and maintained by one person: github.com/Abanoub-Rodolf/mcp-scan\n'));
  shownThisProcess = true;

  // Claim the one-time slot now that the line has actually printed.
  // Best-effort: a read-only home or sandboxed FS just means the hint
  // can show again next process, capped by shownThisProcess within this one.
  try {
    fs.mkdirSync(auditDir(), { recursive: true });
    fs.writeFileSync(markerPath, new Date().toISOString());
  } catch (_error) {}
}

/**
 * First server in the report launched via npx/npm/node with a bare package
 * spec as its argument, for the post-scan badge hint below. Reuses the same
 * name validation as `mcp-scan badge` so the hint never suggests a package
 * name that command would then reject (also filters out `node <file-path>`
 * servers, which aren't a package spec at all).
 */
export function findBadgeablePackage(report: ScanReport): string | undefined {
  for (const result of report.results) {
    const command = result.connection?.command;
    if (command !== 'npx' && command !== 'npm' && command !== 'node') continue;

    const pkgArg = result.connection?.args?.find(a => !a.startsWith('-'));
    if (!pkgArg) continue;

    const validated = validatePackageName(pkgArg);
    if (validated.valid) return validated.name;
  }
  return undefined;
}

// No marker file here, unlike repoHint: this is cheap to compute per scan
// and only fires when the scan actually found something to badge, so
// there's no "once ever" state worth persisting.
export function badgeHint(packageName: string | undefined, stream: NodeJS.WriteStream = process.stdout): void {
  if (!packageName) return;
  if (process.env.MCP_SCAN_NO_HINTS) return;
  if (!stream.isTTY) return;

  stream.write(chalk.dim(`\nPublishing an MCP server? Add a public scan badge: npx mcp-scan badge ${packageName}\n`));
}
