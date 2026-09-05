import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import { auditDir } from './audit-logger.js';
import { validatePackageName } from '../scanners/package-scanner.js';
import { reportUrlFor } from '../commands/badge.js';
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

// A JS/TS entrypoint like `index.js` or `dist/index.js` is a legal npm
// package name character-for-character (dots and slashes-after-scope are
// both allowed by the registry name rules), so validatePackageName alone
// waves it through. Catch it before that: a script extension or a path
// separator outside the `@scope/` position means "file", not "package".
const SCRIPT_EXTENSION_RE = /\.(js|mjs|cjs|ts|mts|cts)$/;

function looksLikeFilePath(candidate: string): boolean {
  if (SCRIPT_EXTENSION_RE.test(candidate)) return true;
  const rest = candidate.startsWith('@') ? candidate.replace(/^@[^/]+\//, '') : candidate;
  return rest.includes('/');
}

// `npx --package=<pkg> <bin>` (and the space-separated / `-p` variants) runs
// a different binary than the package that provides it, so the first
// non-flag arg is the bin name, not the package. Look for an explicit
// --package/-p first and only fall back to "first bare arg" when there isn't one.
function packageArgFrom(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--package' || arg === '-p') return args[i + 1];
    if (arg.startsWith('--package=')) return arg.slice('--package='.length);
    if (arg.startsWith('-p=')) return arg.slice('-p='.length);
  }
  return args.find(a => !a.startsWith('-'));
}

/**
 * First server in the report launched via npx/npm/node with a bare package
 * spec as its argument, for the post-scan report hint below. Reuses the
 * same name validation as `mcp-scan badge` so the hint never points at a
 * report URL for a name that command would then reject (also filters out
 * `node <file-path>` servers, which aren't a package spec at all).
 */
export function findReportablePackage(report: ScanReport): string | undefined {
  for (const result of report.results) {
    const command = result.connection?.command;
    if (command !== 'npx' && command !== 'npm' && command !== 'node') continue;

    const pkgArg = packageArgFrom(result.connection?.args ?? []);
    if (!pkgArg || looksLikeFilePath(pkgArg)) continue;

    const validated = validatePackageName(pkgArg);
    if (validated.valid) return validated.name;
  }
  return undefined;
}

// No marker file here, unlike repoHint: this is cheap to compute per scan
// and only fires when the scan actually found a package to report on, so
// there's no "once ever" state worth persisting.
//
// Points at the hosted report rather than the `badge` command: the scanned
// server is almost always a third-party package the user doesn't own, so a
// "publish a badge" pitch is wrong for the common case. A report link is
// useful regardless of who owns the package.
export function reportHint(packageName: string | undefined, stream: NodeJS.WriteStream = process.stdout): void {
  if (!packageName) return;
  if (process.env.MCP_SCAN_NO_HINTS) return;
  if (!stream.isTTY) return;

  stream.write(chalk.dim(`\nPublic scan report for ${packageName}: ${reportUrlFor(packageName)}\n`));
}
