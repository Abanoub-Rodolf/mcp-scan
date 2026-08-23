/**
 * Exit-code contracts, one entry per command surface. This file is the
 * single place that documents "when does mcp-scan exit nonzero"; if you
 * change a rule here, change the owning command in the same commit.
 *
 * - scan (interactive): findings never fail the shell; only thrown errors
 *   produce nonzero. index.ts enforces this guard.
 * - scan --ci: legacy inline guard, hardcoded to CRITICAL/HIGH only. The
 *   `ci` subcommand is the fuller contract (--max-severity, all five
 *   severities). Unifying them changes shell-visible behavior and needs
 *   an explicit product decision first.
 * - audit <server>: 1 on CRITICAL or HIGH findings after the deep audit.
 * - diff <old> <new>: 1 when any regression (newly added finding of any
 *   severity) exists between the two reports.
 * - watch / proxy: long-running processes; they manage their own exit on
 *   termination signals and carry no severity-based contract.
 */
export const EXIT_OK = 0;
export const EXIT_FINDINGS = 1;
