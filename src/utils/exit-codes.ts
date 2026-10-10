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
 * - any command: 1 (EXIT_ERROR) when mcp-scan refuses to run, e.g. baseline.key
 *   is a directory. No scan happens and the message goes to stderr.
 * - any command that needs a policy: 1 and a message on stderr when a policy
 *   file exists but cannot be read or parsed, has a wrong-typed field, or
 *   when --policy names a file that is missing. Same code as findings, so
 *   the message is the way to tell them apart; the scan never runs.
 * - watch / proxy: long-running processes; they manage their own exit on
 *   termination signals and carry no severity-based contract.
 */
export const EXIT_OK = 0;
export const EXIT_FINDINGS = 1;
export const EXIT_ERROR = 1;
export const EXIT_POLICY_ERROR = 1;
