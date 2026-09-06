// Scanners in this set were built to read short MCP config strings (tool
// descriptions, CLI args, manifest fields) - not whole source files. Fed a
// real JS/TS file by source-scan.mjs's ecosystem package-source deep scan,
// they fire on ordinary template literals, doc-comment URLs, and common
// words like "run", producing thousands of MEDIUM/HIGH hits with no real
// signal (run2 ecosystem-scan campaign, 2026-09-05: env-var-scope-leak,
// tool-name-shadow, exfiltration-vector, network-egress-unknown were the
// top offenders). Their findings still occasionally catch something real,
// so this downgrades rather than drops them: severity becomes INFO and a
// heuristic:true flag is added for manual triage. findings-ranked.mjs
// excludes heuristic:true from the reportable list by default.
//
// This module is intentionally standalone (no import of the compiled
// scanners) so the downgrade logic can be unit tested without a build.
// It is only ever applied inside the ecosystem deep-scan path
// (scripts/source-scan.mjs) - CLI scans of real user configs never call
// this and are unaffected.
export const HEURISTIC_SOURCE_SCANNERS = new Set([
  'tool-poisoning-scanner',
  'prompt-injection-scanner',
  'transport-scanner',
  'network-egress-scanner',
  'data-flow-scanner',
  'env-leak-scanner',
]);

export function downgradeIfHeuristic(finding, scanner) {
  if (!HEURISTIC_SOURCE_SCANNERS.has(scanner)) return finding;
  if (finding.severity === 'INFO') return finding;
  return {
    ...finding,
    heuristic: true,
    originalSeverity: finding.severity,
    severity: 'INFO',
  };
}
