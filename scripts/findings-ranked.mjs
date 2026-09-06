// Renders the high/critical findings across an ecosystem-scan run into one
// markdown table meant to be read by a person deciding what to report to a
// bounty program - not the full per-package JSON dump.

import { writeFile } from 'fs/promises';
import path from 'path';

const REPORTABLE_SEVERITIES = new Set(['CRITICAL', 'HIGH']);

// OSV/CVE hits are a deterministic rule (id + confirmed version-range
// match against a published advisory); everything else here is a regex
// pattern match on text taken out of runtime context - a real hit, but
// one a human still needs to read in context before trusting it.
function confidenceFor(findingId) {
  return findingId.startsWith('dependency-known-vulnerability-') || findingId.startsWith('known-vulnerability-')
    ? 'deterministic'
    : 'heuristic';
}

function mdEscape(value) {
  return String(value).replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

function oneSentence(description) {
  const trimmed = description.trim();
  const cut = trimmed.match(/^[^.]{1,180}\.?/);
  return (cut ? cut[0] : trimmed).slice(0, 200);
}

export function collectRankedFindings(results) {
  const rows = [];
  for (const result of results) {
    if (result.unsupported) continue;
    for (const finding of result.findings ?? []) {
      // Heuristic hits (config-oriented scanners run against whole source
      // files - see scripts/heuristic-findings.mjs) are for manual triage,
      // never a severity count. Excluded here even though the downgrade
      // already drops them below REPORTABLE_SEVERITIES, so this list stays
      // correct if a future scanner ever flags something heuristic above
      // INFO.
      if (finding.heuristic) continue;
      if (!REPORTABLE_SEVERITIES.has(finding.severity)) continue;
      rows.push({
        package: result.package,
        version: result.metadata?.version ?? 'unknown',
        weeklyDownloads: result.weeklyDownloads ?? null,
        vendor: result.bounty?.vendor ?? null,
        bountyProgram: result.bounty?.program ?? null,
        payout: result.bounty?.payout ?? null,
        scanner: finding.scanner ?? 'unknown',
        location: `${finding.sourceFile ?? result.package}${finding.sourceLine ? ':' + finding.sourceLine : ''}`,
        description: oneSentence(finding.description),
        confidence: confidenceFor(finding.id),
        severity: finding.severity,
        // Only set on OSV dependency-CVE findings: whether the resolved
        // version came from a shipped lockfile or was inferred from the
        // manifest's semver range. 'n/a' for every other finding type.
        dependencyResolution: finding.dependencyResolution ?? 'n/a',
      });
    }
  }

  const severityRank = { CRITICAL: 0, HIGH: 1 };
  rows.sort((a, b) => {
    const bySeverity = severityRank[a.severity] - severityRank[b.severity];
    if (bySeverity !== 0) return bySeverity;
    return (b.weeklyDownloads ?? 0) - (a.weeklyDownloads ?? 0);
  });
  return rows;
}

export async function writeFindingsRanked(results, outDir) {
  const rows = collectRankedFindings(results);

  const lines = [
    '# High and critical findings, ranked',
    '',
    `Generated ${new Date().toISOString()}. ${rows.length} finding(s) at HIGH or CRITICAL severity ` +
      `across ${results.filter((r) => !r.unsupported).length} scanned npm packages. Heuristic hits ` +
      "(config-oriented scanners run against whole source files) are excluded regardless of severity - " +
      "see out/ecosystem/<package>.json for the full heuristic:true list. Dep. Resolution is 'lockfile' " +
      "only when a shipped lockfile confirmed the installed version; 'manifest-range' means the version " +
      "was inferred from a semver range and needs a real install to confirm before reporting. Nothing " +
      "here is a confirmed, reported vulnerability - see docs/disclosure-policy.md before reporting anything.",
    '',
    '| Severity | Package | Version | Weekly DL | Vendor | Bounty | Payout | Scanner | Location | Finding | Confidence | Dep. Resolution |',
    '|---|---|---|---:|---|---|---|---|---|---|---|---|',
  ];

  for (const row of rows) {
    lines.push(
      `| ${row.severity} | ${mdEscape(row.package)} | ${mdEscape(row.version)} | ${row.weeklyDownloads ?? 'n/a'} | ` +
        `${mdEscape(row.vendor ?? 'unmapped')} | ${mdEscape(row.bountyProgram ?? 'n/a')} | ${mdEscape(row.payout ?? 'n/a')} | ` +
        `${mdEscape(row.scanner)} | ${mdEscape(row.location)} | ${mdEscape(row.description)} | ${row.confidence} | ${row.dependencyResolution} |`
    );
  }

  if (rows.length === 0) {
    lines.push('', '_No HIGH or CRITICAL findings in this run._');
  }

  await writeFile(path.join(outDir, 'findings-ranked.md'), lines.join('\n') + '\n');
  return rows;
}
