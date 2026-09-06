import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';
import { downgradeIfHeuristic, HEURISTIC_SOURCE_SCANNERS } from '../../scripts/heuristic-findings.mjs';

const SOURCE_SCAN_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), '../../scripts/source-scan.mjs');

// scripts/source-scan.mjs never imports HEURISTIC_SOURCE_SCANNERS directly -
// it calls downgradeIfHeuristic(withMeta, scanner) with a scanner-id string
// literal it owns itself (the first element of each pair in its `tagged`
// array). A typo or rename on either side (e.g. 'env-leak-scanner' drifting
// to 'env-var-leak-scanner' in one file but not the other) would silently
// stop that scanner's findings from ever being downgraded, and none of the
// tests above would catch it since they call downgradeIfHeuristic directly
// with hand-picked strings, not the real ones source-scan.mjs uses.
function taggedScannerIds() {
  const text = readFileSync(SOURCE_SCAN_PATH, 'utf8');
  const ids = [...text.matchAll(/^\s*\['([a-z-]+)',/gm)].map((m) => m[1]);
  if (ids.length === 0) throw new Error('no scanner-id literals found in source-scan.mjs tagged array - regex out of sync with the file');
  return ids;
}

describe('heuristic-findings: integration with source-scan.mjs', () => {
  it('every HEURISTIC_SOURCE_SCANNERS id is one of the scanner-id literals source-scan.mjs actually tags findings with', () => {
    const ids = new Set(taggedScannerIds());
    for (const heuristicId of HEURISTIC_SOURCE_SCANNERS) {
      expect(ids.has(heuristicId), `'${heuristicId}' not found in source-scan.mjs tagged array - downgrade would silently never apply`).toBe(true);
    }
  });

  it('ast-scanner and secret-scanner (real findings, never heuristic) are not accidentally in HEURISTIC_SOURCE_SCANNERS', () => {
    expect(HEURISTIC_SOURCE_SCANNERS.has('ast-scanner')).toBe(false);
    expect(HEURISTIC_SOURCE_SCANNERS.has('secret-scanner')).toBe(false);
  });
});

// scripts/source-scan.mjs (the ecosystem package-source deep scan) feeds
// whole JS/TS source files to scanners built for short MCP config strings.
// This is the guard that keeps their volume out of the severity counts -
// see run2 campaign-summary.md, FP-REVIEW-2026-09-05.
describe('heuristic-findings: downgradeIfHeuristic', () => {
  it('downgrades a HIGH finding from a config-oriented scanner to INFO with a heuristic flag', () => {
    const finding = { id: 'env-var-scope-leak', severity: 'HIGH', description: 'template literal found' };
    const result = downgradeIfHeuristic(finding, 'env-leak-scanner');
    expect(result.severity).toBe('INFO');
    expect(result.heuristic).toBe(true);
    expect(result.originalSeverity).toBe('HIGH');
    // original finding fields survive untouched
    expect(result.id).toBe('env-var-scope-leak');
    expect(result.description).toBe('template literal found');
  });

  it('downgrades a MEDIUM finding from tool-poisoning-scanner (tool-name-shadow false positives)', () => {
    const finding = { id: 'tool-name-shadow', severity: 'MEDIUM', description: 'the word "run" appears' };
    const result = downgradeIfHeuristic(finding, 'tool-poisoning-scanner');
    expect(result.severity).toBe('INFO');
    expect(result.heuristic).toBe(true);
  });

  it('leaves findings from scanners outside the heuristic set untouched', () => {
    const finding = { id: 'exposed-secret', severity: 'CRITICAL', description: 'real looking secret' };
    const result = downgradeIfHeuristic(finding, 'secret-scanner');
    expect(result).toEqual(finding);
    expect(result.heuristic).toBeUndefined();
  });

  it('does not add a heuristic flag to a finding that is already INFO', () => {
    const finding = { id: 'network-egress-unknown', severity: 'INFO', description: 'already info' };
    const result = downgradeIfHeuristic(finding, 'network-egress-scanner');
    expect(result).toEqual(finding);
    expect(result.heuristic).toBeUndefined();
  });

  it('covers exactly the six config-oriented scanners named in FP-REVIEW-2026-09-05', () => {
    expect([...HEURISTIC_SOURCE_SCANNERS].sort()).toEqual([
      'data-flow-scanner',
      'env-leak-scanner',
      'network-egress-scanner',
      'prompt-injection-scanner',
      'tool-poisoning-scanner',
      'transport-scanner',
    ]);
  });
});
