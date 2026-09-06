import { describe, it, expect } from 'vitest';
import { downgradeIfHeuristic, HEURISTIC_SOURCE_SCANNERS } from '../../scripts/heuristic-findings.mjs';

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
