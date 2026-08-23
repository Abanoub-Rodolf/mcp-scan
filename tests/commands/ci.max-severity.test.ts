import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../../src/commands/scan.js', () => ({ runScan: vi.fn() }));

import { runCi } from '../../src/commands/ci.js';
import { runScan } from '../../src/commands/scan.js';
import { ScanReport } from '../../src/types/scan-result.js';

const base: ScanReport = {
  results: [], totalScanned: 0, criticalCount: 0, highCount: 0,
  mediumCount: 0, lowCount: 0, infoCount: 0, totalDurationMs: 0,
};

function report(counts: Partial<ScanReport>): ScanReport {
  return { ...base, ...counts };
}

describe('runCi --max-severity covers LOW and INFO', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.exitCode = undefined;
  });

  it('fails when only LOW findings exist and threshold is low', async () => {
    vi.mocked(runScan).mockResolvedValue(report({ lowCount: 1 }));
    await runCi({ maxSeverity: 'low' });
    expect(process.exitCode).toBe(1);
  });

  it('fails when only INFO findings exist and threshold is info', async () => {
    vi.mocked(runScan).mockResolvedValue(report({ infoCount: 1 }));
    await runCi({ maxSeverity: 'info' });
    expect(process.exitCode).toBe(1);
  });

  it('passes when only MEDIUM findings exist and threshold is high', async () => {
    vi.mocked(runScan).mockResolvedValue(report({ mediumCount: 1 }));
    await runCi({ maxSeverity: 'high' });
    expect(process.exitCode).not.toBe(1);
  });

  it('still fails on CRITICAL findings even with low threshold', async () => {
    vi.mocked(runScan).mockResolvedValue(report({ criticalCount: 2 }));
    await runCi({ maxSeverity: 'low' });
    expect(process.exitCode).toBe(1);
  });

  it('forwards config, policy, and offline options into runScan', async () => {
    vi.mocked(runScan).mockResolvedValue(report({}));
    await runCi({ maxSeverity: 'high', config: '/tmp/cfg.json', policy: '/tmp/pol.yml', offline: true });
    expect(vi.mocked(runScan)).toHaveBeenCalledWith(expect.objectContaining({
      silent: true,
      ci: true,
      config: '/tmp/cfg.json',
      policy: '/tmp/pol.yml',
      offline: true,
    }));
  });
});
