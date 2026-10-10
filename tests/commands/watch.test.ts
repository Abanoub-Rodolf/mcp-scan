import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import path from 'path';
import fs from 'fs';

const runScanMock = vi.fn();
vi.mock('../../src/commands/scan.js', () => ({
  runScan: (...args: unknown[]) => runScanMock(...args),
}));

vi.mock('../../src/utils/logger.js', () => {
  const noop = vi.fn();
  return {
    logger: {
      brand: noop, info: noop, detail: noop, warn: noop, pass: noop, high: noop,
      log: noop, divider: noop, emptyLine: noop, error: vi.fn(),
    },
  };
});

const CONFIG = path.resolve('/tmp/mcp-scan-watch-test/config.json');
vi.mock('../../src/config/detector.js', () => ({
  detectTools: async () => [{ name: 'x', configPath: CONFIG, exists: true }],
}));

import { runWatch } from '../../src/commands/watch.js';
import { BaselineKeyError } from '../../src/utils/audit-logger.js';
import { logger } from '../../src/utils/logger.js';

const emptyReport = {
  results: [], totalScanned: 0, criticalCount: 0, highCount: 0, mediumCount: 0,
  lowCount: 0, infoCount: 0, totalDurationMs: 1,
};

describe('watch mode and an unusable baseline key', () => {
  let onChange: (event: string, file: string) => void;
  const unhandled: unknown[] = [];
  const onUnhandled = (e: unknown) => { unhandled.push(e); };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    unhandled.length = 0;
    process.on('unhandledRejection', onUnhandled);
    process.exitCode = undefined;
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    vi.spyOn(fs, 'watch').mockImplementation(((dir: string, cb: (e: string, f: string) => void) => {
      // watch also registers the policy file dirs; only the config's dir matters here
      if (dir === path.dirname(CONFIG)) onChange = cb;
      return {} as fs.FSWatcher;
    }) as unknown as typeof fs.watch);
  });

  afterEach(() => {
    process.off('unhandledRejection', onUnhandled);
    process.removeAllListeners('SIGINT');
    process.removeAllListeners('SIGTERM');
    process.exitCode = undefined;
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  const rescan = async () => {
    onChange('change', path.basename(CONFIG));
    await vi.advanceTimersByTimeAsync(600);
    // let a rejection reach the unhandledRejection hook
    await vi.advanceTimersByTimeAsync(0);
    await new Promise<void>(r => setImmediate(r));
  };

  it('logs one clear line, keeps watching and fails the exit code, with no unhandled rejection', async () => {
    runScanMock.mockResolvedValueOnce(emptyReport);
    await runWatch();
    runScanMock.mockRejectedValueOnce(new BaselineKeyError('baseline key /k is a directory, move it'));

    await rescan();

    expect(unhandled).toEqual([]);
    expect(logger.error).toHaveBeenCalledTimes(1);
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('baseline key /k is a directory'));
    expect(process.exitCode).toBe(1);

    // still watching: a later good rescan runs and clears the failure
    runScanMock.mockResolvedValueOnce(emptyReport);
    await rescan();
    expect(runScanMock).toHaveBeenCalledTimes(3);
    // undefined is exit 0; watch clears the code after any good scan
    expect(process.exitCode).toBeUndefined();
  });
});
