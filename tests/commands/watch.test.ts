import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import path from 'path';
import fs from 'fs';
import os from 'os';

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

const CONFIG = path.join(os.tmpdir(), 'mcp-scan-watch-test', 'config.json');
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
  let onKeyDirChange: ((event: string, file: string) => void) | undefined;
  let home: string;
  const unhandled: unknown[] = [];
  const onUnhandled = (e: unknown) => { unhandled.push(e); };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    unhandled.length = 0;
    process.on('unhandledRejection', onUnhandled);
    process.exitCode = undefined;
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-watch-home-'));
    vi.stubEnv('MCP_SCAN_HOME', home);
    onKeyDirChange = undefined;
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    vi.spyOn(fs, 'watch').mockImplementation(((dir: string, cb: (e: string, f: string) => void) => {
      // watch also registers the policy file dirs; only the config's dir matters here
      if (dir === path.dirname(CONFIG)) onChange = cb;
      if (dir === home) onKeyDirChange = cb;
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
    vi.unstubAllEnvs();
    fs.rmSync(home, { recursive: true, force: true });
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

  it('says the scan was skipped and what rescans it', async () => {
    runScanMock.mockResolvedValueOnce(emptyReport);
    await runWatch();
    runScanMock.mockRejectedValueOnce(new BaselineKeyError('baseline key /k is a directory, move it'));

    await rescan();

    expect(logger.log).toHaveBeenCalledWith(expect.stringContaining('Scan skipped. Fixing baseline.key rescans.'));
  });

  it('rescans when baseline.key changes and clears the failure', async () => {
    runScanMock.mockRejectedValueOnce(new BaselineKeyError('baseline key /k is a directory, move it'));
    await runWatch();
    expect(process.exitCode).toBe(1);
    expect(onKeyDirChange).toBeDefined();

    runScanMock.mockResolvedValueOnce(emptyReport);
    // the user fixes the key: it now exists, unlike when the failing scan ended
    fs.writeFileSync(path.join(home, 'baseline.key'), 'k');
    onKeyDirChange!('rename', 'baseline.key');
    await vi.advanceTimersByTimeAsync(600);

    expect(runScanMock).toHaveBeenCalledTimes(2);
    expect(process.exitCode).toBeUndefined();
  });

  it('ignores other files in the audit dir', async () => {
    runScanMock.mockResolvedValueOnce(emptyReport);
    await runWatch();
    onKeyDirChange!('change', 'audit.log');
    await vi.advanceTimersByTimeAsync(600);
    expect(runScanMock).toHaveBeenCalledTimes(1);
  });

  it('does not watch a missing audit dir and does not report it as a failure', async () => {
    const missing = path.join(home, 'nope');
    vi.stubEnv('MCP_SCAN_HOME', missing);
    runScanMock.mockResolvedValueOnce(emptyReport);
    await runWatch();

    expect(vi.mocked(fs.watch).mock.calls.map(c => c[0])).not.toContain(missing);
    expect(logger.error).not.toHaveBeenCalledWith(expect.stringContaining('Failed to watch'));
  });

  it('watches the config dir once when it is also the audit dir, and rescans on a key event', async () => {
    const shared = path.dirname(CONFIG);
    fs.mkdirSync(shared, { recursive: true });
    vi.stubEnv('MCP_SCAN_HOME', shared);
    runScanMock.mockResolvedValueOnce(emptyReport);
    await runWatch();
    expect(vi.mocked(fs.watch).mock.calls.filter(c => c[0] === shared)).toHaveLength(1);

    runScanMock.mockResolvedValueOnce(emptyReport);
    fs.writeFileSync(path.join(shared, 'baseline.key'), 'k');
    try {
      onChange('rename', 'baseline.key');
      await vi.advanceTimersByTimeAsync(600);
      expect(runScanMock).toHaveBeenCalledTimes(2);
    } finally {
      fs.rmSync(shared, { recursive: true, force: true });
    }
  });

  it('does not rescan for a baseline.key change its own scan made', async () => {
    runScanMock.mockResolvedValueOnce(emptyReport);
    await runWatch();

    // the rescan creates the key and the watcher event arrives after it ends
    runScanMock.mockImplementationOnce(async () => {
      fs.writeFileSync(path.join(home, 'baseline.key'), 'k');
      return emptyReport;
    });
    await rescan();
    expect(runScanMock).toHaveBeenCalledTimes(2);
    onKeyDirChange!('rename', 'baseline.key');
    await vi.advanceTimersByTimeAsync(600);
    expect(runScanMock).toHaveBeenCalledTimes(2);

    // and one that lands while the scan is still running
    runScanMock.mockImplementationOnce(async () => {
      fs.rmSync(path.join(home, 'baseline.key'), { force: true });
      onKeyDirChange!('rename', 'baseline.key');
      return emptyReport;
    });
    await rescan();
    await vi.advanceTimersByTimeAsync(600);
    expect(runScanMock).toHaveBeenCalledTimes(3);
  });
});
