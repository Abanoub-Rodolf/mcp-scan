import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import { PolicyError } from '../../src/utils/policy-file.js';

vi.mock('../../src/commands/scan.js', () => ({ runScan: vi.fn() }));
vi.mock('../../src/config/detector.js', () => ({
  detectTools: vi.fn(async () => [{ name: 't', configPath: '/cfg/mcp.json', exists: true }]),
}));

import { runScan } from '../../src/commands/scan.js';
import { runWatch } from '../../src/commands/watch.js';

const emptyReport = { results: [], totalScanned: 0, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, infoCount: 0, totalDurationMs: 0 };

// fs.watch can't run in every sandbox, so the watcher is captured and fired by hand.
describe('watch with a policy that breaks mid-session', () => {
  let watchers: Record<string, (ev: string, name: string) => void>;
  const onChange = (ev: string, name: string) => watchers['/cfg'](ev, name);
  const handlers: Record<string, () => void> = {};

  beforeEach(() => {
    vi.useFakeTimers();
    vi.mocked(runScan).mockReset();
    process.exitCode = undefined;
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
    watchers = {};
    vi.spyOn(fs, 'watch').mockImplementation(((d: string, cb: any) => { watchers[d] = cb; return { close() {}, on() {} }; }) as any);
    vi.spyOn(process, 'on').mockImplementation(((ev: string, fn: () => void) => { handlers[ev] = fn; return process; }) as any);
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    process.exitCode = undefined;
  });

  it('keeps the failing exit code through Ctrl+C and never reports all clear for the skipped scan', async () => {
    vi.mocked(runScan)
      .mockResolvedValueOnce(emptyReport as any)
      .mockRejectedValueOnce(new PolicyError('Invalid policy /x/.mcp-scan.json: broken'));
    const exit = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as any);

    await runWatch();
    onChange('change', 'mcp.json');
    await vi.advanceTimersByTimeAsync(600);

    expect(process.exitCode).toBe(1);
    expect(exit).not.toHaveBeenCalled();
    handlers.SIGINT();
    expect(exit).toHaveBeenCalledWith(1);
  });

  it('saving the fixed policy rescans and clears the failing exit code', async () => {
    vi.mocked(runScan)
      .mockResolvedValueOnce(emptyReport as any)
      .mockRejectedValueOnce(new PolicyError('Invalid policy: broken'))
      .mockResolvedValueOnce(emptyReport as any);
    const exit = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as any);

    await runWatch();
    onChange('change', 'mcp.json');
    await vi.advanceTimersByTimeAsync(600);
    expect(process.exitCode).toBe(1);

    watchers[process.cwd()]('change', '.mcp-scan.json');
    await vi.advanceTimersByTimeAsync(600);
    expect(runScan).toHaveBeenCalledTimes(3);
    expect(process.exitCode).toBeUndefined();
    handlers.SIGINT();
    expect(exit).toHaveBeenCalledWith(0);
  });

  it('Ctrl+C after a healthy session still exits 0', async () => {
    vi.mocked(runScan).mockResolvedValue(emptyReport as any);
    const exit = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as any);
    await runWatch();
    handlers.SIGINT();
    expect(exit).toHaveBeenCalledWith(0);
  });

  it('a policy that is broken at start exits 1 without watching', async () => {
    vi.mocked(runScan).mockRejectedValue(new PolicyError('Invalid policy: broken'));
    const exit = vi.spyOn(process, 'exit').mockImplementation((() => { throw new Error('exit'); }) as any);
    await expect(runWatch()).rejects.toThrow('exit');
    expect(exit).toHaveBeenCalledWith(1);
    expect(fs.watch).not.toHaveBeenCalled();
  });
});
