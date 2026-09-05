import { describe, it, expect, vi, afterEach } from 'vitest';

vi.mock('../../src/utils/dashboard-ui.js', () => {
  throw new Error("Cannot find package 'blessed'");
});

describe('runDashboard', () => {
  afterEach(() => {
    process.exitCode = undefined;
    vi.restoreAllMocks();
  });

  it('prints an install hint and exits 1 when blessed is not installed', async () => {
    const { runDashboard } = await import('../../src/commands/dashboard.js');
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await runDashboard();

    expect(errSpy).toHaveBeenCalledWith(expect.stringContaining('npm i -g blessed blessed-contrib'));
    expect(process.exitCode).toBe(1);
  });
});
