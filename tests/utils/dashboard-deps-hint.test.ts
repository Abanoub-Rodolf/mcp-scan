import { describe, it, expect, vi, afterEach } from 'vitest';
import { reportBlessedImportError } from '../../src/utils/dashboard-deps-hint.js';

describe('reportBlessedImportError', () => {
  afterEach(() => {
    process.exitCode = undefined;
    vi.restoreAllMocks();
  });

  it('shows the install hint for a real missing blessed (CJS)', () => {
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const err = Object.assign(new Error("Cannot find module 'blessed'"), { code: 'MODULE_NOT_FOUND' });

    reportBlessedImportError(err);

    expect(errSpy).toHaveBeenCalledWith(expect.stringContaining('npm i -g mcp-scan'));
    expect(process.exitCode).toBe(1);
  });

  it('shows the install hint for a real missing blessed-contrib (ESM)', () => {
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const err = Object.assign(
      new Error("Cannot find package 'blessed-contrib' imported from /app/dist/dashboard-ui.js"),
      { code: 'ERR_MODULE_NOT_FOUND' }
    );

    reportBlessedImportError(err);

    expect(errSpy).toHaveBeenCalledWith(expect.stringContaining('npm i -g mcp-scan'));
    expect(process.exitCode).toBe(1);
  });

  // Near-miss: a real, different package whose name merely starts with
  // "blessed" must not be mistaken for the optional dashboard dep.
  it('does not show the hint for a differently-named package (near-miss)', () => {
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const err = Object.assign(
      new Error("Cannot find package 'blessed-something-else' imported from /app/dist/dashboard-ui.js"),
      { code: 'ERR_MODULE_NOT_FOUND' }
    );

    reportBlessedImportError(err);

    expect(errSpy).toHaveBeenCalledWith("Cannot find package 'blessed-something-else' imported from /app/dist/dashboard-ui.js");
    expect(errSpy).not.toHaveBeenCalledWith(expect.stringContaining('npm i -g mcp-scan'));
    expect(process.exitCode).toBe(1);
  });

  it('shows the real message for an unrelated error', () => {
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const err = new Error('unexpected token in dashboard-ui.js');

    reportBlessedImportError(err);

    expect(errSpy).toHaveBeenCalledWith('unexpected token in dashboard-ui.js');
    expect(process.exitCode).toBe(1);
  });
});
