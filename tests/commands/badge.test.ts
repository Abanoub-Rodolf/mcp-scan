import { describe, it, expect, vi, afterEach } from 'vitest';
import { runBadge } from '../../src/commands/badge.js';

describe('runBadge', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    process.exitCode = undefined;
  });

  it('prints a markdown snippet and the report URL for a plain package', () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    runBadge('mcp-scan');

    const output = log.mock.calls.map(c => c.join(' ')).join('\n');
    expect(output).toContain('[![mcp-scan](https://thynkq.com/api/mcp-scan/badge/mcp-scan.svg)](https://thynkq.com/mcp-scan/check/mcp-scan)');
    expect(output).toContain('https://thynkq.com/mcp-scan/check/mcp-scan');
  });

  it('URL-encodes a scoped package name in both URLs', () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    runBadge('@modelcontextprotocol/server-filesystem');

    const output = log.mock.calls.map(c => c.join(' ')).join('\n');
    expect(output).toContain('https://thynkq.com/api/mcp-scan/badge/%40modelcontextprotocol%2Fserver-filesystem.svg');
    expect(output).toContain('https://thynkq.com/mcp-scan/check/%40modelcontextprotocol%2Fserver-filesystem');
  });

  it('outputs structured JSON with --json', () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    runBadge('mcp-scan', { json: true });

    expect(log).toHaveBeenCalledTimes(1);
    const parsed = JSON.parse(log.mock.calls[0][0]);
    expect(parsed).toEqual({
      package: 'mcp-scan',
      badgeUrl: 'https://thynkq.com/api/mcp-scan/badge/mcp-scan.svg',
      reportUrl: 'https://thynkq.com/mcp-scan/check/mcp-scan',
      markdown: '[![mcp-scan](https://thynkq.com/api/mcp-scan/badge/mcp-scan.svg)](https://thynkq.com/mcp-scan/check/mcp-scan)',
    });
  });

  it('rejects an invalid package name without printing a snippet', () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    runBadge('Not A Valid Name');

    expect(log).not.toHaveBeenCalled();
    expect(error).toHaveBeenCalled();
    expect(process.exitCode).toBe(1);
  });

  it('rejects an invalid package name in --json mode with structured JSON', () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    runBadge('/etc/passwd', { json: true });

    expect(log).not.toHaveBeenCalled();
    expect(error).toHaveBeenCalledTimes(1);
    const parsed = JSON.parse(error.mock.calls[0][0]);
    expect(parsed.package).toBe('/etc/passwd');
    expect(typeof parsed.error).toBe('string');
    expect(process.exitCode).toBe(1);
  });
});
