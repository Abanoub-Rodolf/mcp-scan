import { describe, it, expect, vi, beforeEach } from 'vitest';
import { submitToUgig } from '../../src/commands/submit.js';

vi.mock('../../src/utils/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), detail: vi.fn(), log: vi.fn(), emptyLine: vi.fn(), brand: vi.fn(), isVerbose: false },
}));

const report = (url: string) => ({
  version: '2.2.0',
  results: [{ serverName: 's', toolName: 'T', findings: [], connection: { command: 'npx', args: ['mcp-remote', url] } }],
}) as any;

describe('submit URL schemes', () => {
  beforeEach(() => vi.clearAllMocks());
  it.each(['https://x.example.com/sse', 'HTTPS://x.example.com/SSE'])('%s is the server url', async (url) => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const { logger } = await import('../../src/utils/logger.js');
    await submitToUgig(report(url), { apiKey: 'k', dryRun: true });
    const out = (logger.log as any).mock.calls.flat().join('\n');
    log.mockRestore();
    expect(out).toContain('"transport_type": "sse"');
    expect(out).toContain(`"server_url": "${url}"`);
  });
});
