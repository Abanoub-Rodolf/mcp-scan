import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { proHint } from '../src/utils/pro-hint.js';

function fakeStream(isTTY: boolean) {
  const writes: string[] = [];
  return {
    stream: { isTTY, write: (s: string) => { writes.push(s); return true; } } as unknown as NodeJS.WriteStream,
    writes,
  };
}

describe('proHint', () => {
  let savedCi: string | undefined;
  beforeEach(() => {
    savedCi = process.env.CI;
    delete process.env.CI;
  });
  afterEach(() => {
    delete process.env.MCP_SCAN_NO_HINTS;
    if (savedCi === undefined) delete process.env.CI; else process.env.CI = savedCi;
  });

  it('writes one line to a TTY stream', () => {
    const { stream, writes } = fakeStream(true);
    proHint(stream);
    expect(writes).toHaveLength(1);
    expect(writes[0]).toContain('thynkq.com/products/mcp-scan');
  });

  it('stays silent when the stream is not a TTY (pipes, CI, json consumers)', () => {
    const { stream, writes } = fakeStream(false);
    proHint(stream);
    expect(writes).toHaveLength(0);
  });

  it('stays silent under CI even with a pseudo-TTY', () => {
    process.env.CI = 'true';
    const { stream, writes } = fakeStream(true);
    proHint(stream);
    expect(writes).toHaveLength(0);
  });

  it('respects MCP_SCAN_NO_HINTS', () => {
    process.env.MCP_SCAN_NO_HINTS = '1';
    const { stream, writes } = fakeStream(true);
    proHint(stream);
    expect(writes).toHaveLength(0);
  });
});
