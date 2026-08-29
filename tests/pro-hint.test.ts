import { describe, it, expect, afterEach } from 'vitest';
import { proHint } from '../src/utils/pro-hint.js';

function fakeStream(isTTY: boolean) {
  const writes: string[] = [];
  return {
    stream: { isTTY, write: (s: string) => { writes.push(s); return true; } } as unknown as NodeJS.WriteStream,
    writes,
  };
}

describe('proHint', () => {
  afterEach(() => { delete process.env.MCP_SCAN_NO_HINTS; });

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

  it('respects MCP_SCAN_NO_HINTS', () => {
    process.env.MCP_SCAN_NO_HINTS = '1';
    const { stream, writes } = fakeStream(true);
    proHint(stream);
    expect(writes).toHaveLength(0);
  });
});
