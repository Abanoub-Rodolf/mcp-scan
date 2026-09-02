import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

function fakeStream(isTTY: boolean) {
  const writes: string[] = [];
  return {
    stream: { isTTY, write: (s: string) => { writes.push(s); return true; } } as unknown as NodeJS.WriteStream,
    writes,
  };
}

// repoHint keeps a module-level "shown this process" flag so a read-only
// home (marker write fails) doesn't reprint on every findings scan. Reset
// the module between tests so that flag doesn't leak across cases.
async function freshRepoHint() {
  vi.resetModules();
  const mod = await import('../src/utils/repo-hint.js');
  return mod.repoHint;
}

describe('repoHint', () => {
  let tmpHome: string;

  beforeEach(() => {
    // Marker lives under MCP_SCAN_HOME (auditDir()); redirect it to a temp
    // dir per test so the real ~/.mcp-scan is never touched.
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-repo-hint-'));
    process.env.MCP_SCAN_HOME = tmpHome;
  });

  afterEach(() => {
    delete process.env.MCP_SCAN_HOME;
    delete process.env.MCP_SCAN_NO_HINTS;
    // Restore permissions before recursive removal in case a test locked the dir down.
    fs.chmodSync(tmpHome, 0o700);
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it('writes exactly one line containing the repo URL on first call with findings', async () => {
    const repoHint = await freshRepoHint();
    const { stream, writes } = fakeStream(true);
    repoHint(true, stream);
    expect(writes).toHaveLength(1);
    expect(writes[0]).toContain('github.com/Abanoub-Rodolf/mcp-scan');
  });

  it('writes nothing on a second call once the marker exists', async () => {
    const repoHint = await freshRepoHint();
    const { stream: first } = fakeStream(true);
    repoHint(true, first);

    const { stream: second, writes: secondWrites } = fakeStream(true);
    repoHint(true, second);
    expect(secondWrites).toHaveLength(0);
  });

  it('stays silent when the stream is not a TTY, and never claims the marker', async () => {
    const repoHint = await freshRepoHint();
    const { stream, writes } = fakeStream(false);
    repoHint(true, stream);
    expect(writes).toHaveLength(0);

    const markerPath = path.join(tmpHome, 'repo-hint-shown');
    expect(fs.existsSync(markerPath)).toBe(false);
  });

  it('respects MCP_SCAN_NO_HINTS', async () => {
    const repoHint = await freshRepoHint();
    process.env.MCP_SCAN_NO_HINTS = '1';
    const { stream, writes } = fakeStream(true);
    repoHint(true, stream);
    expect(writes).toHaveLength(0);
  });

  it('stays silent when there are no findings', async () => {
    const repoHint = await freshRepoHint();
    const { stream, writes } = fakeStream(true);
    repoHint(false, stream);
    expect(writes).toHaveLength(0);
  });

  it('swallows a read-only home without throwing and without printing twice in one process', async () => {
    const repoHint = await freshRepoHint();
    // Lock the marker directory down so mkdirSync/writeFileSync inside
    // repoHint hit EACCES, simulating a read-only $HOME.
    fs.chmodSync(tmpHome, 0o500);

    const { stream: first, writes: firstWrites } = fakeStream(true);
    expect(() => repoHint(true, first)).not.toThrow();
    expect(firstWrites).toHaveLength(1);

    // Marker write failed, but the module-level flag still caps it at
    // once per process: a second qualifying call in the same process
    // must not print again.
    const { stream: second, writes: secondWrites } = fakeStream(true);
    expect(() => repoHint(true, second)).not.toThrow();
    expect(secondWrites).toHaveLength(0);
  });
});
