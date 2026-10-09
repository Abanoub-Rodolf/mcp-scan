import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runProxy } from '../../src/commands/proxy.js';
import { loadPolicy } from '../../src/config/parser.js';
import { maskPii } from '../../src/utils/privacy-engine.js';
import { spawn } from 'child_process';
import { PassThrough } from 'stream';
import fs from 'fs';
import os from 'os';
import path from 'path';

vi.mock('../../src/config/parser.js', async () => {
  const actual = await vi.importActual('../../src/config/parser.js') as any;
  return { ...actual, loadPolicy: vi.fn() };
});

vi.mock('../../src/utils/privacy-engine.js', async () => {
  const actual = await vi.importActual('../../src/utils/privacy-engine.js') as any;
  return { ...actual, maskPii: vi.fn(actual.maskPii) };
});

vi.mock('child_process', () => ({ spawn: vi.fn() }));

vi.mock('../../src/utils/logger.js', () => ({
  logger: { brand: vi.fn(), info: vi.fn(), detail: vi.fn(), error: vi.fn(), warn: vi.fn() },
}));

describe('proxy log hardening', () => {
  let root: string;
  let logDir: string;
  let childStdin: PassThrough;

  beforeEach(async () => {
    vi.clearAllMocks();
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-proxy-hardening-'));
    // Not created yet, so the test sees the modes runProxy gives new dirs.
    logDir = path.join(root, 'fresh', 'logs');
    process.env.MCP_SCAN_LOG_DIR = logDir;
    process.env.MCP_SCAN_NO_EXIT = '1';
    childStdin = new PassThrough();
    vi.mocked(spawn).mockReturnValue({
      stdin: childStdin,
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      on: vi.fn(),
      kill: vi.fn(),
    } as any);
  });

  afterEach(() => {
    process.stdin.unpipe();
    delete process.env.MCP_SCAN_LOG_DIR;
    delete process.env.MCP_SCAN_NO_EXIT;
    fs.rmSync(root, { recursive: true, force: true });
  });

  const send = async (line: string) => {
    process.stdin.emit('data', Buffer.from(line + '\n'));
    await new Promise(r => setTimeout(r, 50));
  };
  const readLog = () => {
    const files = fs.readdirSync(logDir);
    expect(files.length).toBe(1);
    return { file: path.join(logDir, files[0]), text: fs.readFileSync(path.join(logDir, files[0]), 'utf8') };
  };

  it('creates the log file 0600 and the log dir 0700', async () => {
    vi.mocked(loadPolicy).mockReturnValue({});
    await runProxy({ command: 'node', args: '-v' });
    await send(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call' }));

    const { file } = readLog();
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    expect(fs.statSync(logDir).mode & 0o777).toBe(0o700);
  });

  it('never writes an unparseable line to the log, but still forwards it', async () => {
    vi.mocked(loadPolicy).mockReturnValue({});
    let forwarded = '';
    childStdin.on('data', c => { forwarded += c.toString(); });
    await runProxy({ command: 'node', args: '-v' });
    await send('token=sk-live-not-json-0123456789');

    expect(readLog().text).not.toContain('sk-live-not-json-0123456789');
    expect(forwarded).toContain('sk-live-not-json-0123456789');
  });

  it('drops and does not log a message when masking throws', async () => {
    vi.mocked(loadPolicy).mockReturnValue({ privacy: { maskPii: true } });
    vi.mocked(maskPii).mockImplementation(() => { throw new Error('mask boom'); });
    let forwarded = '';
    childStdin.on('data', c => { forwarded += c.toString(); });
    await runProxy({ command: 'node', args: '-v' });
    await send(JSON.stringify({ params: { email: 'secret@corp.example' } }));

    expect(readLog().text).not.toContain('secret@corp.example');
    expect(forwarded).not.toContain('secret@corp.example');
  });
});
