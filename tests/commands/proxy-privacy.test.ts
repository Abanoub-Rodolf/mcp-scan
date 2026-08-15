import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runProxy } from '../../src/commands/proxy.js';
import { loadPolicy } from '../../src/config/parser.js';
import { spawn } from 'child_process';
import { PassThrough } from 'stream';
import fs from 'fs';
import os from 'os';
import path from 'path';

vi.mock('../../src/config/parser.js', async () => {
    const actual = await vi.importActual('../../src/config/parser.js') as any;
    return {
        ...actual,
        loadPolicy: vi.fn(),
    };
});

vi.mock('child_process', () => ({
  spawn: vi.fn()
}));

vi.mock('../../src/utils/logger.js', () => ({
  logger: {
    brand: vi.fn(),
    info: vi.fn(),
    detail: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
  }
}));

describe('Proxy Privacy Engine', () => {
  let tmpLogDir: string;

  beforeEach(() => {
    vi.clearAllMocks();
    // Redirect proxy logs away from the real user home and prevent
    // runProxy from calling process.exit (which would kill the worker).
    tmpLogDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-proxy-test-'));
    process.env.MCP_SCAN_LOG_DIR = tmpLogDir;
    process.env.MCP_SCAN_NO_EXIT = '1';
  });

  afterEach(() => {
    delete process.env.MCP_SCAN_LOG_DIR;
    delete process.env.MCP_SCAN_NO_EXIT;
    fs.rmSync(tmpLogDir, { recursive: true, force: true });
  });

  it('should mask PII when enabled in policy', async () => {
    vi.mocked(loadPolicy).mockReturnValue({
      privacy: { maskPii: true }
    });

    const mockChildProcess = {
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      on: vi.fn(),
      kill: vi.fn()
    };
    
    vi.mocked(spawn).mockReturnValue(mockChildProcess as any);

    // We only need to check what gets written to child's stdin
    
    await runProxy({ command: 'node', args: '-v' });

    // Client -> Server direction
    const sensitivePayload = JSON.stringify({ method: 'test', params: { email: 'user@example.com' } }) + '\n';
    
    let capturedInput = '';
    mockChildProcess.stdin.on('data', (chunk) => {
        capturedInput += chunk.toString();
    });

    // Write to process.stdin simulation (interceptor wraps it)
    process.stdin.emit('data', Buffer.from(sensitivePayload));

    // Small delay to allow stream to flush
    await new Promise(r => setTimeout(r, 50));
    
    expect(capturedInput).toContain('[EMAIL_MASKED]');
    expect(capturedInput).not.toContain('user@example.com');
  });

  it('never writes the raw email to the proxy log when masking is on', async () => {
    vi.mocked(loadPolicy).mockReturnValue({
      privacy: { maskPii: true }
    });

    const mockChildProcess = {
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      on: vi.fn(),
      kill: vi.fn()
    };
    vi.mocked(spawn).mockReturnValue(mockChildProcess as any);

    await runProxy({ command: 'node', args: '-v' });

    process.stdin.emit('data', Buffer.from(JSON.stringify({ params: { email: 'secret@corp.example' } }) + '\n'));
    await new Promise(r => setTimeout(r, 50));

    const files = fs.readdirSync(tmpLogDir);
    expect(files.length).toBe(1);
    const logContent = fs.readFileSync(path.join(tmpLogDir, files[0]), 'utf8');
    expect(logContent).not.toContain('secret@corp.example');
    expect(logContent).toContain('[EMAIL_MASKED]');
  });

  it('keeps proxying even when the log directory is not writable', async () => {
    vi.mocked(loadPolicy).mockReturnValue({});
    vi.mocked(spawn).mockReturnValue({
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      on: vi.fn(),
      kill: vi.fn()
    } as any);

    // Point the log dir at a path that cannot be created (a file).
    const blocker = path.join(tmpLogDir, 'blocker');
    fs.writeFileSync(blocker, 'x');
    process.env.MCP_SCAN_LOG_DIR = path.join(blocker, 'nested');

    await expect(runProxy({ command: 'node', args: '-v' })).resolves.toBeUndefined();
  });
});
