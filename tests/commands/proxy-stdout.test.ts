import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execa } from 'execa';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(__dirname, '../../dist/index.js');

// stdout is the MCP channel to the client: one stray "INFO:" line breaks it.
describe('proxy stdout', () => {
  let dir: string;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-proxy-stdout-')); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('carries only JSON-RPC, even when a warning fires, and logs go to stderr', async () => {
    // A log dir that cannot be created makes the proxy warn.
    fs.writeFileSync(path.join(dir, 'blocker'), 'x');
    const server = path.join(dir, 'server.js');
    fs.writeFileSync(server, `process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { ok: true } }) + '\\n');`);

    const { stdout, stderr, exitCode } = await execa('node', [CLI, 'proxy', '--command', 'node', '--args', server], {
      cwd: dir, reject: false, stdin: 'ignore', env: { MCP_SCAN_LOG_DIR: path.join(dir, 'blocker', 'logs') },
    });

    expect(exitCode).toBe(0);
    const lines = stdout.split('\n').filter(Boolean);
    expect(lines.length).toBeGreaterThan(0);
    for (const l of lines) expect(JSON.parse(l)).toMatchObject({ jsonrpc: '2.0' });
    expect(stderr).toMatch(/Proxy logging disabled/);
    expect(stderr).toMatch(/Proxying/);
  }, 30000);
});
