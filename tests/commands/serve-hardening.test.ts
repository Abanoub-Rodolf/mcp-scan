import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI_PATH = path.resolve(process.env.MCP_SCAN_CLI || './dist/index.js');

// None of these match a vendor pattern in secret-patterns.ts: the point is
// that redaction is structural, not a list of known token formats.
const OPAQUE_ARG = 'Kq8ZmN2xV7bL4rT9wY3cH6dF1gJ5pS0aXeUiOvB8nCzMa2Wd7Rt'; // 51 chars
const B64_URL = 'Zm9vYmFyQmF6UXV4MTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1O'; // 48 chars
const B64_ENV = 'bXlzZWNyZXRWYWx1ZTAxMjM0NTY3ODlhYmNkZWZnaGlqa2xtbm8'; // opaque env value
const BEARER = 'opaqueBearer7Xk29LmQ4vTzR81nHdY0cWpE';
const QS_SECRET = 'qsSecretValue93KdLm2PxWv81NzRt5Hy';
const HEADER_SECRET = 'hdrSecretValue64QwErTy09UiOpAsDf12';
const ALL_SECRETS = [OPAQUE_ARG, B64_URL, B64_ENV, BEARER, QS_SECRET, HEADER_SECRET];

type Msg = { id?: number; result?: any; error?: any };

// Talks to the real stdio server and hands back everything it printed.
async function rpc(calls: { name: string; arguments: object }[], opts: { cwd?: string; env?: Record<string, string> } = {}) {
  const child = spawn(process.execPath, [CLI_PATH, 'serve'], {
    cwd: opts.cwd,
    env: { ...process.env, MCP_SCAN_NO_HINTS: '1', ...opts.env },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (d) => { stdout += d.toString(); });
  child.stderr.on('data', (d) => { stderr += d.toString(); });
  const send = (m: object) => child.stdin.write(JSON.stringify(m) + '\n');
  send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'h', version: '1' } } });
  send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  calls.forEach((c, i) => send({ jsonrpc: '2.0', id: i + 2, method: 'tools/call', params: c }));
  const last = calls.length + 1;
  const deadline = Date.now() + 25000;
  const done = new RegExp(`"id":${last}\\b`);
  while (Date.now() < deadline && !done.test(stdout)) await new Promise(r => setTimeout(r, 50));
  child.stdin.end();
  await new Promise(r => child.on('close', r));
  const msgs: Msg[] = stdout.split('\n').filter(Boolean).map(l => JSON.parse(l));
  const results = calls.map((_, i) => msgs.find(m => m.id === i + 2)?.result);
  return { results, stdout, stderr };
}

const scan = (config_path: string, extra: object = {}) => ({ name: 'scan_configs', arguments: { config_path, ...extra } });

describe('mcp-scan serve hardening', () => {
  let tmp: string;
  beforeAll(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-hard-')); });
  afterAll(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  it('leaks no opaque credential on stdout or stderr', async () => {
    const config = path.join(tmp, 'leaky.json');
    fs.writeFileSync(config, JSON.stringify({
      mcpServers: {
        argtoken: { command: 'npx', args: ['-y', 'some-server', OPAQUE_ARG] },
        urlarg: { command: 'npx', args: ['-y', 'other-server', `--url=https://api.example-svc.io/mcp?token=${B64_URL}`] },
        envurl: { command: 'npx', args: ['-y', 'env-server'], env: { WEBHOOK: `https://hooks.example-svc.io/v1?token=${B64_URL}`, OPAQUE: B64_ENV } },
        bearer: { command: 'npx', args: ['-y', 'hdr-server', `--header=Authorization: Bearer ${BEARER}`] },
        qs: { url: `http://tools.example-svc.io/sse?apiKey=${QS_SECRET}` },
        hdr: { url: 'https://x.example-svc.io/mcp', headers: { 'X-Api-Key': HEADER_SECRET } },
      },
    }));
    const { results, stdout, stderr } = await rpc([scan(config), scan(config, { severity: 'critical' })]);
    expect(results[0].isError).toBeFalsy();
    expect(results[0].structuredContent.results.length).toBeGreaterThan(0);
    for (const secret of ALL_SECRETS) {
      expect(stdout, `stdout contains ${secret.slice(0, 8)}...`).not.toContain(secret);
      expect(stderr, `stderr contains ${secret.slice(0, 8)}...`).not.toContain(secret);
      // Partial echoes (a cut or re-encoded value) would still be a leak.
      expect(stdout).not.toContain(secret.slice(0, 16));
    }
  });

  it('returns a tool error for a directory, a missing file, an oversized file and a non-JSON file', async () => {
    const dir = path.join(tmp, 'adir');
    fs.mkdirSync(dir);
    const big = path.join(tmp, 'big.json');
    fs.writeFileSync(big, '{"mcpServers":{}}' + ' '.repeat(9 * 1024 * 1024));
    const junk = path.join(tmp, 'junk.json');
    fs.writeFileSync(junk, 'this is not json {{{');
    const { results } = await rpc([scan(dir), scan(path.join(tmp, 'missing.json')), scan(big), scan(junk), scan('x'.repeat(5000))]);
    expect(results[0].isError).toBe(true);
    expect(results[1].isError).toBe(true);
    expect(results[2].isError).toBe(true);
    expect(results[3].isError).toBe(true);
    // Over the schema limit: rejected before the handler runs.
    expect(results[4].isError).toBe(true);
  });

  it('follows a symlink to a regular file', async () => {
    const real = path.join(tmp, 'real.json');
    fs.writeFileSync(real, JSON.stringify({ mcpServers: { a: { command: 'npx', args: ['-y', 'left-pad'] } } }));
    const link = path.join(tmp, 'link.json');
    fs.symlinkSync(real, link);
    const { results } = await rpc([scan(link)]);
    expect(results[0].isError).toBeFalsy();
    expect(results[0].structuredContent.summary.serversScanned).toBe(1);
  });

  it('skips a null server entry instead of aborting', async () => {
    const config = path.join(tmp, 'null-entry.json');
    fs.writeFileSync(config, JSON.stringify({ mcpServers: { broken: null, ok: { command: 'npx', args: ['-y', 'left-pad'] } } }));
    const { results } = await rpc([scan(config)]);
    expect(results[0].isError).toBeFalsy();
    expect(results[0].structuredContent.summary.serversScanned).toBe(1);
  });

  it('does not read .env files above the scanned config', async () => {
    const parent = path.join(tmp, 'envparent');
    const child = path.join(parent, 'sub');
    fs.mkdirSync(child, { recursive: true });
    fs.writeFileSync(path.join(parent, '.env'), 'STRIPE_API_KEY=realLookingValueWithManyChars12345\n');
    const config = path.join(child, 'mcp.json');
    fs.writeFileSync(config, JSON.stringify({ mcpServers: { a: { command: 'npx', args: ['-y', 'left-pad'] } } }));
    const { results, stdout } = await rpc([scan(config)]);
    const ids = results[0].structuredContent.results.flatMap((r: any) => r.findings.map((f: any) => f.id));
    expect(ids).not.toContain('env-secret-exposed');
    expect(stdout).not.toContain('STRIPE_API_KEY');
  });

  it('reports findings hidden by cwd policy and ignore files', async () => {
    const proj = path.join(tmp, 'proj');
    fs.mkdirSync(proj);
    fs.writeFileSync(path.join(proj, '.mcp-scan.json'), JSON.stringify({ suppressRules: ['exposed-secret'] }));
    fs.writeFileSync(path.join(proj, '.mcp-scan-ignore'), 'some-other-id\n');
    const config = path.join(proj, 'mcp.json');
    fs.writeFileSync(config, JSON.stringify({ mcpServers: { gh: { command: 'npx', args: ['-y', 'x-server'], env: { GITHUB_TOKEN: 'ghp_Zq8LmN2xV7bK4rT9wY3cH6dF1gJ5pS0aXeUi' } } } }));
    const { results } = await rpc([scan(config)], { cwd: proj });
    const out = results[0].structuredContent;
    expect(out.suppression.suppressed).toBeGreaterThanOrEqual(1);
    expect(out.suppression.sources).toEqual(expect.arrayContaining(['.mcp-scan.json', '.mcp-scan-ignore']));
    expect(out.suppression.sources.every((s: string) => !s.includes('/'))).toBe(true);
  });

  it('caps results and reports the truncated count', async () => {
    const servers: Record<string, object> = {};
    for (let i = 0; i < 260; i++) servers[`s${i}`] = { command: 'npx', args: ['-y', `pkg-${i}`], env: { GITHUB_TOKEN: `ghp_Zq8LmN2xV7bK4rT9wY3cH6dF1gJ5pS0a${String(i).padStart(4, '0')}` } };
    const config = path.join(tmp, 'many.json');
    fs.writeFileSync(config, JSON.stringify({ mcpServers: servers }));
    const { results } = await rpc([scan(config)]);
    const out = results[0].structuredContent;
    expect(out.results.length).toBeLessThanOrEqual(200);
    expect(out.truncated.results).toBeGreaterThanOrEqual(60);
    expect(out.truncated.findings).toBeGreaterThan(0);
  }, 60000);
});
