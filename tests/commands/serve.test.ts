import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

// Runs against the built artifact like ci.test.ts does: `npm run build` first.
const CLI_PATH = path.resolve(process.env.MCP_SCAN_CLI || './dist/index.js');
const TRAP_PATH = path.resolve('./tests/fixtures/net-trap.mjs');
const FAKE_KEY = 'ghp_Zq8LmN2xV7bK4rT9wY3cH6dF1gJ5pS0aXeUi';
const FAKE_ARG_KEY = 'sk_live_Qm7Lx2Vn9Rb4Tc8Wd3Hf6Jg1Ps5';

describe('mcp-scan serve', () => {
  let tmp: string;
  let configPath: string;
  let trapFile: string;
  let auditHome: string;
  let client: Client;
  let transport: StdioClientTransport;
  let stderr = '';

  beforeAll(async () => {
    expect(fs.existsSync(CLI_PATH), 'run `npm run build` before the tests').toBe(true);
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-serve-'));
    auditHome = path.join(tmp, 'home');
    trapFile = path.join(tmp, 'net.log');
    fs.writeFileSync(trapFile, '');
    configPath = path.join(tmp, 'mcp.json');
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: {
        github: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-github', `--token=${FAKE_ARG_KEY}`],
          env: { GITHUB_PERSONAL_ACCESS_TOKEN: FAKE_KEY },
        },
      },
    }));

    transport = new StdioClientTransport({
      command: process.execPath,
      args: ['--import', TRAP_PATH, CLI_PATH, 'serve'],
      env: { ...process.env, NET_TRAP_FILE: trapFile, MCP_SCAN_HOME: auditHome, MCP_SCAN_NO_HINTS: '1' },
      stderr: 'pipe',
    });
    transport.stderr?.on('data', (d) => { stderr += d.toString(); });
    client = new Client({ name: 'serve-test', version: '1.0.0' });
    await client.connect(transport);
  });

  afterAll(async () => {
    await client?.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it('answers initialize with the package name and version', () => {
    const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
    expect(client.getServerVersion()).toMatchObject({ name: 'mcp-scan', version: pkg.version });
  });

  it('lists exactly the three read-only tools', async () => {
    const { tools } = await client.listTools();
    expect(tools.map(t => t.name).sort()).toEqual(['list_detected_clients', 'list_scanners', 'scan_configs']);
    for (const tool of tools) {
      expect(tool.annotations?.readOnlyHint).toBe(true);
      expect(tool.annotations?.openWorldHint).toBe(false);
    }
  });

  it('list_scanners returns the scanner table', async () => {
    const res = await client.callTool({ name: 'list_scanners', arguments: {} });
    const { scanners } = res.structuredContent as { scanners: { name: string }[] };
    expect(scanners.map(s => s.name)).toContain('secret-scanner');
  });

  it('list_detected_clients returns paths with an exists flag', async () => {
    const res = await client.callTool({ name: 'list_detected_clients', arguments: {} });
    const { clients } = res.structuredContent as { clients: { name: string; configPath: string; exists: boolean }[] };
    expect(clients.length).toBeGreaterThan(0);
    expect(typeof clients[0].exists).toBe('boolean');
  });

  it('scan_configs finds the exposed secret without echoing it', async () => {
    const res = await client.callTool({ name: 'scan_configs', arguments: { config_path: configPath } });
    expect(res.isError).toBeFalsy();
    const out = res.structuredContent as { summary: { critical: number; offline: boolean }; results: { findings: { id: string }[] }[] };
    expect(out.summary.offline).toBe(true);
    expect(out.results[0].findings.some(f => f.id === 'exposed-secret')).toBe(true);

    const everything = JSON.stringify(res);
    expect(everything).not.toContain(FAKE_KEY);
    expect(everything).not.toContain(FAKE_ARG_KEY);
    expect(everything).not.toContain('Zq8LmN2xV7');
  });

  it('scan_configs honours the severity filter', async () => {
    const res = await client.callTool({ name: 'scan_configs', arguments: { config_path: configPath, severity: 'critical' } });
    const out = res.structuredContent as { results: { findings: { severity: string }[] }[] };
    for (const r of out.results) for (const f of r.findings) expect(f.severity).toBe('CRITICAL');
  });

  it('scan_configs reports a missing config as a tool error', async () => {
    const res = await client.callTool({ name: 'scan_configs', arguments: { config_path: path.join(tmp, 'nope.json') } });
    expect(res.isError).toBe(true);
  });

  it('never touched the network or the audit log', () => {
    expect(fs.readFileSync(trapFile, 'utf8')).toBe('');
    expect(fs.existsSync(auditHome)).toBe(false);
    expect(stderr).not.toContain(FAKE_KEY);
  });
});

describe('mcp-scan serve stdout', () => {
  it('writes only JSON-RPC frames to stdout', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-serve-raw-'));
    const config = path.join(tmp, 'mcp.json');
    fs.writeFileSync(config, JSON.stringify({ mcpServers: { s: { command: 'npx', args: ['-y', 'left-pad'] } } }));
    const child = spawn(process.execPath, [CLI_PATH, 'serve'], {
      env: { ...process.env, MCP_SCAN_HOME: path.join(tmp, 'home') },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    child.stdout.on('data', (d) => { stdout += d.toString(); });

    const send = (m: object) => child.stdin.write(JSON.stringify(m) + '\n');
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'raw', version: '1' } } });
    send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'scan_configs', arguments: { config_path: config } } });
    send({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'list_detected_clients', arguments: {} } });

    const deadline = Date.now() + 25000;
    while (Date.now() < deadline && !/"id":4\b/.test(stdout)) await new Promise(r => setTimeout(r, 100));
    child.stdin.end();
    await new Promise(r => child.on('close', r));
    fs.rmSync(tmp, { recursive: true, force: true });

    const lines = stdout.split('\n').filter(Boolean);
    expect(lines.length).toBeGreaterThanOrEqual(4);
    for (const line of lines) {
      const msg = JSON.parse(line);
      expect(msg.jsonrpc).toBe('2.0');
    }
  }, 40000);
});
