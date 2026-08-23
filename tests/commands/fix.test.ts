import { describe, it, expect } from 'vitest';
import { applyAutoFix } from '../../src/commands/fix.js';
import { RawMcpServerEntry } from '../../src/types/config.js';
import { Finding } from '../../src/types/scan-result.js';

function finding(id: string): Finding {
  return { id, severity: 'HIGH', description: 'test', fixable: true };
}

describe('applyAutoFix', () => {
  it('replaces secret-valued env vars with a ${KEY} reference', () => {
    const server: RawMcpServerEntry = { command: 'npx', env: { API_KEY: 'sk_live_' + 'a1B2c3D4e5F6g7H8i9J0k1L2', PLAIN: 'hello' } };
    expect(applyAutoFix(finding('exposed-secret'), server)).toBe(true);
    expect(server.env!.API_KEY).toBe('${API_KEY}');
    expect(server.env!.PLAIN).toBe('hello');
  });

  it('upgrades http:// args for http-transport-no-auth', () => {
    const server: RawMcpServerEntry = { command: 'npx', args: ['--endpoint', 'http://api.example.com'] };
    expect(applyAutoFix(finding('http-transport-no-auth'), server)).toBe(true);
    expect(server.args).toEqual(['--endpoint', 'https://api.example.com']);
  });

  it('upgrades an http:// server url for http-transport-no-auth (previously unhandled)', () => {
    const server: RawMcpServerEntry = { command: 'node', url: 'http://api.example.com/mcp' };
    expect(applyAutoFix(finding('http-transport-no-auth'), server)).toBe(true);
    expect(server.url).toBe('https://api.example.com/mcp');
  });

  it('upgrades sse transport flag', () => {
    const server: RawMcpServerEntry = { command: 'npx', args: ['--transport=sse'] };
    expect(applyAutoFix(finding('outdated-transport'), server)).toBe(true);
    expect(server.args).toEqual(['--transport=streamable-http']);
  });

  it('upgrades ws:// args and ws:// urls for insecure-transport', () => {
    const viaArgs: RawMcpServerEntry = { command: 'npx', args: ['ws://sock.example.com'] };
    expect(applyAutoFix(finding('insecure-transport'), viaArgs)).toBe(true);
    expect(viaArgs.args).toEqual(['wss://sock.example.com']);

    const viaUrl: RawMcpServerEntry = { command: 'node', url: 'ws://sock.example.com' };
    expect(applyAutoFix(finding('insecure-transport'), viaUrl)).toBe(true);
    expect(viaUrl.url).toBe('wss://sock.example.com');
  });

  it('upgrades BOTH args and url when a server carries http:// in each', () => {
    const server: RawMcpServerEntry = { command: 'node', args: ['--endpoint', 'http://api.example.com'], url: 'http://api.example.com/mcp' };
    expect(applyAutoFix(finding('http-transport-no-auth'), server)).toBe(true);
    expect(server.args).toEqual(['--endpoint', 'https://api.example.com']);
    expect(server.url).toBe('https://api.example.com/mcp');
  });

  it('coerces non-string env values before secret matching', () => {
    const server: RawMcpServerEntry = { command: 'npx', env: { TOKEN: 12345678 } };
    expect(applyAutoFix(finding('exposed-secret'), server)).toBe(false);
    expect(server.env!.TOKEN).toBe(12345678);
  });

  it('reports no change when nothing matches', () => {
    const server: RawMcpServerEntry = { command: 'node', args: ['--ok'], url: 'https://fine.example.com' };
    expect(applyAutoFix(finding('http-transport-no-auth'), server)).toBe(false);
    expect(applyAutoFix(finding('not-a-real-id'), server)).toBe(false);
  });
});
