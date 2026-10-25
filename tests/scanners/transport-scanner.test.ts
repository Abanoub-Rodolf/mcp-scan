import { describe, it, expect } from 'vitest';
import { scanTransport } from '../../src/scanners/transport-scanner.js';

describe('Transport Scanner', () => {
  it('should flag HTTP URLs with no auth', () => {
    const findings = scanTransport({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'server', 'http://example.com']
    });
    expect(findings.some(f => f.id === 'http-transport-no-auth')).toBe(true);
  });

  it('should pass HTTP URLs with auth in env', () => {
    const findings = scanTransport({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'server', 'http://example.com'],
      env: { API_KEY: 'some-key' }
    });
    expect(findings.some(f => f.id === 'http-transport-no-auth')).toBe(false);
  });

  it('should flag deprecated SSE transport', () => {
    const findings = scanTransport({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'server', '--transport=sse']
    });
    expect(findings.some(f => f.id === 'outdated-transport')).toBe(true);
  });
  // Plain HTTP to loopback never leaves the machine. 2.1.0 graded
  // http://localhost:3002 HIGH like a remote host, three runs in a row.
  // It stays LOW: any local process or a DNS-rebinding page can reach an
  // unauthenticated local server.
  it('grades loopback http:// LOW and remote http:// HIGH', () => {
    const sev = (url: string) =>
      scanTransport({ name: 'test', toolName: 't', configPath: 'p', url })
        .find(f => f.id === 'http-transport-no-auth')?.severity;
    for (const url of ['http://localhost:3002/mcp', 'http://LOCALHOST/mcp', 'http://127.0.0.1:8080', 'http://127.1.2.3', 'http://[::1]:9000/mcp']) {
      expect(sev(url), url).toBe('LOW');
    }
    for (const url of ['http://example.com/mcp', 'http://localhost.evil.com', 'http://127.0.0.1.nip.io', 'http://10.0.0.5']) {
      expect(sev(url), url).toBe('HIGH');
    }
  });

  // Rewriting a loopback arg to https:// just breaks the local server.
  it('does not mark a loopback http:// arg fixable', () => {
    const f = scanTransport({ name: 's', toolName: 't', configPath: 'p', command: 'npx', args: ['mcp-remote', 'http://localhost:3000/mcp'] });
    const t = f.find(x => x.id === 'http-transport-no-auth');
    expect(t?.severity).toBe('LOW');
    expect(t?.fixable).toBeFalsy();
    const remote = scanTransport({ name: 's', toolName: 't', configPath: 'p', command: 'npx', args: ['mcp-remote', 'http://example.com/mcp'] });
    expect(remote.find(x => x.id === 'http-transport-no-auth')).toMatchObject({ severity: 'MEDIUM', fixable: true });
  });

  // URL schemes are case-insensitive; 2.2.0 missed HTTP:// and WS:// entirely.
  it('flags plain-text schemes in any case', () => {
    const ids = (s: Partial<Parameters<typeof scanTransport>[0]>) =>
      scanTransport({ name: 's', toolName: 't', configPath: 'p', ...s } as Parameters<typeof scanTransport>[0]).map(f => `${f.id}:${f.severity}`);
    expect(ids({ url: 'HTTP://evil.example/mcp' })).toContain('http-transport-no-auth:HIGH');
    expect(ids({ url: 'Http://LOCALHOST:3000' })).toContain('http-transport-no-auth:LOW');
    expect(ids({ command: 'npx', args: ['mcp-remote', 'HTTP://evil.example/mcp'] })).toContain('http-transport-no-auth:MEDIUM');
    expect(ids({ url: 'WS://sock.example' })).toContain('insecure-transport:HIGH');
    expect(ids({ url: 'HTTPS://ok.example/mcp' })).toEqual([]);
  });
});
