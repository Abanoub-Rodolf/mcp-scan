import { describe, it, expect } from 'vitest';
import { redactDeep, redactText, sanitizeUrl } from '../../src/utils/redact.js';

describe('redactText', () => {
  it('strips userinfo, query and fragment from URLs', () => {
    expect(sanitizeUrl('https://u:p@host.io/mcp?token=abc#frag')).toBe('https://host.io/mcp?[REDACTED]');
  });

  it.each([
    'q7m2x9k4p1w8z3v6b5n0c2d4f6h8j1k3',
    'qwertzuiopasdfghjklyxcvb',
    'k3j4h5g6f7d8-s9a0p1o2i3u4-y5t6r7e8w9q0',
  ])('redacts the lowercase token %s anywhere, including a path segment', (tok) => {
    expect(redactText(`arg ${tok}`)).not.toContain(tok);
    expect(redactText(`https://a.io/v1/${tok}/mcp`)).not.toContain(tok);
  });

  it('keeps normal package names, env var names and unix paths readable', () => {
    expect(redactText('@modelcontextprotocol/server-filesystem')).toBe('@modelcontextprotocol/server-filesystem');
    expect(redactText("key 'GITHUB_PERSONAL_ACCESS_TOKEN'")).toBe("key 'GITHUB_PERSONAL_ACCESS_TOKEN'");
    expect(redactText('/Users/someone/Library/claude_desktop_config.json')).toContain('claude_desktop_config.json');
  });

  it('keeps a windows path readable', () => {
    const out = redactText('C:\\Users\\someone\\AppData\\Roaming\\Claude\\claude_desktop_config.json');
    expect(out).toContain('claude_desktop_config.json');
    expect(out).not.toContain('[REDACTED]');
  });

  it('redacts bearer values and key=value flags', () => {
    expect(redactText('--header=Authorization: Bearer opaque123456')).not.toContain('opaque123456');
    expect(redactText('--api-key=hunter2hunter2')).not.toContain('hunter2');
  });

  it('keeps path and name fields intact but still scrubs secrets in them', () => {
    const p = '/Users/rodolf/Library/Application Support/Claude/claude_desktop_config.json';
    const out = redactDeep({ configPath: p, server: 'Filesystem-Server-Production-Instance', note: p });
    expect(out.configPath).toBe(p);
    expect(out.server).toBe('Filesystem-Server-Production-Instance');
    expect(out.note).not.toBe(p);
    expect(redactDeep({ configPath: 'https://u:p@host.io/x?token=abc' }).configPath).toBe('https://host.io/x?[REDACTED]');
  });

  it('stays fast on 100KB of dash-chained input', () => {
    const t = Date.now();
    redactText('a-'.repeat(50_000));
    redactText('a.'.repeat(50_000));
    expect(Date.now() - t).toBeLessThan(500);
  });

  it('still scrubs credential-shaped text inside identifier fields', () => {
    for (const bad of ['api_key=hunter2hunter2', 'Authorization: Bearer opaque123456', '/srv/a/c.json?token=abcdef123456', 'user:hunter2@host.io/x']) {
      const out = redactDeep({ server: bad, configPath: bad, client: bad });
      expect(JSON.stringify(out)).not.toMatch(/hunter2|opaque123456|abcdef123456/);
    }
  });

  it('does not leave half a token after truncation', () => {
    const out = redactText(`${'x '.repeat(1020)}ghp_0123456789abcdefghijklmnopqrstuvwxyz`);
    expect(out).not.toContain('ghp_0123');
  });

  it('has no quadratic path on token-chained input, cap aside', () => {
    const t = Date.now();
    redactText('token-'.repeat(20_000));
    redactText('a.'.repeat(60_000));
    expect(Date.now() - t).toBeLessThan(500);
  });
});
