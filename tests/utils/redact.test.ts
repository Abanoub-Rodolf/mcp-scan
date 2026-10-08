import { describe, it, expect } from 'vitest';
import { redactText, sanitizeUrl } from '../../src/utils/redact.js';

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
});
