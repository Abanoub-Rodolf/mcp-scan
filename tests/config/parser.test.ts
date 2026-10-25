import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { parseConfig, extractServers } from '../../src/config/parser.js';
import { logger } from '../../src/utils/logger.js';
import path from 'path';
import fs from 'fs';
import os from 'os';

describe('Config Parser', () => {
  const validPath = path.join(__dirname, '../fixtures/valid-config.json');
  const jsoncPath = path.join(__dirname, '../fixtures/jsonc-config.json');
  const emptyPath = path.join(__dirname, '../fixtures/empty-config.json');
  const invalidPath = path.join(__dirname, '../fixtures/invalid-config.json');
  const noServersPath = path.join(__dirname, '../fixtures/no-mcpservers-config.json');

  it('should successfully parse a valid config', () => {
    const config = parseConfig(validPath);
    expect(config).not.toBeNull();
    expect(config?.mcpServers).toHaveProperty('sqlite');
    expect(config?.mcpServers).toHaveProperty('puppeteer');
  });

  it('should successfully parse JSONC (comments and trailing commas)', () => {
    const config = parseConfig(jsoncPath);
    expect(config).not.toBeNull();
    expect(config?.mcpServers).toHaveProperty('test');
    expect(config?.mcpServers.test.command).toBe('node');
  });

  it('should gracefully handle empty files', () => {
    const config = parseConfig(emptyPath);
    expect(config).toBeNull();
  });

  it('should gracefully handle invalid JSON without crashing', () => {
    const config = parseConfig(invalidPath);
    expect(config).toBeNull();
  });

  it('should extract empty servers array if mcpServers key is missing', () => {
    const config = parseConfig(noServersPath);
    const servers = extractServers('TestTool', noServersPath, config);
    expect(servers).toHaveLength(0);
  });

  it('should return null for non-existent file gracefully', () => {
    const config = parseConfig('non-existent.json');
    expect(config).toBeNull();
  });

  it('should extract servers correctly', () => {
    const config = parseConfig(validPath);
    const servers = extractServers('TestTool', validPath, config);
    expect(servers).toHaveLength(2);
    expect(servers[0].name).toBe('sqlite');
    expect(servers[0].toolName).toBe('TestTool');
  });

  it('preserves URLs containing }, and // inside string values', () => {
    // Regression: the old quote-count heuristic stripped characters after
    // a URL containing ",}" and mis-parsed URLs followed by a comment.
    const config = parseJsonCContent(`{
      "mcpServers": {
        "web": { "url": "http://a,}" },
        "combo": { "url": "https://ok.com/api" } // trailing comment
      }
    }`);
    expect(config?.mcpServers.web.url).toBe('http://a,}');
    expect(config?.mcpServers.combo.url).toBe('https://ok.com/api');
  });

  it('preserves escaped quotes and double-slashes inside strings', () => {
    const config = parseJsonCContent(`{
      "mcpServers": {
        "x": { "args": ["say \\"hi\\" // not a comment", "https://x/y,,"], "n": 1 },
      }
    }`);
    expect(config?.mcpServers.x.args[0]).toBe('say "hi" // not a comment');
    expect(config?.mcpServers.x.args[1]).toBe('https://x/y,,');
  });

  it('normalizes object-form args and non-string env values', () => {
    const config = parseJsonCContent(`{
      "mcpServers": {
        "odd": {
          "command": "node",
          "args": { "a": "x", "b": 2 },
          "env": { "PORT": 3000, "FLAG": true, "NAME": "n" }
        }
      }
    }`);
    const servers = extractServers('T', 'p', config);
    expect(servers).toHaveLength(1);
    expect(servers[0].args).toEqual(['x', '2']);
    expect(servers[0].env).toEqual({ PORT: '3000', FLAG: 'true', NAME: 'n' });
  });
});

// Helper: run content through the same JSONC parser the CLI uses.
function parseJsonCContent(content: string): any {
  const tmp = path.join(os.tmpdir(), `mcp-scan-parser-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  fs.writeFileSync(tmp, content);
  try {
    return parseConfig(tmp);
  } finally {
    fs.unlinkSync(tmp);
  }
}

// Claude and Codex plugin manifests may point mcpServers at another file
// instead of inlining it. 2.1.0 iterated the string, so "./.mcp.json"
// became 11 servers named "0".."10" and 10 bogus duplicate-server hits.
describe('mcpServers given as a file reference', () => {
  let root: string;
  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-plugin-'));
    fs.mkdirSync(path.join(root, '.claude-plugin'));
  });
  afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

  it('follows a plugin manifest path relative to the plugin root', () => {
    const manifest = path.join(root, '.claude-plugin', 'plugin.json');
    fs.writeFileSync(manifest, JSON.stringify({ name: 'p', mcpServers: './.mcp.json' }));
    fs.writeFileSync(path.join(root, '.mcp.json'), JSON.stringify({ mcpServers: { docs: { command: 'node', args: ['s.js'] } } }));

    const servers = extractServers('claude-code', manifest, parseConfig(manifest));
    expect(servers.map(s => s.name)).toEqual(['docs']);
    // Findings must point at the file that defines the server.
    expect(servers[0].configPath).toBe(path.join(root, '.mcp.json'));
  });

  it('follows each path in an array of references', () => {
    const manifest = path.join(root, '.claude-plugin', 'plugin.json');
    fs.writeFileSync(manifest, JSON.stringify({ mcpServers: ['./a.json', './b.json'] }));
    fs.writeFileSync(path.join(root, 'a.json'), JSON.stringify({ mcpServers: { a: { command: 'node' } } }));
    fs.writeFileSync(path.join(root, 'b.json'), JSON.stringify({ mcpServers: { b: { command: 'node' } } }));

    expect(extractServers('t', manifest, parseConfig(manifest)).map(s => s.name)).toEqual(['a', 'b']);
  });

  // An array of server objects is not a list of file refs: 2.1.0 scanned
  // each entry, so dropping them would hide every server in that file.
  it('still scans an array of server objects', () => {
    const cfg = path.join(root, 'mcp.json');
    fs.writeFileSync(cfg, JSON.stringify({ mcpServers: [{ command: 'node' }, { command: 'npx' }] }));
    expect(extractServers('t', cfg, parseConfig(cfg)).map(s => s.command)).toEqual(['node', 'npx']);
  });

  // --json and --ci silence the logger, so the skip must reach stderr directly.
  it('reports an unreadable reference on stderr even when the logger is silent', () => {
    const manifest = path.join(root, '.claude-plugin', 'plugin.json');
    fs.writeFileSync(manifest, JSON.stringify({ mcpServers: './.mcp.json' }));
    const spy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const was = logger.isSilent;
    logger.isSilent = true;
    try {
      extractServers('t', manifest, parseConfig(manifest));
      expect(spy.mock.calls.map(c => String(c[0])).join('')).toContain('./.mcp.json');
    } finally {
      logger.isSilent = was;
      spy.mockRestore();
    }
  });

  it('yields no pseudo-servers when the reference cannot be read', () => {
    const manifest = path.join(root, '.claude-plugin', 'plugin.json');
    fs.writeFileSync(manifest, JSON.stringify({ mcpServers: './.mcp.json' }));

    expect(extractServers('t', manifest, parseConfig(manifest))).toEqual([]);
  });

  it('does not follow a reference that is itself a reference', () => {
    const manifest = path.join(root, 'plugin.json');
    fs.writeFileSync(manifest, JSON.stringify({ mcpServers: './plugin.json' }));

    expect(extractServers('t', manifest, parseConfig(manifest))).toEqual([]);
  });

  // A manifest from an untrusted clone must not make the scanner read,
  // and echo parse errors from, files outside the plugin.
  it('does not follow a reference out of the plugin root', () => {
    const outside = path.join(path.dirname(root), `outside-${path.basename(root)}.json`);
    fs.writeFileSync(outside, JSON.stringify({ mcpServers: { x: { command: 'node' } } }));
    try {
      const manifest = path.join(root, '.claude-plugin', 'plugin.json');
      fs.writeFileSync(manifest, JSON.stringify({ mcpServers: [`../${path.basename(outside)}`, outside] }));
      expect(extractServers('t', manifest, parseConfig(manifest))).toEqual([]);
    } finally {
      fs.rmSync(outside, { force: true });
    }
  });

  it('does not follow a symlink inside the root that leads out of it', () => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-outside-'));
    try {
      fs.writeFileSync(path.join(outside, 'm.json'), JSON.stringify({ mcpServers: { x: { command: 'node' } } }));
      fs.symlinkSync(path.join(outside, 'm.json'), path.join(root, '.mcp.json'));
      const manifest = path.join(root, '.claude-plugin', 'plugin.json');
      fs.writeFileSync(manifest, JSON.stringify({ mcpServers: './.mcp.json' }));
      expect(extractServers('t', manifest, parseConfig(manifest))).toEqual([]);
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  it('skips server entries that are not objects', () => {
    const servers = extractServers('t', 'p', { mcpServers: { ok: { command: 'node' }, bad: 'oops', nil: null } } as any);
    expect(servers.map(s => s.name)).toEqual(['ok']);
  });
});
