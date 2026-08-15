import { describe, it, expect } from 'vitest';
import { parseConfig, extractServers } from '../../src/config/parser.js';
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
