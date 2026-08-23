import fs from 'fs';
import path from 'path';
import * as toml from 'smol-toml';
import { McpConfig, ResolvedServer, McpScanPolicy, McpServerEntry } from '../types/config.js';
import { logger } from '../utils/logger.js';

/**
 * Strips JSONC comments and trailing commas with a proper string-state
 * machine. The old quote-count heuristic corrupted valid configs: a URL
 * with a trailing ",}" inside a string lost characters, and a line with
 * a URL plus a trailing double-slash comment failed to parse entirely
 * because the heuristic found the URL's double-slash first. Only line
 * and block comments outside string literals are removed, so 'http://x',
 * escaped quotes, and commas inside strings survive byte-for-byte.
 */
function stripJsonc(content: string): string {
  let out = '';
  let i = 0;
  const n = content.length;
  let inString = false;
  let escaped = false;

  while (i < n) {
    const c = content[i];
    const next = content[i + 1];

    if (inString) {
      out += c;
      if (escaped) {
        escaped = false;
      } else if (c === '\\') {
        escaped = true;
      } else if (c === '"') {
        inString = false;
      }
      i++;
      continue;
    }

    if (c === '"') {
      inString = true;
      out += c;
      i++;
      continue;
    }

    if (c === '/' && next === '/') {
      while (i < n && content[i] !== '\n') i++;
      continue;
    }

    if (c === '/' && next === '*') {
      i += 2;
      while (i < n && !(content[i] === '*' && content[i + 1] === '/')) i++;
      i += 2;
      continue;
    }

    if (c === ',') {
      // Trailing comma before } or ] (skip whitespace and any comments
      // that sit between the comma and the closing brace)
      let j = i + 1;
      for (;;) {
        while (j < n && /\s/.test(content[j])) j++;
        if (content[j] === '/' && content[j + 1] === '/') {
          while (j < n && content[j] !== '\n') j++;
          continue;
        }
        if (content[j] === '/' && content[j + 1] === '*') {
          j += 2;
          while (j < n && !(content[j] === '*' && content[j + 1] === '/')) j++;
          j += 2;
          continue;
        }
        break;
      }
      if (content[j] === '}' || content[j] === ']') {
        i++;
        continue;
      }
    }

    out += c;
    i++;
  }

  return out;
}

function parseJsonC(content: string) {
  // Remove BOM
  let json = content.replace(/^\uFEFF/, '');
  json = stripJsonc(json);
  return JSON.parse(json);
}

export function parseConfig(configPath: string): McpConfig | null {
  try {
    const content = fs.readFileSync(configPath, 'utf8');
    if (!content.trim()) return null;
    
    if (path.extname(configPath) === '.toml') {
       const parsed = toml.parse(content) as any;
       // Handle case where TOML structure might be mcpServers or mcp_servers
       const mcpServers = parsed.mcpServers || parsed.mcp_servers || {};
       return { mcpServers } as McpConfig;
    }

    return parseJsonC(content) as McpConfig;
  } catch (error: any) {
    if (error.code !== 'ENOENT') {
      logger.warn(`Failed to parse config at ${configPath}: ${error.message}`);
    }
    return null;
  }
}

export function extractServers(toolName: string, configPath: string, config: McpConfig | null): ResolvedServer[] {
  if (!config || !config.mcpServers) return [];

  const servers: ResolvedServer[] = [];
  for (const [name, entry] of Object.entries(config.mcpServers)) {
    // Normalize shapes that appear in real-world configs: args as objects
    // or with non-string values, env values that are numbers/booleans.
    // Downstream scanners assume string arrays / string values; one odd
    // entry must not abort the whole scan.
    const { args, env, ...rest } = entry;
    const normalized: McpServerEntry = { ...rest };

    if (args !== undefined && !Array.isArray(args)) {
      normalized.args = Object.values(args)
        .filter((a): a is string | number => typeof a === 'string' || typeof a === 'number')
        .map(String);
    } else if (Array.isArray(args)) {
      normalized.args = args;
    }

    if (env) {
      const normalizedEnv: Record<string, string> = {};
      for (const [k, v] of Object.entries(env)) {
        normalizedEnv[k] = typeof v === 'string' ? v : String(v);
      }
      normalized.env = normalizedEnv;
    }

    servers.push({
      ...normalized,
      name,
      toolName,
      configPath
    });
  }

  return servers;
}

export function loadPolicy(cwd: string = process.cwd()): McpScanPolicy | null {
  const policyPath = path.join(cwd, '.mcp-scan.json');
  try {
    if (fs.existsSync(policyPath)) {
      const content = fs.readFileSync(policyPath, 'utf8');
      return parseJsonC(content) as McpScanPolicy;
    }
  } catch (error: any) {
    logger.warn(`Failed to parse policy at ${policyPath}: ${error.message}`);
  }
  return null;
}

export function loadIgnoreList(cwd: string = process.cwd()): string[] {
  const ignorePath = path.join(cwd, '.mcp-scan-ignore');
  try {
    if (fs.existsSync(ignorePath)) {
      const content = fs.readFileSync(ignorePath, 'utf8');
      return content.split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));
    }
  } catch (_error) {}
  return [];
}

