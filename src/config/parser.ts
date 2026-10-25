import fs from 'fs';
import path from 'path';
import * as toml from 'smol-toml';
import { McpConfig, ResolvedServer, McpScanPolicy, McpServerEntry } from '../types/config.js';
import { logger } from '../utils/logger.js';
import { readRegularFile, NotRegularFileError } from '../utils/regular-file.js';
import { PolicyError, policyFileExists, readPolicyFile } from '../utils/policy-file.js';
import { SEVERITY_ORDER, isSeverity } from '../types/severity.js';

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

export function extractServers(toolName: string, configPath: string, config: McpConfig | null, follow = true): ResolvedServer[] {
  if (!config || !config.mcpServers) return [];

  // Claude and Codex plugin manifests may point mcpServers at other files
  // ("./.mcp.json") instead of inlining them. Iterating that string made
  // one pseudo-server per character. Paths are relative to the plugin
  // root, the parent of .claude-plugin/. Followed one level only.
  const raw: unknown = config.mcpServers;
  // An array of server objects is the older inline shape, not refs.
  if (typeof raw === 'string' || (Array.isArray(raw) && raw.every(r => typeof r === 'string'))) {
    if (!follow) return [];
    const dir = path.dirname(configPath);
    const root = /^\.(claude|codex)-plugin$/.test(path.basename(dir)) ? path.dirname(dir) : dir;
    return (Array.isArray(raw) ? raw : [raw]).flatMap((ref: string) => {
      const target = path.resolve(root, ref);
      let nested: McpConfig | null = null;
      try {
        // The manifest may come from an untrusted clone: stay inside the
        // plugin root (after symlinks), refuse FIFOs and devices, and keep
        // the file's content out of any parse error.
        const realRoot = fs.realpathSync(root);
        const real = fs.realpathSync(target);
        const rel = path.relative(realRoot, real);
        if (rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) throw new Error('outside the plugin root');
        nested = parseJsonC(readRegularFile(real)) as McpConfig;
      } catch (_e) {}
      // stderr, not logger.warn: --json and --ci silence the logger, and a
      // skipped file must not pass as a clean one.
      if (!nested) process.stderr.write(`mcp-scan: ${configPath} points mcpServers at ${ref}, which could not be read or lies outside the plugin. Its servers were not scanned.\n`);
      return extractServers(toolName, target, nested, false);
    });
  }
  if (typeof raw !== 'object') return [];

  const servers: ResolvedServer[] = [];
  for (const [name, entry] of Object.entries(config.mcpServers)) {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue;
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

const isStringArray = (v: unknown) => Array.isArray(v) && v.every(x => typeof x === 'string');
const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

// Returns the first wrong-typed field, or null. A string where a list is
// expected would otherwise make includes() match substrings, or never match,
// and the rule would quietly stop enforcing.
function policyShapeProblem(p: unknown): string | null {
  if (!isPlainObject(p)) return 'expected a JSON object';
  for (const key of ['allowedPackages', 'blockedPackages', 'allowedDomains', 'suppressRules']) {
    if (p[key] !== undefined && !isStringArray(p[key])) return `"${key}" must be an array of strings`;
  }
  if (p.requiredEnvVarPrefix !== undefined && typeof p.requiredEnvVarPrefix !== 'string') {
    return '"requiredEnvVarPrefix" must be a string';
  }
  if (p.maxSeverity !== undefined
    && !(typeof p.maxSeverity === 'string' && isSeverity(p.maxSeverity.toUpperCase()))) {
    return `"maxSeverity" must be one of ${Object.keys(SEVERITY_ORDER).join(', ').toLowerCase()}`;
  }
  if (p.privacy !== undefined) {
    const pr = p.privacy;
    if (!isPlainObject(pr)) return '"privacy" must be an object';
    if (pr.maskPii !== undefined && typeof pr.maskPii !== 'boolean') return '"privacy.maskPii" must be true or false';
    if (pr.excludePatterns !== undefined && !isStringArray(pr.excludePatterns)) {
      return '"privacy.excludePatterns" must be an array of strings';
    }
    if (pr.customPatterns !== undefined
      && !(isPlainObject(pr.customPatterns) && Object.values(pr.customPatterns).every(v => typeof v === 'string'))) {
      return '"privacy.customPatterns" must be an object of strings';
    }
  }
  return null;
}

/**
 * Absent file: null, scan runs with no policy. A file that is there but
 * cannot be read, parsed or has a wrong-typed field throws PolicyError:
 * a typo must not turn enforcement off.
 */
export function loadPolicy(cwd: string = process.cwd()): McpScanPolicy | null {
  const policyPath = path.join(cwd, '.mcp-scan.json');
  if (!policyFileExists(policyPath)) return null;

  let parsed: unknown;
  try {
    parsed = parseJsonC(readPolicyFile(policyPath));
  } catch (error: any) {
    throw new PolicyError(`Cannot use policy ${policyPath}: ${error.message}. Fix or remove the file; the scan will not run without it.`);
  }
  const problem = policyShapeProblem(parsed);
  if (problem) {
    throw new PolicyError(`Invalid policy ${policyPath}: ${problem}. Fix or remove the file; the scan will not run without it.`);
  }
  return parsed as McpScanPolicy;
}

// Once per path per process: watch mode rescans on every config edit and
// would repeat the same line each time.
const noticed = new Set<string>();

export function loadIgnoreList(cwd: string = process.cwd(), opts: { silent?: boolean } = {}): string[] {
  const ignorePath = path.join(cwd, '.mcp-scan-ignore');
  try {
    return readRegularFile(ignorePath).split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
  } catch (error) {
    // Skipped, not fatal: the list only suppresses findings, so dropping it
    // can add findings but never hide one. stderr, because this runs before
    // --json silences the logger and stdout must stay parseable.
    // Anything but a plain absence: a socket that fails to open (ENXIO), a
    // permission error, EISDIR on Windows all drop the list too.
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT' && !opts.silent && !noticed.has(ignorePath)) {
      noticed.add(ignorePath);
      const why = error instanceof NotRegularFileError ? error.message : `${(error as NodeJS.ErrnoException).code ?? 'error'}: ${error instanceof Error ? error.message : String(error)}`;
      process.stderr.write(`mcp-scan: ignoring ${ignorePath}: ${why}\n`);
    }
  }
  return [];
}
