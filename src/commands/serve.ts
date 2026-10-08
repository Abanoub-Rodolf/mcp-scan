import fs from 'fs';
import os from 'os';
import path from 'path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { runScan } from './scan.js';
import { SCANNERS } from './scanners.js';
import { detectTools } from '../config/detector.js';
import { parseConfig } from '../config/parser.js';
import { redactDeep, redactIdentifier, redactText } from '../utils/redact.js';
import { logger } from '../utils/logger.js';

// Every tool only reads local config files and never touches the network.
const ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

const MAX_CONFIG_BYTES = 8 * 1024 * 1024;
const MAX_RESULTS = 200;
const MAX_FINDINGS = 500;

const findingSchema = z.object({
  id: z.string(),
  severity: z.string(),
  description: z.string(),
  fixRecommendation: z.string().optional(),
});

const scanOutput = {
  summary: z.object({
    version: z.string(),
    offline: z.literal(true),
    serversScanned: z.number(),
    totalFindings: z.number(),
    critical: z.number(),
    high: z.number(),
    medium: z.number(),
    low: z.number(),
    info: z.number(),
    durationMs: z.number(),
  }),
  suppression: z.object({ suppressed: z.number(), sources: z.array(z.string()) }),
  truncated: z.object({ results: z.number(), findings: z.number() }),
  results: z.array(z.object({
    server: z.string(),
    client: z.string(),
    configPath: z.string(),
    trustScore: z.number().optional(),
    findings: z.array(findingSchema),
  })),
};

// Every string leaving the server goes through redactDeep, whatever the
// scanner put in it. The scanners' own echo sites are only a first layer.
function ok<T extends Record<string, unknown>>(raw: T) {
  const structured = redactDeep(raw);
  return {
    structuredContent: structured,
    content: [{ type: 'text' as const, text: JSON.stringify(structured, null, 2) }],
  };
}

// Last-resort net: any throw out of a handler is returned as a redacted tool
// error instead of whatever message the runtime produced.
function guarded<A, R>(fn: (args: A) => Promise<R>) {
  return async (args: A) => {
    try {
      return await fn(args);
    } catch (err) {
      return fail(`Tool failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  };
}

// `ident` is a caller-supplied path echoed after the message; it gets the
// identifier pass so "Application Support" survives.
function fail(text: string, ident?: string) {
  const msg = redactText(text) + (ident ? `: ${redactIdentifier(ident)}` : '');
  return { isError: true, content: [{ type: 'text' as const, text: msg }] };
}

export function createServer(version: string): McpServer {
  const server = new McpServer({ name: 'mcp-scan', version });

  server.registerTool(
    'scan_configs',
    {
      title: 'Scan MCP configs',
      description: 'Audit MCP server configs for exposed secrets, risky permissions, prompt injection, typosquatting and other issues. Offline: no network calls, nothing is modified. Scans every detected AI tool config, or one file via config_path.',
      inputSchema: {
        config_path: z.string().max(4096).optional().describe('Path to a single MCP config file. Omit to scan all detected clients.'),
        severity: z.enum(['low', 'medium', 'high', 'critical']).default('low').describe('Minimum severity to report.'),
      },
      outputSchema: scanOutput,
      // Output also depends on ~/.mcp-scan/rules and ~/.mcp-scan-policy.yml,
      // so repeat calls are not guaranteed identical.
      annotations: { ...ANNOTATIONS, idempotentHint: false },
    },
    guarded(async ({ config_path, severity }: { config_path?: string; severity: string }) => {
      let target: string | undefined;
      let content: string | undefined;
      if (config_path) {
        const expanded = (config_path === '~' || config_path.startsWith('~/')) ? path.join(os.homedir(), config_path.slice(1)) : config_path;
        let fd: number | undefined;
        try {
          target = fs.realpathSync(path.resolve(expanded));
          // Type and size are checked on the open fd and the bytes come from
          // that same fd, so a swap after the check cannot change what is
          // read. O_NONBLOCK stops a FIFO from hanging the open.
          fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
          const st = fs.fstatSync(fd);
          if (!st.isFile()) return fail(`config_path is not a regular file`, config_path);
          if (st.size > MAX_CONFIG_BYTES) return fail(`config_path is larger than ${MAX_CONFIG_BYTES / (1024 * 1024)} MB`, config_path);
          content = fs.readFileSync(fd, 'utf8');
        } catch {
          return fail(`Config file not found or unreadable`, config_path);
        } finally {
          if (fd !== undefined) fs.closeSync(fd);
        }
        if (!parseConfig(target, content)) return fail(`config_path is empty or not valid JSON, JSONC or TOML`, config_path);
      }
      try {
        const report = await runScan({
          config: target,
          configContent: content,
          severity,
          offline: true,
          silent: true,
          readOnly: true,
          version,
        });
        // The report's connection block (command, args, url) is left out:
        // it is raw config text. Finding text is redacted in ok().
        const findingsLeft = { n: MAX_FINDINGS };
        let droppedFindings = report.results.slice(MAX_RESULTS).reduce((n, r) => n + r.findings.length, 0);
        const rows = report.results.slice(0, MAX_RESULTS).map(r => {
          const kept = r.findings.slice(0, Math.max(0, findingsLeft.n));
          findingsLeft.n -= kept.length;
          droppedFindings += r.findings.length - kept.length;
          return {
            server: r.serverName,
            client: r.toolName,
            configPath: r.configPath,
            ...(r.trustScore !== undefined ? { trustScore: r.trustScore } : {}),
            findings: kept.map(f => ({
              id: f.id,
              severity: f.severity,
              description: f.description,
              ...(f.fixRecommendation ? { fixRecommendation: f.fixRecommendation } : {}),
            })),
          };
        });
        return ok({
          summary: {
            version,
            offline: true as const,
            serversScanned: report.totalScanned,
            totalFindings: report.criticalCount + report.highCount + report.mediumCount + report.lowCount + report.infoCount,
            critical: report.criticalCount,
            high: report.highCount,
            medium: report.mediumCount,
            low: report.lowCount,
            info: report.infoCount,
            durationMs: report.totalDurationMs,
          },
          suppression: report.suppression ?? { suppressed: 0, sources: [] },
          truncated: {
            results: Math.max(0, report.results.length - MAX_RESULTS),
            findings: droppedFindings,
          },
          results: rows,
        });
      } catch (err) {
        return fail(`Scan failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    })
  );

  server.registerTool(
    'list_scanners',
    {
      title: 'List scanners',
      description: 'List the security scanners mcp-scan runs and what each one checks.',
      inputSchema: {},
      outputSchema: { scanners: z.array(z.object({ name: z.string(), description: z.string() })) },
      annotations: ANNOTATIONS,
    },
    guarded(async () => ok({ scanners: SCANNERS.map(s => ({ name: s.name, description: s.description })) }))
  );

  server.registerTool(
    'list_detected_clients',
    {
      title: 'List detected AI clients',
      description: 'List the AI tool configs mcp-scan knows about (Claude Desktop, Cursor, VS Code and others), their paths, and whether each exists on this machine.',
      inputSchema: {},
      outputSchema: { clients: z.array(z.object({ name: z.string(), configPath: z.string(), exists: z.boolean() })) },
      annotations: ANNOTATIONS,
    },
    guarded(async () => {
      const tools = await detectTools({ fs, os, process });
      return ok({ clients: tools.map(t => ({ name: t.name, configPath: t.configPath, exists: t.exists })) });
    })
  );

  return server;
}

export async function runServe(version: string): Promise<void> {
  // stdout carries JSON-RPC frames only. Anything that still calls
  // console.log (a scanner, a dependency) is sent to stderr instead of
  // corrupting the stream. The transport writes via process.stdout directly.
  logger.isSilent = true;
  console.log = console.error;
  console.info = console.error;
  console.warn = console.error;

  await createServer(version).connect(new StdioServerTransport());
  console.error(`mcp-scan ${version} MCP server ready on stdio`);
}
