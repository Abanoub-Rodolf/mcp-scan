import fs from 'fs';
import os from 'os';
import path from 'path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { runScan } from './scan.js';
import { SCANNERS } from './scanners.js';
import { detectTools } from '../config/detector.js';
import { SECRET_PATTERNS } from '../data/secret-patterns.js';
import { logger } from '../utils/logger.js';

// Every tool only reads local config files and never touches the network.
const ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

// Findings carry key names, not values, so this should never match. It is a
// second line of defence in case a scanner ever interpolates a raw value.
const SECRET_REGEXES = SECRET_PATTERNS.map(p =>
  new RegExp(p.regex.source, p.regex.flags.includes('g') ? p.regex.flags : p.regex.flags + 'g'));

function scrub(text: string): string {
  let out = text;
  for (const re of SECRET_REGEXES) out = out.replace(re, '[REDACTED]');
  return out;
}

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
  results: z.array(z.object({
    server: z.string(),
    client: z.string(),
    configPath: z.string(),
    trustScore: z.number().optional(),
    findings: z.array(findingSchema),
  })),
};

function ok<T extends Record<string, unknown>>(structured: T) {
  return {
    structuredContent: structured,
    content: [{ type: 'text' as const, text: JSON.stringify(structured, null, 2) }],
  };
}

function fail(text: string) {
  return { isError: true, content: [{ type: 'text' as const, text }] };
}

export function createServer(version: string): McpServer {
  const server = new McpServer({ name: 'mcp-scan', version });

  server.registerTool(
    'scan_configs',
    {
      title: 'Scan MCP configs',
      description: 'Audit MCP server configs for exposed secrets, risky permissions, prompt injection, typosquatting and other issues. Offline: no network calls, nothing is modified. Scans every detected AI tool config, or one file via config_path.',
      inputSchema: {
        config_path: z.string().optional().describe('Path to a single MCP config file. Omit to scan all detected clients.'),
        severity: z.enum(['low', 'medium', 'high', 'critical']).default('low').describe('Minimum severity to report.'),
      },
      outputSchema: scanOutput,
      annotations: ANNOTATIONS,
    },
    async ({ config_path, severity }) => {
      if (config_path) {
        const expanded = config_path.startsWith('~') ? path.join(os.homedir(), config_path.slice(1)) : config_path;
        if (!fs.existsSync(path.resolve(expanded))) return fail(`Config file not found: ${config_path}`);
      }
      try {
        const report = await runScan({
          config: config_path,
          severity,
          offline: true,
          silent: true,
          readOnly: true,
          version,
        });
        // connection.args and url can hold raw credentials, so the report's
        // connection block is left out entirely rather than filtered.
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
          results: report.results.map(r => ({
            server: r.serverName,
            client: r.toolName,
            configPath: r.configPath,
            ...(r.trustScore !== undefined ? { trustScore: r.trustScore } : {}),
            findings: r.findings.map(f => ({
              id: f.id,
              severity: f.severity,
              description: scrub(f.description),
              ...(f.fixRecommendation ? { fixRecommendation: scrub(f.fixRecommendation) } : {}),
            })),
          })),
        });
      } catch (err) {
        return fail(`Scan failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
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
    async () => ok({ scanners: SCANNERS.map(s => ({ name: s.name, description: s.description })) })
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
    async () => {
      const tools = await detectTools({ fs, os, process });
      return ok({ clients: tools.map(t => ({ name: t.name, configPath: t.configPath, exists: t.exists })) });
    }
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
