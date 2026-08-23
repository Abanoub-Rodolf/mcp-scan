import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { ScanReport, ServerScanResult, Finding } from '../types/scan-result.js';
import { atomicWriteConfig } from '../config/writer.js';

// MCP_SCAN_HOME lets embedders and tests redirect the audit store away
// from the real user home (the test suite sets it to a temp dir). Read at
// call time: module-load evaluation would freeze the default in.
const MAX_LOG_SIZE = 10 * 1024 * 1024; // 10MB
export function auditDir(): string {
  return process.env.MCP_SCAN_HOME || path.join(os.homedir(), '.mcp-scan');
}

export function logScan(report: ScanReport) {
  try {
    const dir = auditDir();
    const logFile = path.join(dir, 'audit.log');
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    if (fs.existsSync(logFile)) {
      const stats = fs.statSync(logFile);
      if (stats.size > MAX_LOG_SIZE) {
        const backupFile = `${logFile}.${Date.now()}.bak`;
        fs.renameSync(logFile, backupFile);
      }
    }

    const logEntry = {
      timestamp: new Date().toISOString(),
      user: os.userInfo().username,
      hostname: os.hostname(),
      version: report.version,
      durationMs: report.totalDurationMs,
      scannedCount: report.totalScanned,
      findings: {
        critical: report.criticalCount,
        high: report.highCount,
        medium: report.mediumCount,
        low: report.lowCount,
        info: report.infoCount
      },
      clients: [...new Set(report.results.map(r => r.toolName))],
      servers: report.results.map(r => r.serverName)
    };

    fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n', 'utf8');
    
    // Update fingerprints
    updateFingerprints(report.results);
  } catch (_error) {}
}

export function checkFingerprints(results: ServerScanResult[]): Record<string, Finding[]> {
  const mutationFindings: Record<string, Finding[]> = {};
  try {
    const fingerprintFile = path.join(auditDir(), 'known-servers.json');
    if (!fs.existsSync(fingerprintFile)) return mutationFindings;
    
    let knownFingerprints: Record<string, string> = {};
    try {
      knownFingerprints = JSON.parse(fs.readFileSync(fingerprintFile, 'utf8'));
    } catch (_e) {}
    
    for (const result of results) {
      const key = `${result.toolName}:${result.serverName}`;
      const currentFingerprint = generateFingerprint(result);
      
      if (knownFingerprints[key] && knownFingerprints[key] !== currentFingerprint) {
        mutationFindings[key] = [{
          id: 'server-mutation',
          severity: 'MEDIUM',
          description: `Server '${result.serverName}' configuration has changed since the last scan. This may indicate unauthorized modification.`,
          fixRecommendation: 'Review the changes. Confirm they are intentional and not introduced by a third party.'
        }];
      }
    }
  } catch (_error) {}
  return mutationFindings;
}

function updateFingerprints(results: ServerScanResult[]) {
  try {
    let fingerprints: Record<string, string> = {};
    const fingerprintFile = path.join(auditDir(), 'known-servers.json');
    if (fs.existsSync(fingerprintFile)) {
      fingerprints = JSON.parse(fs.readFileSync(fingerprintFile, 'utf8'));
    }

    for (const result of results) {
      const key = `${result.toolName}:${result.serverName}`;
      fingerprints[key] = generateFingerprint(result);
    }

    atomicWriteConfig(fingerprintFile, JSON.stringify(fingerprints, null, 2));
  } catch (_error) {}
}

function generateFingerprint(result: ServerScanResult): string {
  const data = {
    command: result.connection?.command,
    args: result.connection?.args,
    url: result.connection?.url,
    type: result.connection?.type,
    env: result.connection?.env, // Already sorted in scan.ts
    packageName: result.metadata?.packageName,
    version: result.metadata?.version
  };
  return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
}

interface AuditLogEntry {
  timestamp: string;
  user: string;
  hostname: string;
  version?: string;
  durationMs: number;
  scannedCount: number;
  findings: { critical: number; high: number; medium: number; low: number; info: number };
  clients: string[];
  servers: string[];
}

export function readAuditLog(count: number = 20): AuditLogEntry[] {
  try {
    const logFile = path.join(auditDir(), 'audit.log');
    if (!fs.existsSync(logFile)) return [];
    const content = fs.readFileSync(logFile, 'utf8');
    const lines = content.trim().split('\n');
    return lines.slice(-count).reverse().map(line => {
      try { return JSON.parse(line); } catch (_e) { return null; }
    }).filter(Boolean);
  } catch (_error) {
    return [];
  }
}
