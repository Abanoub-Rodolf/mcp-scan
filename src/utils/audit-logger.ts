import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import semver from 'semver';
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

// Bumped when the fingerprint recipe changes, so an old store is rebuilt
// quietly instead of flagging every server once.
const SCHEMA_KEY = '__schema';
const SCHEMA = '2';
const resolvedKey = (key: string) => `${key}#resolved`;

type Store = { status: 'missing' } | { status: 'ok'; data: Record<string, string> } | { status: 'bad'; reason: string };

function fingerprintFile(): string {
  return path.join(auditDir(), 'known-servers.json');
}

function readStore(): Store {
  const file = fingerprintFile();
  let raw: string;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return { status: 'missing' };
    return { status: 'bad', reason: e instanceof Error ? e.message : String(e) };
  }
  try {
    const data = JSON.parse(raw);
    const valid = data !== null && typeof data === 'object' && !Array.isArray(data)
      && Object.values(data).every(v => typeof v === 'string');
    return valid ? { status: 'ok', data } : { status: 'bad', reason: 'not a map of fingerprints' };
  } catch (e) {
    return { status: 'bad', reason: e instanceof Error ? e.message : String(e) };
  }
}

// Move a corrupt store aside so the next scan rebuilds a baseline instead
// of tripping on the same file forever.
function quarantineStore() {
  try {
    const file = fingerprintFile();
    fs.renameSync(file, `${file}.corrupt-${Date.now()}`);
  } catch (_e) {}
}

export function checkFingerprints(results: ServerScanResult[]): Record<string, Finding[]> {
  const mutationFindings: Record<string, Finding[]> = {};
  const store = readStore();
  if (store.status === 'missing') return mutationFindings;

  // Fail closed: if the baseline cannot be trusted, no server can be
  // verified, so every server is reported rather than silently passed.
  if (store.status === 'bad') {
    quarantineStore();
    for (const result of results) {
      mutationFindings[`${result.toolName}:${result.serverName}`] = [{
        id: 'server-mutation',
        severity: 'MEDIUM',
        description: `Server '${result.serverName}' could not be checked for tampering: the fingerprint store (${fingerprintFile()}) was unreadable or corrupt (${store.reason}). Treat it as possibly modified.`,
        fixRecommendation: 'The bad file was moved aside and a fresh baseline is built on this scan. Review the server configs by hand this once, and check why the store was damaged.'
      }];
    }
    return mutationFindings;
  }

  if (store.data[SCHEMA_KEY] !== SCHEMA) return mutationFindings;

  for (const result of results) {
    const key = `${result.toolName}:${result.serverName}`;
    const currentFingerprint = generateFingerprint(result);

    if (store.data[key] && store.data[key] !== currentFingerprint) {
      mutationFindings[key] = [{
        id: 'server-mutation',
        severity: 'MEDIUM',
        description: `Server '${result.serverName}' configuration has changed since the last scan. This may indicate unauthorized modification.`,
        fixRecommendation: 'Review the changes. Confirm they are intentional and not introduced by a third party.'
      }];
      continue;
    }

    const before = store.data[resolvedKey(key)];
    const now = result.metadata?.version;
    if (store.data[key] && before && now && before !== now) {
      // A resolved version swap is how a rug-pull looks, so it is MEDIUM.
      // Only a plain patch bump of the same package drops to LOW.
      const patchBump = semver.valid(before) && semver.valid(now)
        && semver.gt(now, before) && semver.diff(before, now) === 'patch';
      mutationFindings[key] = [{
        id: 'server-mutation',
        severity: patchBump ? 'LOW' : 'MEDIUM',
        description: `Server '${result.serverName}' resolved to a different package version since the last scan (${before} -> ${now}). The config itself is unchanged. This may indicate a package swap.`,
        fixRecommendation: 'Pin the version in the config and confirm the new release is the one you expect.'
      }];
    }
  }
  return mutationFindings;
}

function updateFingerprints(results: ServerScanResult[]) {
  try {
    const store = readStore();
    if (store.status === 'bad') quarantineStore();
    // A store from an older recipe is rebuilt from scratch, not merged.
    const fingerprints = store.status === 'ok' && store.data[SCHEMA_KEY] === SCHEMA ? store.data : {};
    fingerprints[SCHEMA_KEY] = SCHEMA;

    for (const result of results) {
      const key = `${result.toolName}:${result.serverName}`;
      fingerprints[key] = generateFingerprint(result);
      const resolved = result.metadata?.version;
      // An offline scan has no resolved version; keep the last known one.
      if (resolved) fingerprints[resolvedKey(key)] = resolved;
    }

    atomicWriteConfig(fingerprintFile(), JSON.stringify(fingerprints, null, 2));
  } catch (_error) {}
}

// Hash of the config the user wrote. The resolved package version is left
// out on purpose: an unpinned npx server gets a new version whenever its
// publisher ships, so the version is tracked separately and judged by how
// it moved. The package name stays in: a different package is a swap.
function generateFingerprint(result: ServerScanResult): string {
  const data = {
    command: result.connection?.command,
    args: result.connection?.args,
    url: result.connection?.url,
    type: result.connection?.type,
    env: result.connection?.env, // Already sorted in scan.ts
    // Same in offline and online scans. A swapped package is tampering.
    packageName: result.metadata?.packageName
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
