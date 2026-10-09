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

    // Fingerprints first, so the entry can say whether this scan left a
    // signed baseline behind. A later unsigned store is then not an upgrade.
    const baselineSigned = updateFingerprints(report.results);

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
      servers: report.results.map(r => r.serverName),
      baselineSigned
    };

    fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n', 'utf8');
  } catch (_error) {}
}

// Bumped when the fingerprint recipe changes, so an old store is rebuilt
// quietly instead of flagging every server once.
const SCHEMA_KEY = '__schema';
const SCHEMA = '2';
const resolvedKey = (key: string) => `${key}#resolved`;

// The HMAC lives inside the store as one more string entry, so the file
// stays a flat map and the signature is replaced in the same atomic write.
const SIG_KEY = '__sig';

type Store =
  | { status: 'missing'; baselineExisted: boolean }
  | { status: 'ok' | 'unsigned' | 'legacy'; data: Record<string, string> }
  | { status: 'bad'; reason: string; tampered?: boolean };

const tampered = (reason: string): Store => ({ status: 'bad', reason, tampered: true });

// What mcp-scan <= 2.0.13 wrote: "tool:server" -> sha256 hex, nothing else.
// Only a file that matches this exactly is treated as a store to upgrade;
// a store missing its schema marker for any other reason is suspect.
function isLegacyShape(data: Record<string, string>): boolean {
  const entries = Object.entries(data);
  return entries.length > 0
    && entries.every(([k, v]) => /^[^:#_][^:#]*:[^#]+$/.test(k) && /^[0-9a-f]{64}$/.test(v));
}

function fingerprintFile(): string {
  return path.join(auditDir(), 'known-servers.json');
}

// Per-install secret, kept next to but outside the store so that editing
// the store alone cannot produce a valid signature.
function keyFile(): string {
  return path.join(auditDir(), 'baseline.key');
}

type Key = { status: 'missing' } | { status: 'ok'; key: Buffer } | { status: 'bad'; reason: string };

function readKey(): Key {
  try {
    const hex = fs.readFileSync(keyFile(), 'utf8').trim();
    if (/^[0-9a-f]{64}$/.test(hex)) return { status: 'ok', key: Buffer.from(hex, 'hex') };
    return { status: 'bad', reason: 'malformed' };
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return { status: 'missing' };
    return { status: 'bad', reason: e instanceof Error ? e.message : String(e) };
  }
}

function loadOrCreateKey(): { key: Buffer; created: boolean } {
  const existing = readKey();
  if (existing.status === 'ok') return { key: existing.key, created: false };
  if (existing.status === 'bad') fs.rmSync(keyFile(), { force: true });
  fs.mkdirSync(auditDir(), { recursive: true });
  const key = crypto.randomBytes(32);
  try {
    // 'wx' so two first runs at once cannot replace each other's key: the
    // one that lands second adopts the key already on disk.
    fs.writeFileSync(keyFile(), key.toString('hex') + '\n', { mode: 0o600, flag: 'wx' });
    return { key, created: true };
  } catch (e) {
    const winner = readKey();
    if ((e as NodeJS.ErrnoException).code === 'EEXIST' && winner.status === 'ok') return { key: winner.key, created: false };
    throw e;
  }
}

// Sorted so the same entries always sign the same, whatever order the file
// or the scan happened to build them in.
function sign(data: Record<string, string>, key: Buffer): string {
  const entries = Object.keys(data).filter(k => k !== SIG_KEY).sort().map(k => [k, data[k]]);
  return crypto.createHmac('sha256', key).update(JSON.stringify(entries)).digest('hex');
}

function signatureMatches(data: Record<string, string>, key: Buffer): boolean {
  const have = data[SIG_KEY];
  if (typeof have !== 'string' || !/^[0-9a-f]{64}$/.test(have)) return false;
  return crypto.timingSafeEqual(Buffer.from(have, 'hex'), Buffer.from(sign(data, key), 'hex'));
}

// Signs that this install has kept a baseline before: the key is created
// with the first store, and the audit log is appended on every scan, so a
// store missing next to either one was removed, not never written.
function baselineExisted(): boolean {
  try {
    if (fs.existsSync(keyFile())) return true;
    return fs.statSync(path.join(auditDir(), 'audit.log')).size > 0;
  } catch (_e) {
    return false;
  }
}

// True once any scan on this install left a signed baseline. Read from the
// audit log, which anyone with write access can edit, so it only raises the
// bar for a script that strips the signature and the key and nothing else.
function everSigned(): boolean {
  try {
    return fs.readFileSync(path.join(auditDir(), 'audit.log'), 'utf8').includes('"baselineSigned":true');
  } catch (_e) {
    return false;
  }
}

function readStore(): Store {
  const file = fingerprintFile();
  let raw: string;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return { status: 'missing', baselineExisted: baselineExisted() };
    return { status: 'bad', reason: e instanceof Error ? e.message : String(e) };
  }
  try {
    const data = JSON.parse(raw);
    const valid = data !== null && typeof data === 'object' && !Array.isArray(data)
      && Object.values(data).every(v => typeof v === 'string');
    if (!valid) return { status: 'bad', reason: 'not a map of fingerprints' };
    // Once this install has a key, every store it reads must carry a valid
    // signature, including one that looks like an older format. Otherwise
    // writing an old-format file would be a way around the check.
    const key = readKey();
    // A store that was signed cannot be verified without its key. A missing
    // or damaged key is how a forged store would be slipped past us.
    if (key.status === 'bad') return tampered(`baseline key unreadable (${key.reason})`);
    if (key.status === 'missing' && SIG_KEY in data) return tampered('signed store but the baseline key is gone');
    if (key.status === 'ok') {
      if (!(SIG_KEY in data)) return tampered('signature missing');
      if (!signatureMatches(data, key.key)) return tampered('signature does not match');
    }
    // No key and no signature reads as an upgrade, unless this install
    // already signed a baseline: then someone removed both.
    const unkeyed = (status: 'unsigned' | 'legacy'): Store =>
      everSigned() ? tampered('baseline was signed before, but its signature and key are gone') : { status, data };
    if (data[SCHEMA_KEY] === SCHEMA) return key.status === 'ok' ? { status: 'ok', data } : unkeyed('unsigned');
    if (SCHEMA_KEY in data) return { status: 'bad', reason: `unknown schema '${data[SCHEMA_KEY]}'` };
    return isLegacyShape(data) ? unkeyed('legacy') : { status: 'bad', reason: 'no schema marker and not the old store format' };
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

// Used when the baseline cannot vouch for any server: every one gets the
// same finding, worded for that server.
function flagAll(results: ServerScanResult[], severity: Finding['severity'], text: (name: string) => Pick<Finding, 'description' | 'fixRecommendation'>) {
  const out: Record<string, Finding[]> = {};
  for (const result of results) {
    out[`${result.toolName}:${result.serverName}`] = [{ id: 'server-mutation', severity, ...text(result.serverName) }];
  }
  return out;
}

export function checkFingerprints(results: ServerScanResult[]): Record<string, Finding[]> {
  const mutationFindings: Record<string, Finding[]> = {};
  const store = readStore();
  // A true first run has nothing to compare against and stays quiet. A
  // store that vanished from an install that had one is not a first run.
  if (store.status === 'missing') {
    if (!store.baselineExisted) return mutationFindings;
    return flagAll(results, 'MEDIUM', name => ({
      description: `Server '${name}' could not be checked for tampering: the fingerprint store (${fingerprintFile()}) went missing although earlier scans had recorded a baseline. Treat it as possibly deleted to hide a change.`,
      fixRecommendation: 'A fresh baseline is built on this scan. Review the server configs by hand this once, and check what removed the file.'
    }));
  }

  // Fail closed: if the baseline cannot be trusted, no server can be
  // verified, so every server is reported rather than silently passed.
  if (store.status === 'bad') {
    quarantineStore();
    return flagAll(results, 'MEDIUM', name => ({
      description: `Server '${name}' could not be checked for tampering: the fingerprint store (${fingerprintFile()}) ${store.tampered ? 'failed its integrity check' : 'was unreadable or corrupt'} (${store.reason}). Treat it as possibly modified.`,
      fixRecommendation: 'The bad file was moved aside and a fresh baseline is built on this scan. Review the server configs by hand this once, and check why the store was damaged.'
    }));
  }

  // An old-format store cannot be compared against the new recipe, so the
  // baseline resets. Say so, once, instead of resetting silently.
  if (store.status === 'legacy') {
    return flagAll(results, 'INFO', name => ({
      description: `Server '${name}' baseline was reset: the fingerprint store used an older format, so this scan could not check it for changes.`,
      fixRecommendation: 'No action needed. Changes are tracked from this scan on.'
    }));
  }

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

  // The store came from a version that did not sign. Its entries were just
  // compared as usual; this scan signs it. Said once, not per server.
  if (store.status === 'unsigned' && results.length > 0) {
    const first = `${results[0].toolName}:${results[0].serverName}`;
    mutationFindings[first] = [...(mutationFindings[first] ?? []), {
      id: 'server-mutation',
      severity: 'INFO',
      description: `The fingerprint store (${fingerprintFile()}) was not signed. It will be signed with a new per-install key on this scan, so later edits to it are detected.`,
      fixRecommendation: 'No action needed. Changes are tracked and verified from this scan on.'
    }];
  }
  return mutationFindings;
}

function updateFingerprints(results: ServerScanResult[]): boolean {
  let newKey = false;
  try {
    const store = readStore();
    if (store.status === 'bad') quarantineStore();
    // A store from an older recipe is rebuilt from scratch, not merged.
    // An unsigned current-format store keeps its entries and gets signed.
    const fingerprints = store.status === 'ok' || store.status === 'unsigned' ? { ...store.data } : {};
    delete fingerprints[SIG_KEY];
    fingerprints[SCHEMA_KEY] = SCHEMA;
    const loaded = loadOrCreateKey();
    const hmacKey = loaded.key;
    newKey = loaded.created;

    for (const result of results) {
      const key = `${result.toolName}:${result.serverName}`;
      fingerprints[key] = generateFingerprint(result);
      const resolved = result.metadata?.version;
      // An offline scan has no resolved version; keep the last known one.
      if (resolved) fingerprints[resolvedKey(key)] = resolved;
    }

    fingerprints[SIG_KEY] = sign(fingerprints, hmacKey);
    atomicWriteConfig(fingerprintFile(), JSON.stringify(fingerprints, null, 2));
    return true;
  } catch (_error) {
    // A key with no store behind it would read as a deleted baseline.
    if (newKey) try { fs.rmSync(keyFile(), { force: true }); } catch (_e) {}
    return false;
  }
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
