import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { ScanReport, ServerScanResult, Finding } from '../types/scan-result.js';
import { atomicWriteConfig } from '../config/writer.js';
import { readRegularFile, NotRegularFileError } from './regular-file.js';

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
  } catch (error) {
    // The scan already ran, so this never throws. But a full disk or a
    // read-only home means there is no audit trail, and nobody would know.
    // stderr, once per distinct failure: stdout may be --json, and watch mode
    // calls this every rescan.
    const why = error instanceof Error ? error.message : String(error);
    // fs errors usually name the path already; print it once
    const msg = why.includes(auditDir()) ? `could not write the audit log: ${why}` : `could not write the audit log (${auditDir()}): ${why}`;
    if (!warnedAuditFailures.has(msg)) {
      if (warnedAuditFailures.size >= 50) warnedAuditFailures.clear();
      warnedAuditFailures.add(msg);
      process.stderr.write(`mcp-scan: ${msg}\n`);
    }
  }
}
const warnedAuditFailures = new Set<string>();

// Bumped when the fingerprint recipe changes, so an old store is rebuilt
// quietly instead of flagging every server once.
const SCHEMA_KEY = '__schema';
const SCHEMA = '2';
// Only registry values are stored. Entries other versions wrote under other
// sources (e.g. #resolved:snapshot) are left in place and never read.
const resolvedKey = (key: string) => `${key}#resolved:registry`;

// One entry per server per config file. Keyed by tool and name alone, two
// files defining the same name (a monorepo, a plugin next to its repo)
// overwrote each other and read as a mutation inside one clean scan.
export const fingerprintKey = (r: Pick<ServerScanResult, 'toolName' | 'serverName' | 'configPath'>) =>
  JSON.stringify([r.toolName, r.serverName, path.resolve(r.configPath)]);
// How 2.1.0 and older keyed entries.
const nameKey = (r: Pick<ServerScanResult, 'toolName' | 'serverName'>) => `${r.toolName}:${r.serverName}`;

// The registry's latest for a server whose spec has no version part (or
// says `latest`), where latest really is what runs. Not tracked: any other
// spec (an exact pin, a range, a tag), because the spec is part of the
// fingerprint, and a range or tag resolves to something other than latest
// (^1.0.0 stays in 1.x when 2.0.0 ships); and the bundled offline snapshot,
// whose version moves whenever mcp-scan itself is upgraded. metadata.version
// is never what the config resolves to.
function trackedLatest(result: ServerScanResult): string | undefined {
  const { packageName, version, versionSource } = result.metadata ?? {};
  if (!version || versionSource !== 'registry') return undefined;
  const at = packageName?.lastIndexOf('@') ?? -1;
  if (at > 0 && packageName!.slice(at + 1) !== 'latest') return undefined;
  return version;
}

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
// Server names are free text ('my#srv' is legal), so the key test is loose and
// the names the new format reserves are rejected by name instead.
const RESOLVED_SUFFIX = /#resolved(:[a-z]+)?$/;
function isLegacyShape(data: Record<string, string>): boolean {
  const entries = Object.entries(data);
  return entries.length > 0
    && entries.every(([k, v]) => /^[^:]+:.+$/.test(k) && k !== SCHEMA_KEY && k !== SIG_KEY
      && !RESOLVED_SUFFIX.test(k) && /^[0-9a-f]{64}$/.test(v));
}

function fingerprintFile(): string {
  return path.join(auditDir(), 'known-servers.json');
}

// Per-install secret, kept next to but outside the store so that editing
// the store alone cannot produce a valid signature.
export function keyFile(): string {
  return path.join(auditDir(), 'baseline.key');
}

// Thrown when baseline.key is there but is not a file (a directory, FIFO or
// device). Nothing can be signed or verified, and every way to carry on
// either hid that behind a misleading finding or deleted the user's path, so
// the scan stops and says what to move.
export class BaselineKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BaselineKeyError';
  }
}

export function assertBaselineKeyUsable(): void {
  const p = keyFile();
  let st: fs.Stats | undefined;
  try {
    st = fs.statSync(p, { throwIfNoEntry: false });
  } catch (_e) {
    return; // unreadable parent and the like: the normal key handling reports it
  }
  if (!st || st.isFile()) return;
  throw new BaselineKeyError(
    `baseline key ${p} ${st.isDirectory() ? 'is a directory' : 'is not a regular file'}, so the known-servers baseline cannot be signed or verified. ` +
    'Move or remove it, then run mcp-scan again.'
  );
}

// 'notfile' is a directory, FIFO or device at the key path: never ours to
// delete, unlike a corrupt regular file.
type Key = { status: 'missing' } | { status: 'ok'; key: Buffer } | { status: 'bad'; reason: string } | { status: 'notfile'; reason: string };

function readKey(): Key {
  try {
    const hex = readRegularFile(keyFile()).trim();
    if (/^[0-9a-f]{64}$/.test(hex)) return { status: 'ok', key: Buffer.from(hex, 'hex') };
    return { status: 'bad', reason: 'malformed' };
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return { status: 'missing' };
    const reason = e instanceof Error ? e.message : String(e);
    if (e instanceof NotRegularFileError || (e as NodeJS.ErrnoException).code === 'EISDIR') return { status: 'notfile', reason };
    return { status: 'bad', reason };
  }
}

function loadOrCreateKey(): { key: Buffer; created: boolean } {
  const existing = readKey();
  if (existing.status === 'ok') return { key: existing.key, created: false };
  // A path swapped in after assertBaselineKeyUsable() ran: refuse, never remove.
  if (existing.status === 'notfile') {
    throw new BaselineKeyError(`baseline key ${keyFile()} ${existing.reason}, so the known-servers baseline cannot be signed or verified. Move or remove it, then run mcp-scan again.`);
  }
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
    // A scan that failed to write its baseline says so; it proves nothing.
    // Lines from before the field existed have no flag and still count.
    const lines = fs.readFileSync(path.join(auditDir(), 'audit.log'), 'utf8').split('\n');
    return lines.some(l => l.trim() !== '' && !l.includes('"baselineSigned":false'));
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
    if (key.status === 'bad' || key.status === 'notfile') return tampered(`baseline key unreadable (${key.reason})`);
    if (key.status === 'missing' && SIG_KEY in data) return tampered('signed store but the baseline key is gone');
    if (key.status === 'ok') {
      if (!(SIG_KEY in data)) return tampered('signature missing');
      if (!signatureMatches(data, key.key)) return tampered('signature does not match');
    }
    // No key and no signature reads as an upgrade, unless this install
    // already signed a baseline: then someone removed both.
    const unkeyed = (status: 'unsigned' | 'legacy'): Store =>
      everSigned() ? tampered('baseline was signed before, but its signature and key are gone') : { status, data };
    // <= 2.0.13 writes {} when a scan finds no servers: an old-format
    // store with no entries, handled like any other old-format store (an
    // INFO per server), and tampered when this install signed before.
    if (Object.keys(data).length === 0) return unkeyed('legacy');
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
    out[fingerprintKey(result)] = [{ id: 'server-mutation', severity, ...text(result.serverName) }];
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
    const key = fingerprintKey(result);
    const currentFingerprint = generateFingerprint(result);
    // A baseline from before per-file keys is checked once, on the first
    // scan after an upgrade, against every file that has the name. That can
    // flag a monorepo once; skipping shared names would let a planted
    // duplicate turn the check off.
    const old = nameKey(result);
    const prior = store.data[key] === undefined && store.data[old] !== undefined ? old : key;

    if (store.data[prior] && store.data[prior] !== currentFingerprint) {
      mutationFindings[key] = [{
        id: 'server-mutation',
        severity: 'MEDIUM',
        description: `Server '${result.serverName}' configuration has changed since the last scan. This may indicate unauthorized modification.`,
        fixRecommendation: 'Review the changes. Confirm they are intentional and not introduced by a third party.'
      }];
      continue;
    }

    const latest = trackedLatest(result);
    const before = latest && store.data[resolvedKey(prior)];
    if (store.data[prior] && latest && before && before !== latest) {
      // A new latest is how a rug-pull looks, so it is MEDIUM whatever the
      // bump size: a compromised publish ships as a patch. Offline scans
      // have no latest, so going offline is not a change.
      mutationFindings[key] = [{
        id: 'server-mutation',
        severity: 'MEDIUM',
        description: `Server '${result.serverName}': registry latest changed for an unpinned server (${before} -> ${latest}). The config itself is unchanged. This may indicate a package swap.`,
        fixRecommendation: 'Pin the version in the config (pkg@x.y.z) and confirm the new release is the one you expect.'
      }];
    }
  }

  // The store came from a version that did not sign. Its entries were just
  // compared as usual; this scan signs it. Said once, not per server.
  if (store.status === 'unsigned' && results.length > 0) {
    const first = fingerprintKey(results[0]);
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
      const key = fingerprintKey(result);
      delete fingerprints[nameKey(result)];
      delete fingerprints[resolvedKey(nameKey(result))];
      fingerprints[key] = generateFingerprint(result);
      const latest = trackedLatest(result);
      if (latest) fingerprints[resolvedKey(key)] = latest;
    }

    fingerprints[SIG_KEY] = sign(fingerprints, hmacKey);
    atomicWriteConfig(fingerprintFile(), JSON.stringify(fingerprints, null, 2), { keepBackups: 5 });
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
