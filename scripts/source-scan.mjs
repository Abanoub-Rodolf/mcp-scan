// Downloads an npm package's published tarball, extracts it to a scratch
// directory outside the repo, and runs mcp-scan's own code scanners against
// the real source instead of the synthetic `npx <pkg>` command line the rest
// of ecosystem-scan.mjs checks. Read-only: the tarball is unpacked but never
// executed (no npm install, no requiring/importing anything from it).

import { mkdtemp, rm, readFile, readdir, stat, writeFile } from 'fs/promises';
import { existsSync } from 'fs';
import os from 'os';
import path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import {
  scanAst,
  scanSecrets,
  scanToolPoisoning,
  scanPromptInjection,
  scanTransport,
  scanEnvLeak,
  scanNetworkEgress,
  scanDataFlow,
  scanDependencyCves,
} from '../dist/lib.js';

const execFileAsync = promisify(execFile);

const MAX_TARBALL_BYTES = 25 * 1024 * 1024;
const MAX_FILES_PER_PACKAGE = 40;
const MAX_FILE_BYTES = 200 * 1024;
const SOURCE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx']);
const SKIP_DIR_NAMES = new Set(['node_modules', '.git', 'test', 'tests', '__tests__', 'fixtures', 'coverage']);

function toFileServer(pkgName, relPath, content) {
  // These scanners read command/args/env as plain text (see ast-scanner.ts,
  // secret-scanner.ts etc.) - none of them parse a real MCP config off
  // disk. Carrying the file's own source as a single "arg" string is what
  // lets their regex-based checks (secrets, exfiltration patterns, prompt
  // injection strings, raw IPs) run against real package code instead of
  // the meaningless `command: npx, args: [pkg-name]` shape used elsewhere.
  return {
    name: pkgName,
    toolName: 'ecosystem-deep-scan',
    configPath: relPath,
    command: 'node',
    args: [content],
    env: {},
    description: '',
  };
}

/** First line number in `content` containing a quoted snippet from a finding's description, or null if none is found. */
function locateLine(content, description) {
  const match = description.match(/'([^']{3,200})'/);
  if (!match) return null;
  const needle = match[1];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(needle)) return i + 1;
  }
  return null;
}

function scanFileForFindings(pkgName, relPath, absPath, content) {
  const server = toFileServer(pkgName, relPath, content);
  const tagged = [
    ['ast-scanner', scanAst(server)],
    ['secret-scanner', scanSecrets(server)],
    ['tool-poisoning-scanner', scanToolPoisoning(server)],
    ['prompt-injection-scanner', scanPromptInjection(server)],
    ['transport-scanner', scanTransport(server)],
    ['network-egress-scanner', scanNetworkEgress(server)],
    ['data-flow-scanner', scanDataFlow(server)],
    ['env-leak-scanner', scanEnvLeak(server, absPath)],
  ];
  const findings = [];
  for (const [scanner, raw] of tagged) {
    for (const f of raw) {
      findings.push({ ...f, scanner, sourceFile: relPath, sourceLine: locateLine(content, f.description) });
    }
  }
  return findings;
}

// Returns { files, truncated }: truncated is true when the walk hit
// MAX_FILES_PER_PACKAGE with candidate files still unvisited, so callers
// can report "scanned 40 of N+" instead of silently implying full coverage.
async function walkSourceFiles(rootDir) {
  const files = [];
  let truncated = false;
  async function walk(dir) {
    if (files.length >= MAX_FILES_PER_PACKAGE) {
      truncated = true;
      return;
    }
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (files.length >= MAX_FILES_PER_PACKAGE) {
        truncated = true;
        return;
      }
      if (entry.name.startsWith('.')) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIR_NAMES.has(entry.name)) continue;
        await walk(full);
        continue;
      }
      const ext = path.extname(entry.name);
      if (!SOURCE_EXTENSIONS.has(ext)) continue;
      if (entry.name.includes('.min.') || entry.name.endsWith('.d.ts')) continue;
      files.push(full);
    }
  }
  await walk(rootDir);
  return { files, truncated };
}

/**
 * Streams `tarballUrl` to `destPath`, aborting as soon as the byte count
 * crosses the cap - a Content-Length header lying or missing must not let
 * an oversized (or unbounded) body get buffered into memory first, which
 * would make the cap a no-op against a malicious or misconfigured host.
 * Returns { skipped: true, reason } instead of throwing on any failure -
 * one bad tarball must not abort the campaign.
 */
async function downloadTarball(tarballUrl, destPath) {
  let res;
  try {
    res = await fetch(tarballUrl);
  } catch (err) {
    return { skipped: true, reason: `download failed: ${err instanceof Error ? err.message : String(err)}` };
  }
  if (!res.ok) return { skipped: true, reason: `download returned HTTP ${res.status}` };

  const declaredSize = Number(res.headers.get('content-length'));
  if (Number.isFinite(declaredSize) && declaredSize > MAX_TARBALL_BYTES) {
    await res.body?.cancel?.();
    return { skipped: true, reason: `tarball is ${declaredSize} bytes, over the ${MAX_TARBALL_BYTES} byte cap` };
  }
  if (!res.body) return { skipped: true, reason: 'download had no response body' };

  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_TARBALL_BYTES) {
      await reader.cancel();
      return { skipped: true, reason: `tarball exceeded the ${MAX_TARBALL_BYTES} byte cap while streaming` };
    }
    chunks.push(value);
  }
  await writeFile(destPath, Buffer.concat(chunks));
  return { skipped: false };
}

// Path segments that would let a tar entry write outside destDir once
// extracted - a crafted tarball is exactly the kind of input this campaign
// scans, so "unpacked but never executed" cannot also mean "unpacked
// wherever its own paths say to write."
function isUnsafeTarEntry(entryPath) {
  const normalized = entryPath.replace(/\\/g, '/');
  if (normalized.startsWith('/')) return true;
  return normalized.split('/').some((segment) => segment === '..');
}

async function listTarballEntries(tgzPath) {
  const { stdout } = await execFileAsync('tar', ['-tzf', tgzPath]);
  return stdout.split('\n').map((line) => line.trim()).filter(Boolean);
}

// A path check on entry NAMES alone misses the classic tar-slip variant:
// a symlink entry named e.g. "assets" pointing outside destDir, followed
// by a normal-looking "assets/pwned" entry that writes through it on
// extraction - every entry name in that pair passes isUnsafeTarEntry.
// GNU and BSD tar's verbose listing both mark a symlink with a leading
// 'l' and a "-> target" suffix; GNU tar marks a hard link with a leading
// 'h' and a "link to" suffix. Legitimate npm packages don't ship either,
// so any link entry at all is refused rather than trying to validate
// where it points.
async function hasLinkEntries(tgzPath) {
  const { stdout } = await execFileAsync('tar', ['-tvzf', tgzPath]);
  return stdout.split('\n').some((line) => {
    if (!line.trim()) return false;
    return line[0] === 'l' || line[0] === 'h' || line.includes(' -> ') || line.includes(' link to ');
  });
}

async function extractTarball(tgzPath, destDir) {
  let entries;
  let linked;
  try {
    entries = await listTarballEntries(tgzPath);
    linked = await hasLinkEntries(tgzPath);
  } catch (err) {
    return { ok: false, reason: `could not inspect tarball entries: ${err instanceof Error ? err.message : String(err)}` };
  }

  if (linked) {
    return { ok: false, reason: 'refused to extract: tarball contains a symlink or hardlink entry' };
  }
  const unsafe = entries.find(isUnsafeTarEntry);
  if (unsafe) {
    return { ok: false, reason: `refused to extract: unsafe path entry '${unsafe}'` };
  }

  try {
    await execFileAsync('tar', ['-xzf', tgzPath, '-C', destDir]);
    return { ok: true };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : String(err) };
  }
}

async function scanDeps(dependencies, lockfile) {
  const findings = await scanDependencyCves({ dependencies }, lockfile);
  return findings.map((f) => ({ ...f, scanner: 'osv-scanner', sourceFile: 'package.json', sourceLine: null }));
}

async function readJsonIfExists(filePath) {
  if (!existsSync(filePath)) return null;
  try {
    return JSON.parse(await readFile(filePath, 'utf8'));
  } catch {
    return null;
  }
}

/**
 * Deep-scans one package: downloads its tarball, extracts it, runs the
 * code scanners against real source files, and checks its dependency tree
 * against OSV. Always cleans up its temp dir, even on failure. `manifest`
 * is the registry's per-version document (needs dist.tarball + dependencies).
 */
export async function deepScanPackage(pkgName, manifest) {
  const summary = { filesScanned: 0, filesSkipped: 0, filesTruncated: false, tarball: 'not attempted' };
  const findings = [];

  const tarballUrl = manifest?.dist?.tarball;
  const dependencies = manifest?.dependencies ?? {};

  let tmpDir = null;
  try {
    if (tarballUrl) {
      tmpDir = await mkdtemp(path.join(os.tmpdir(), 'mcp-scan-deep-'));
      const tgzPath = path.join(tmpDir, 'package.tgz');
      const download = await downloadTarball(tarballUrl, tgzPath);

      if (download.skipped) {
        summary.tarball = `skipped: ${download.reason}`;
      } else {
        const extracted = await extractTarball(tgzPath, tmpDir);
        if (!extracted.ok) {
          summary.tarball = `extract failed: ${extracted.reason}`;
        } else {
          summary.tarball = 'scanned';
          const packageRoot = path.join(tmpDir, 'package');
          const rootForWalk = existsSync(packageRoot) ? packageRoot : tmpDir;

          const { files, truncated } = await walkSourceFiles(rootForWalk);
          summary.filesTruncated = truncated;
          for (const absPath of files) {
            const relPath = path.relative(rootForWalk, absPath);
            const st = await stat(absPath);
            if (st.size > MAX_FILE_BYTES) {
              summary.filesSkipped++;
              continue;
            }
            const content = await readFile(absPath, 'utf8');
            findings.push(...scanFileForFindings(pkgName, relPath, absPath, content));
            summary.filesScanned++;
          }

          const lockfile =
            (await readJsonIfExists(path.join(packageRoot, 'package-lock.json'))) ||
            (await readJsonIfExists(path.join(packageRoot, 'npm-shrinkwrap.json')));
          findings.push(...(await scanDeps(dependencies, lockfile)));
        }
      }
    } else {
      summary.tarball = 'skipped: no dist.tarball in registry metadata';
    }

    // OSV dependency check doesn't need the tarball at all when the
    // extraction path above didn't already run it (skipped/failed
    // download, or no tarball URL) - the registry manifest's own
    // `dependencies` field is the same data a shipped package.json has.
    if (summary.tarball !== 'scanned' && Object.keys(dependencies).length > 0) {
      findings.push(...(await scanDeps(dependencies, null)));
    }
  } finally {
    if (tmpDir) await rm(tmpDir, { recursive: true, force: true });
  }

  return { findings, summary };
}
