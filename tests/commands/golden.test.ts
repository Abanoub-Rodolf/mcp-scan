import { describe, it, expect } from 'vitest';
import { execa } from 'execa';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');
const CLI_PATH = path.resolve(REPO_ROOT, 'dist/index.js');
const VULNERABLE_FIXTURE = path.resolve(REPO_ROOT, 'tests/fixtures/vulnerable-config.json');
const VALID_FIXTURE = path.resolve(REPO_ROOT, 'tests/fixtures/valid-config.json');
const GOLDEN_DIR = path.join(__dirname, '../golden');

function loadGolden(name: string) {
  return JSON.parse(fs.readFileSync(path.join(GOLDEN_DIR, name), 'utf8'));
}

// Findings whose presence depends on environment state (~/.mcp-scan fingerprints,
// audit log) rather than scanner output. These differ across machines and runs.
const ENV_STATE_FINDING_IDS = new Set(['server-mutation']);

function normalize(report: Record<string, unknown>): Record<string, unknown> {
  const cleaned: Record<string, unknown> = { ...report };
  delete cleaned.totalDurationMs;
  delete cleaned.version;

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 } as Record<string, number>;

  if (Array.isArray(cleaned.results)) {
    cleaned.results = (cleaned.results as Record<string, unknown>[])
      .map((r) => {
        const cr: Record<string, unknown> = { ...r };
        delete cr.scanDurationMs;
        delete cr.configPath;
        if (cr.metadata && typeof cr.metadata === 'object') {
          const meta = { ...cr.metadata as Record<string, unknown> };
          delete meta.version;
          delete meta.repositoryUrl;
          delete meta.author;
          delete meta.license;
          cr.metadata = meta;
        }
        if (Array.isArray(cr.findings)) {
          const filtered = (cr.findings as Record<string, unknown>[])
            .filter(f => !ENV_STATE_FINDING_IDS.has(String(f.id)));
          for (const f of filtered) {
            const sev = String(f.severity).toUpperCase();
            if (counts[sev] !== undefined) counts[sev]++;
          }
          cr.findings = filtered.sort((a, b) => {
            const idCmp = String(a.id).localeCompare(String(b.id));
            if (idCmp !== 0) return idCmp;
            return String(a.description ?? '').localeCompare(String(b.description ?? ''));
          });
        }
        return cr;
      })
      .sort((a, b) => String(a.serverName ?? '').localeCompare(String(b.serverName ?? '')));
  }

  cleaned.criticalCount = counts.CRITICAL;
  cleaned.highCount = counts.HIGH;
  cleaned.mediumCount = counts.MEDIUM;
  cleaned.lowCount = counts.LOW;
  cleaned.infoCount = counts.INFO;

  return cleaned;
}

async function runCli(fixture: string) {
  return execa('node', [CLI_PATH, 'scan', '--ci', '--offline', '--config', fixture], {
    reject: false,
    stdin: 'ignore',
  });
}

function expectedExit(golden: { criticalCount?: number; highCount?: number }): number {
  return (golden.criticalCount ?? 0) + (golden.highCount ?? 0) > 0 ? 1 : 0;
}

describe('Golden File CLI Tests', () => {
  it('vulnerable config: stdout matches golden file', async () => {
    const golden = loadGolden('scan-vulnerable-ci.golden.json');
    const { stdout, stderr, exitCode } = await runCli(VULNERABLE_FIXTURE);

    expect(exitCode).toBe(expectedExit(golden));
    expect(stderr).toBe('');

    const actual = normalize(JSON.parse(stdout));
    expect(JSON.stringify(actual, null, 2)).toBe(JSON.stringify(golden, null, 2));
  }, 30000);

  it('valid config: stdout matches golden file', async () => {
    const golden = loadGolden('scan-valid-ci.golden.json');
    const { stdout, stderr, exitCode } = await runCli(VALID_FIXTURE);

    expect(exitCode).toBe(expectedExit(golden));
    expect(stderr).toBe('');

    const actual = normalize(JSON.parse(stdout));
    expect(JSON.stringify(actual, null, 2)).toBe(JSON.stringify(golden, null, 2));
  }, 30000);
});
