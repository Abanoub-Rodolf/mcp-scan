import { describe, it, expect } from 'vitest';
import { execa } from 'execa';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI_PATH = path.resolve('./dist/index.js');
const VULNERABLE_FIXTURE = path.resolve('./tests/fixtures/vulnerable-config.json');
const VALID_FIXTURE = path.resolve('./tests/fixtures/valid-config.json');
const GOLDEN_DIR = path.join(__dirname, '../golden');

function loadGolden(name: string) {
  return JSON.parse(fs.readFileSync(path.join(GOLDEN_DIR, name), 'utf8'));
}

function stripNonDeterministic(report: Record<string, unknown>) {
  const cleaned = { ...report };
  delete cleaned.totalDurationMs;
  delete cleaned.version;
  if (Array.isArray(cleaned.results)) {
    cleaned.results = (cleaned.results as Record<string, unknown>[]).map((r) => {
      const cr = { ...r };
      delete cr.scanDurationMs;
      return cr;
    });
  }
  return cleaned;
}

describe('Golden File CLI Tests', () => {
  it('vulnerable config: output matches golden file', async () => {
    let stdout = '';
    try {
      await execa(`node ${CLI_PATH} scan --ci --config ${VULNERABLE_FIXTURE}`, { shell: true, stdin: 'ignore' });
    } catch (e: any) {
      stdout = e.stdout;
      expect(e.exitCode).toBe(1);
    }

    const actual = stripNonDeterministic(JSON.parse(stdout));
    const golden = loadGolden('scan-vulnerable-ci.golden.json');
    expect(JSON.stringify(actual, null, 2)).toBe(JSON.stringify(golden, null, 2));
  }, 30000);

  it('valid config: output matches golden file', async () => {
    const { stdout, exitCode } = await execa(`node ${CLI_PATH} scan --ci --config ${VALID_FIXTURE}`, { shell: true, stdin: 'ignore' });

    expect(exitCode).toBe(0);
    const actual = stripNonDeterministic(JSON.parse(stdout));
    const golden = loadGolden('scan-valid-ci.golden.json');
    expect(JSON.stringify(actual, null, 2)).toBe(JSON.stringify(golden, null, 2));
  }, 30000);

  it('exit codes: vulnerable exits 1, valid exits 0', async () => {
    let vulnerableExitCode = 0;
    try {
      await execa(`node ${CLI_PATH} scan --ci --config ${VULNERABLE_FIXTURE}`, { shell: true, stdin: 'ignore' });
    } catch (e: any) {
      vulnerableExitCode = e.exitCode;
    }
    expect(vulnerableExitCode).toBe(1);

    const { exitCode: validExitCode } = await execa(`node ${CLI_PATH} scan --ci --config ${VALID_FIXTURE}`, { shell: true, stdin: 'ignore' });
    expect(validExitCode).toBe(0);
  }, 60000);
});
