import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execa } from 'execa';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const FIXTURE = path.join(REPO, 'tests/fixtures/valid-config.json');
const PACKAGES = ['@modelcontextprotocol/server-sqlite', '@modelcontextprotocol/server-puppeteer'];
const BROKEN = { length: 1 };
const WARNING = /mcp-scan: Offline CVE check for '[^']+' failed .*vulnerability results may be incomplete\./;

// The snapshot is read from <dist>/../data, so the built CLI runs from a copy of
// the repo layout with a snapshot this test controls. `vulns` that is not an
// array makes the lookup throw (no `.map`), as a real malformed snapshot does,
// while the trust score still reads the entry as having no advisories, so the
// report itself has no reason to differ from the healthy one.
describe('malformed offline CVE snapshot, through the built CLI', () => {
  let root: string;
  let home: string;
  const snapshot = (vulns: unknown) => fs.writeFileSync(path.join(root, 'data/cve-snapshot.json'), JSON.stringify({
    updatedAt: new Date().toISOString(),
    packages: Object.fromEntries(PACKAGES.map(p => [p, { version: '1.0.0', vulns }])),
  }));
  const run = (args: string[], cwd = root) => execa('node', [path.join(root, 'dist/index.js'), ...args], {
    cwd, reject: false, stdin: 'ignore', env: { MCP_SCAN_HOME: home, HOME: home },
  });
  // Timings are the only bytes that legitimately differ between two runs.
  const untimed = (s: string) => s.replace(/"(totalDurationMs|scanDurationMs)": \d+/g, '"$1": 0');

  beforeAll(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-snap-'));
    home = path.join(root, 'home');
    fs.mkdirSync(home);
    fs.mkdirSync(path.join(root, 'data'));
    fs.cpSync(path.join(REPO, 'dist'), path.join(root, 'dist'), { recursive: true });
    fs.copyFileSync(path.join(REPO, 'package.json'), path.join(root, 'package.json'));
    fs.symlinkSync(path.join(REPO, 'node_modules'), path.join(root, 'node_modules'));
  });
  afterAll(() => { fs.rmSync(root, { recursive: true, force: true }); });

  it('scan --json: stdout matches a healthy snapshot (durations masked), only stderr differs', async () => {
    snapshot([]);
    const healthy = await run(['scan', '--json', '--offline', '--config', FIXTURE]);
    snapshot(BROKEN);
    const broken = await run(['scan', '--json', '--offline', '--config', FIXTURE]);

    // JSON on stdout, and nothing of the warning in it
    expect(() => JSON.parse(broken.stdout)).not.toThrow();
    expect(untimed(broken.stdout)).toBe(untimed(healthy.stdout));
    expect(broken.exitCode).toBe(healthy.exitCode);
    expect(healthy.stderr).toBe('');
    expect(broken.stderr).toMatch(WARNING);
  }, 60000);

  it('sbom, which prints no report, still puts the warning on stderr and leaves stdout alone', async () => {
    const cwd = path.join(root, 'project');
    fs.mkdirSync(path.join(cwd, '.cursor'), { recursive: true });
    fs.copyFileSync(FIXTURE, path.join(cwd, '.cursor/mcp.json'));
    snapshot([]);
    const healthy = await run(['sbom', '--offline', '--output', 'sbom.json'], cwd);
    snapshot(BROKEN);
    const broken = await run(['sbom', '--offline', '--output', 'sbom.json'], cwd);

    expect(healthy.stdout).toMatch(/SBOM written to sbom\.json \(2 components\)/);
    expect(broken.stdout).toBe(healthy.stdout);
    expect(healthy.stderr).toBe('');
    expect(broken.stderr).toMatch(WARNING);
  }, 60000);
});
