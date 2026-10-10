import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execa } from 'execa';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(here, '../../dist/index.js');
const CONFIG = path.resolve(here, '../fixtures/valid-config.json');

// A policy that exists but cannot be used must stop the scan with an error
// on stderr and a non-zero exit, before any scanning or output.
describe('CLI fails closed on an unusable policy', () => {
  let dir: string;
  let home: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-pfc-cwd-'));
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-pfc-home-'));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  });

  const run = (args: string[]) => execa('node', [CLI, ...args, '--offline', '--config', CONFIG], {
    cwd: dir, reject: false, stdin: 'ignore',
    env: { HOME: home, MCP_SCAN_HOME: path.join(home, '.mcp-scan') },
  });

  it('scan --ci with an unparseable .mcp-scan.json exits non-zero, names the file and prints no report', async () => {
    fs.writeFileSync(path.join(dir, '.mcp-scan.json'), '{ "blockedPackages": ["x" ');
    const res = await run(['scan', '--ci']);
    expect(res.exitCode).toBe(1);
    expect(res.stderr).toContain(path.join(dir, '.mcp-scan.json'));
    expect(res.stderr).toMatch(/JSON/);
    expect(res.stdout).toBe('');
    // Nothing was scanned, so nothing was written to the audit store.
    expect(fs.existsSync(path.join(home, '.mcp-scan', 'audit.log'))).toBe(false);
  }, 30000);

  it('ci with a wrong-typed field exits non-zero and names the field', async () => {
    fs.writeFileSync(path.join(dir, '.mcp-scan.json'), JSON.stringify({ blockedPackages: 'evil' }));
    const res = await run(['ci']);
    expect(res.exitCode).toBe(1);
    expect(res.stderr).toMatch(/blockedPackages.*array of strings/);
    expect(res.stdout).toBe('');
  }, 30000);

  it('an unparseable .mcp-scan-policy.yml in cwd exits non-zero', async () => {
    fs.writeFileSync(path.join(dir, '.mcp-scan-policy.yml'), 'version: 1\nrules: [unclosed\n');
    const res = await run(['scan', '--ci']);
    expect(res.exitCode).toBe(1);
    expect(res.stderr).toContain('.mcp-scan-policy.yml');
    expect(res.stdout).toBe('');
  }, 30000);

  it('--policy pointing at a missing file exits non-zero', async () => {
    const res = await run(['ci', '--policy', path.join(dir, 'typo.yml')]);
    expect(res.exitCode).toBe(1);
    expect(res.stderr).toMatch(/not found.*typo\.yml/);
    expect(res.stdout).toBe('');
  }, 30000);

  it('report does not skip configs one by one when the policy is broken', async () => {
    fs.writeFileSync(path.join(dir, '.mcp-scan.json'), '{ nope');
    const configs = path.join(dir, 'configs');
    fs.mkdirSync(configs);
    fs.copyFileSync(CONFIG, path.join(configs, 'mcp.json'));
    const res = await execa('node', [CLI, 'report', '--configs', configs, '--json'], {
      cwd: dir, reject: false, stdin: 'ignore',
      env: { HOME: home, MCP_SCAN_HOME: path.join(home, '.mcp-scan') },
    });
    expect(res.exitCode).toBe(1);
    expect(res.stderr).toContain(path.join(dir, '.mcp-scan.json'));
    expect(res.stdout).not.toContain('totalScanned');
  }, 30000);

  it('policy list on a broken file exits non-zero instead of saying none was found', async () => {
    fs.writeFileSync(path.join(dir, 'p.yml'), 'rules: [unclosed\n');
    const res = await execa('node', [CLI, 'policy', 'list', 'p.yml'], { cwd: dir, reject: false, stdin: 'ignore', env: { HOME: home } });
    expect(res.exitCode).toBe(1);
    expect(res.stderr).toContain('p.yml');
  }, 30000);

  it('a rule that would write a bogus severity stops the run instead of dropping findings', async () => {
    fs.writeFileSync(path.join(dir, 'p.yml'), 'version: 1\nrules:\n  - id: r\n    action: override-severity\n    severity: bogus\n');
    const res = await run(['ci', '--policy', 'p.yml']);
    expect(res.exitCode).toBe(1);
    expect(res.stderr).toMatch(/severity 'bogus'/);
  }, 30000);

  it('an unparseable custom rule file stops the run', async () => {
    const rules = path.join(home, '.mcp-scan', 'rules');
    fs.mkdirSync(rules, { recursive: true });
    fs.writeFileSync(path.join(rules, 'mine.json'), '[{ "id": ');
    const res = await run(['scan', '--ci']);
    expect(res.exitCode).toBe(1);
    expect(res.stderr).toContain('mine.json');
    expect(res.stdout).toBe('');
  }, 30000);

  it.each(['list', 'show', 'validate'])('policy %s on a dangling symlink fails instead of reporting no policy', async (action) => {
    fs.symlinkSync(path.join(dir, 'gone.yml'), path.join(dir, 'p.yml'));
    const res = await execa('node', [CLI, 'policy', action, 'p.yml'], { cwd: dir, reject: false, stdin: 'ignore', env: { HOME: home } });
    expect(res.exitCode).toBe(1);
    expect(res.stdout).not.toMatch(/No policy file found/);
  }, 30000);

  // These commands detect configs from HOME, so give HOME a Cursor config.
  // watch is covered in watch-policy.test.ts (it needs fs.watch).
  it.each([
    ['audit sqlite'],
    ['sbom --offline --output sbom.json'],
    ['compliance'],
    ['fix'],
    ['submit --dry-run'],
  ])('%s stops on a broken policy', async (argline) => {
    fs.mkdirSync(path.join(home, '.cursor'));
    fs.copyFileSync(CONFIG, path.join(home, '.cursor', 'mcp.json'));
    fs.writeFileSync(path.join(dir, '.mcp-scan.json'), '{ "blockedPackages": ');
    const res = await execa('node', [CLI, ...argline.split(' ')], {
      cwd: dir, reject: false, stdin: 'ignore',
      env: { HOME: home, MCP_SCAN_HOME: path.join(home, '.mcp-scan') },
    });
    expect(res.exitCode).toBe(1);
    expect(res.stderr).toContain(path.join(dir, '.mcp-scan.json'));
    expect(fs.existsSync(path.join(dir, 'sbom.json'))).toBe(false);
  }, 30000);

  it('absent policy files still scan and exit 0', async () => {
    const res = await run(['scan', '--ci']);
    expect(res.exitCode).toBe(0);
    expect(() => JSON.parse(res.stdout)).not.toThrow();
  }, 30000);

  it('valid policy files still scan and exit 0', async () => {
    fs.writeFileSync(path.join(dir, '.mcp-scan.json'), JSON.stringify({ blockedPackages: ['nothing-here'] }));
    fs.writeFileSync(path.join(dir, '.mcp-scan-policy.yml'), 'version: 1\nrules:\n  - id: r\n    action: warn\n    match:\n      finding_id: none\n');
    const res = await run(['scan', '--ci']);
    expect(res.exitCode).toBe(0);
  }, 30000);
});
