import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import { execSync } from 'child_process';
import os from 'os';
import path from 'path';
import { loadPolicy } from '../../src/config/parser.js';
import { loadYamlPolicy } from '../../src/policy/engine.js';
import { PolicyError } from '../../src/utils/policy-file.js';

// A policy that exists but cannot be used must stop the scan, not fall back
// to "no policy". Absent files stay a quiet no-op.
describe('policy loading fails closed', () => {
  let dir: string;
  let home: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-policy-cwd-'));
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-policy-home-'));
    vi.spyOn(process, 'cwd').mockReturnValue(dir);
    vi.spyOn(os, 'homedir').mockReturnValue(home);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  });

  const json = (body: string) => fs.writeFileSync(path.join(dir, '.mcp-scan.json'), body);
  const yml = (body: string, where = dir) => fs.writeFileSync(path.join(where, '.mcp-scan-policy.yml'), body);

  describe('.mcp-scan.json', () => {
    it('absent file is null', () => {
      expect(loadPolicy(dir)).toBeNull();
    });

    it('valid file loads, JSONC comments included', () => {
      json('{ // keep\n "blockedPackages": ["evil"], "maxSeverity": "HIGH", "privacy": { "maskPii": true },\n}');
      expect(loadPolicy(dir)?.blockedPackages).toEqual(['evil']);
    });

    it('the file `mcp-scan init` writes still loads', () => {
      json(JSON.stringify({
        allowedPackages: [], blockedPackages: [], allowedDomains: ['localhost'], requiredEnvVarPrefix: '',
        maxSeverity: 'low', suppressRules: [], ignorePaths: [], policyFile: '.mcp-scan-policy.yml', reportFormat: 'text',
      }));
      expect(loadPolicy(dir)).not.toBeNull();
    });

    it('unparseable JSON throws, naming the file and the parse error', () => {
      json('{ "blockedPackages": ["evil"] ');
      expect(() => loadPolicy(dir)).toThrow(PolicyError);
      expect(() => loadPolicy(dir)).toThrow(new RegExp(`${path.join(dir, '.mcp-scan.json').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}.*JSON`, 's'));
    });

    it('an empty file throws', () => {
      json('');
      expect(() => loadPolicy(dir)).toThrow(PolicyError);
    });

    it('a dangling symlink throws rather than reading as absent', () => {
      fs.symlinkSync(path.join(dir, 'gone.json'), path.join(dir, '.mcp-scan.json'));
      expect(() => loadPolicy(dir)).toThrow(PolicyError);
    });

    it('a dangling symlink says the target was not found', () => {
      fs.symlinkSync(path.join(dir, 'gone.json'), path.join(dir, '.mcp-scan.json'));
      expect(() => loadPolicy(dir)).toThrow(/symlink target not found.*gone\.json/);
    });

    it('a directory in its place throws', () => {
      fs.mkdirSync(path.join(dir, '.mcp-scan.json'));
      expect(() => loadPolicy(dir)).toThrow(/not a regular file/);
    });

    it.each([
      ['an array', '[]'],
      ['null', 'null'],
      ['a string', '"x"'],
    ])('JSON that parses to %s throws', (_n, body) => {
      json(body);
      expect(() => loadPolicy(dir)).toThrow(/expected a JSON object/);
    });

    it.each([
      ['blockedPackages as a string', { blockedPackages: 'evil' }, /blockedPackages/],
      ['allowedPackages with a number in it', { allowedPackages: ['ok', 3] }, /allowedPackages/],
      ['allowedDomains as an object', { allowedDomains: {} }, /allowedDomains/],
      ['suppressRules as a string', { suppressRules: 'x' }, /suppressRules/],
      ['requiredEnvVarPrefix as a list', { requiredEnvVarPrefix: ['A_'] }, /requiredEnvVarPrefix/],
      ['maxSeverity not a severity', { maxSeverity: 'severe' }, /maxSeverity/],
      ['maxSeverity as a number', { maxSeverity: 3 }, /maxSeverity/],
      ['privacy as a string', { privacy: 'on' }, /privacy/],
      ['privacy.maskPii as a string', { privacy: { maskPii: 'true' } }, /maskPii/],
      ['privacy.excludePatterns as a string', { privacy: { excludePatterns: 'email' } }, /excludePatterns/],
      ['privacy.customPatterns with a non-string', { privacy: { customPatterns: { a: 1 } } }, /customPatterns/],
    ])('wrong type throws: %s', (_n, body, re) => {
      json(JSON.stringify(body));
      expect(() => loadPolicy(dir)).toThrow(PolicyError);
      expect(() => loadPolicy(dir)).toThrow(re);
    });
  });

  describe('.mcp-scan-policy.yml', () => {
    const good = 'version: 1\nrules:\n  - id: r1\n    action: skip\n';

    it('absent files are null', () => {
      expect(loadYamlPolicy()).toBeNull();
    });

    it('valid file in cwd loads', () => {
      yml(good);
      expect(loadYamlPolicy()?.rules).toHaveLength(1);
    });

    it('unparseable YAML in cwd throws, naming the file and the parse error', () => {
      yml('version: 1\nrules: [unclosed\n');
      expect(() => loadYamlPolicy()).toThrow(PolicyError);
      expect(() => loadYamlPolicy()).toThrow(/\.mcp-scan-policy\.yml.*(flow sequence|Flow sequence|Unexpected|end of the stream)/is);
    });

    it('unparseable YAML in the home directory throws too', () => {
      yml('rules: [unclosed\n', home);
      expect(() => loadYamlPolicy()).toThrow(PolicyError);
    });

    it('a broken cwd file does not fall through to a good home file', () => {
      yml('rules: [unclosed\n');
      yml(good, home);
      expect(() => loadYamlPolicy()).toThrow(PolicyError);
    });

    it('an explicit --policy path that does not exist throws', () => {
      const missing = path.join(dir, 'nope.yml');
      expect(() => loadYamlPolicy(missing)).toThrow(PolicyError);
      expect(() => loadYamlPolicy(missing)).toThrow(/not found.*nope\.yml/);
    });

    it('an explicit --policy path that is a dangling symlink says the target was not found', () => {
      const link = path.join(dir, 'p.yml');
      fs.symlinkSync(path.join(dir, 'gone.yml'), link);
      expect(() => loadYamlPolicy(link)).toThrow(/symlink target not found.*gone\.yml/);
    });

    it('an explicit path wins over a good cwd file and still loads', () => {
      yml(good);
      const other = path.join(dir, 'other.yml');
      fs.writeFileSync(other, 'version: 1\nrules:\n  - id: a\n    action: warn\n  - id: b\n    action: block\n');
      expect(loadYamlPolicy(other)?.rules).toHaveLength(2);
    });

    const rule = (extra: string) => `version: 1\nrules:\n  - id: r\n    action: block\n${extra}`;

    it.each([
      ['an override-severity target that is not a severity', 'version: 1\nrules:\n  - id: r\n    action: override-severity\n    severity: bogus\n', /severity 'bogus'/],
      ['a severity on a warn rule that is not a severity', 'version: 1\nrules:\n  - id: r\n    action: warn\n    severity: urgent\n', /severity 'urgent'/],
      ['a typo in a match key', rule('    match:\n      finding_ids: [exposed-secret]\n'), /unknown match key 'finding_ids'/],
      ['a match that is a list', rule('    match: [exposed-secret]\n'), /'match' must be an object/],
      ['a match value that is a number', rule('    match:\n      finding_id: 7\n'), /match\.finding_id/],
      ['an empty match list', rule('    match:\n      server_name: []\n'), /match\.server_name/],
      ['pii_types, which no finding carries', rule('    match:\n      pii_types: [SSN]\n'), /unknown match key 'pii_types'/],
      ['an empty string match value', rule('    match:\n      finding_id: ""\n'), /match\.finding_id/],
      ['an empty string in a match list', rule('    match:\n      server_name: [a, ""]\n'), /match\.server_name/],
      ['a whitespace-only match value', rule('    match:\n      category: "  "\n'), /match\.category/],
      ['a typo in a rule key (matcher)', 'version: 1\nrules:\n  - id: r\n    action: skip\n    matcher:\n      finding_id: x\n', /unknown key 'matcher'/],
      ['a typo in a rule key (scaner)', 'version: 1\nrules:\n  - id: r\n    action: skip\n    scaner: data-flow\n', /unknown key 'scaner'/],
      ['an empty scanner', 'version: 1\nrules:\n  - id: r\n    action: skip\n    scanner: ""\n', /scanner/],
      ['a match.severity that is not a severity', rule('    match:\n      severity: [critcal]\n'), /match\.severity/],
    ])('a rule with %s throws', (_n, body, re) => {
      yml(body);
      expect(() => loadYamlPolicy()).toThrow(PolicyError);
      expect(() => loadYamlPolicy()).toThrow(re);
    });

    it('every documented match key and severity case still loads', () => {
      yml(rule('    match:\n      server_name: [a]\n      finding_id: x\n      severity: [CRITICAL, high]\n      category: c\n      license_type: GPL\n'));
      expect(loadYamlPolicy()?.rules).toHaveLength(1);
      yml('version: 1\nrules:\n  - id: r\n    action: override-severity\n    severity: Critical\n');
      expect(loadYamlPolicy()?.rules).toHaveLength(1);
    });

    it.each([
      ['an empty file', ''],
      ['only comments', '# no rules yet\n'],
      ['rules as a string', 'version: 1\nrules: block-everything\n'],
      ['a missing version', 'rules:\n  - id: r\n    action: skip\n'],
      ['an unknown action', 'version: 1\nrules:\n  - id: r\n    action: allow\n'],
      ['a rule without an id', 'version: 1\nrules:\n  - action: skip\n'],
      ['override-severity with no severity', 'version: 1\nrules:\n  - id: r\n    action: override-severity\n'],
    ])('a file that parses but fails the schema throws: %s', (_n, body) => {
      yml(body);
      expect(() => loadYamlPolicy()).toThrow(PolicyError);
    });
  });
});

// The type check has to be on the opened file, not on a path that can be
// swapped for a FIFO between a stat and the read.
describe('policy file type is checked on the opened file', () => {
  let dir: string;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-policy-fifo-')); });
  afterEach(() => { vi.restoreAllMocks(); fs.rmSync(dir, { recursive: true, force: true }); });

  const lyingStat = () => {
    const real = fs.statSync;
    // Every path-based stat claims a regular file, as if the swap happened after it.
    vi.spyOn(fs, 'statSync').mockImplementation(((p: any, o: any) => ({ ...real(dir), isFile: () => true, isDirectory: () => false, size: 0, p, o })) as any);
  };

  it('a FIFO at .mcp-scan.json is rejected, not read', () => {
    execSync(`mkfifo "${path.join(dir, '.mcp-scan.json')}"`);
    lyingStat();
    expect(() => loadPolicy(dir)).toThrow(/not a regular file/);
  }, 5000);

  it('a FIFO as the YAML policy is rejected, not read', () => {
    const f = path.join(dir, 'p.yml');
    execSync(`mkfifo "${f}"`);
    lyingStat();
    expect(() => loadYamlPolicy(f)).toThrow(/not a regular file/);
  }, 5000);
});
