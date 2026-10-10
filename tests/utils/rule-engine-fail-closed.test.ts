import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import { execSync } from 'child_process';
import os from 'os';
import path from 'path';
import { loadCustomRules } from '../../src/utils/rule-engine.js';
import { PolicyError } from '../../src/utils/policy-file.js';

// A custom rule file that exists but can't be used must stop the scan, not
// run it with whichever rules happened to load.
describe('custom rules fail closed', () => {
  let home: string;
  let rules: string;
  const good = { id: 'ok', severity: 'HIGH', description: 'd', pattern: 'x', target: 'args' };

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-rules-'));
    rules = path.join(home, 'rules');
    process.env.MCP_SCAN_HOME = home;
  });
  afterEach(() => {
    delete process.env.MCP_SCAN_HOME;
    fs.rmSync(home, { recursive: true, force: true });
  });

  const put = (name: string, body: string) => {
    fs.mkdirSync(rules, { recursive: true });
    fs.writeFileSync(path.join(rules, name), body);
  };

  it('no rules directory is a no-op', () => {
    expect(loadCustomRules()).toEqual([]);
  });

  it('valid files load, and non-json files are ignored', () => {
    put('a.json', JSON.stringify([good]));
    put('notes.txt', 'not json');
    expect(loadCustomRules()).toHaveLength(1);
  });

  it('a file with bad JSON throws, naming the file, even when another file is fine', () => {
    put('a.json', JSON.stringify([good]));
    put('b.json', '[{ "id": ');
    expect(() => loadCustomRules()).toThrow(PolicyError);
    expect(() => loadCustomRules()).toThrow(/b\.json/);
  });

  it('an unreadable file throws', () => {
    put('a.json', JSON.stringify([good]));
    fs.mkdirSync(path.join(rules, 'dir.json'));
    expect(() => loadCustomRules()).toThrow(/Cannot read custom rule file.*dir\.json/);
  });

  it('a FIFO named like a rule file is rejected instead of blocking the scan', () => {
    put('a.json', JSON.stringify([good]));
    execSync(`mkfifo "${path.join(rules, 'pipe.json')}"`);
    expect(() => loadCustomRules()).toThrow(/pipe\.json.*not a regular file/);
  }, 5000);

  it('a rules path that is not a directory throws', () => {
    fs.writeFileSync(rules, 'x');
    expect(() => loadCustomRules()).toThrow(PolicyError);
  });

  it.each([
    ['a severity the tally would drop', { ...good, severity: 'bogus' }, /severity/],
    ['a lowercase severity', { ...good, severity: 'high' }, /severity/],
    ['a severity that is an Object.prototype name', { ...good, severity: 'constructor' }, /severity/],
    ['an unknown target', { ...good, target: 'header' }, /target/],
    ['a regex that does not compile', { ...good, pattern: '(' }, /invalid pattern/],
    ['a pattern that is not a string', { ...good, pattern: 5 }, /pattern/],
    ['a missing id', { ...good, id: undefined }, /id/],
    ['negate as a string', { ...good, negate: 'yes' }, /negate/],
    ['an entry that is not an object', 'oops', /expected an object/],
  ])('a rule with %s throws', (_n, rule, re) => {
    put('a.json', JSON.stringify([rule]));
    expect(() => loadCustomRules()).toThrow(PolicyError);
    expect(() => loadCustomRules()).toThrow(re);
  });
});
