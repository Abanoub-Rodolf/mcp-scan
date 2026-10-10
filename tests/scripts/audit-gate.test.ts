import { describe, it, expect } from 'vitest';
import { spawnSync } from 'child_process';
import os from 'os';
import fs from 'fs';
import path from 'path';
import { parse } from 'yaml';
import { evaluate } from '../../scripts/audit-gate.mjs';

const root = path.resolve(__dirname, '../..');
const advisory = (id: string, severity: string, name = 'pkg') => ({
  source: 1, name, title: 'bad', severity, url: `https://github.com/advisories/${id}`,
});
const audit = (...via: unknown[]) => ({ vulnerabilities: { pkg: { via }, parent: { via: ['pkg'] } } });
const now = new Date('2026-10-09');

describe('audit gate', () => {
  it('fails on a high advisory nobody accepted', () => {
    const out = evaluate(audit(advisory('GHSA-aaaa', 'high')), [], now);
    expect(out.map(f => f.id)).toEqual(['GHSA-aaaa']);
  });

  it('fails on critical, passes moderate', () => {
    expect(evaluate(audit(advisory('GHSA-bbbb', 'critical')), [], now)).toHaveLength(1);
    expect(evaluate(audit(advisory('GHSA-cccc', 'moderate')), [], now)).toHaveLength(0);
  });

  it('lets an accepted advisory through until its review date passes', () => {
    const acc = [{ id: 'GHSA-aaaa', owner: 'rodolf', reviewBy: '2026-12-09' }];
    expect(evaluate(audit(advisory('GHSA-aaaa', 'high')), acc, now)).toHaveLength(0);
    const late = evaluate(audit(advisory('GHSA-aaaa', 'high')), acc, new Date('2027-01-01'));
    expect(late).toHaveLength(1);
    expect(late[0].why).toMatch(/expired/);
  });

  it('treats a missing or malformed review date as expired', () => {
    for (const reviewBy of [undefined, 'soon', '']) {
      const acc = [{ id: 'GHSA-aaaa', owner: 'rodolf', reviewBy }];
      expect(evaluate(audit(advisory('GHSA-aaaa', 'high')), acc, now)).toHaveLength(1);
    }
  });

  it.each([
    ['no vulnerabilities key', {}],
    ['a null map', { vulnerabilities: null }],
    ['an array map', { vulnerabilities: [] }],
    ['a string map', { vulnerabilities: 'none' }],
    ['a non-object report', null],
  ])('throws on an unexpected shape (%s) instead of passing', (_n, shape) => {
    expect(() => evaluate(shape as any, [], now)).toThrow(/no vulnerabilities map/);
  });

  it('passes a clean v2 report with an empty map', () => {
    expect(evaluate({ auditReportVersion: 2, vulnerabilities: {} }, [], now)).toEqual([]);
  });

  it.skipIf(process.platform === 'win32')('exits 2 when npm prints JSON of the wrong shape', () => {
    const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-gate-npm-'));
    try {
      fs.writeFileSync(path.join(bin, 'npm'), '#!/bin/sh\necho \'{"message":"surprise"}\'\n', { mode: 0o755 });
      const run = spawnSync(process.execPath, [path.join(root, 'scripts/audit-gate.mjs')], {
        encoding: 'utf8', env: { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}` },
      });
      expect(run.status).toBe(2);
      expect(run.stderr).toMatch(/no vulnerabilities map/);
    } finally {
      fs.rmSync(bin, { recursive: true, force: true });
    }
  });

  it('the CI step name says it audits runtime dependencies only', () => {
    const ci = parse(fs.readFileSync(path.join(root, '.github/workflows/ci.yml'), 'utf8'));
    const step = Object.values<any>(ci.jobs).flatMap(j => j.steps ?? []).find((s: any) => String(s.run ?? '').includes('audit-gate'));
    expect(step.name).toMatch(/runtime dependencies only/i);
    expect(step.name).toContain('--omit=dev');
  });

  it('every accepted entry names an owner and a review date', () => {
    const accepted = JSON.parse(fs.readFileSync(path.join(root, 'scripts/audit-accepted.json'), 'utf8'));
    for (const a of accepted) {
      expect(a.owner).toBeTruthy();
      expect(Number.isNaN(Date.parse(a.reviewBy))).toBe(false);
    }
  });

  it('CI, GitLab CI and the publish job all run the gate, not a critical-only audit', () => {
    const ci = fs.readFileSync(path.join(root, '.github/workflows/ci.yml'), 'utf8');
    const gl = fs.readFileSync(path.join(root, '.gitlab-ci.yml'), 'utf8');
    const publish = fs.readFileSync(path.join(root, '.github/workflows/publish.yml'), 'utf8');
    for (const text of [ci, gl, publish]) {
      expect(text).toContain('node scripts/audit-gate.mjs');
      expect(text).not.toContain('--audit-level=critical');
    }
    expect(parse(publish).jobs.test).toBeDefined();
  });
});
