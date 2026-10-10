import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { parse } from 'yaml';

const root = path.resolve(__dirname, '../..');
const workflow = parse(fs.readFileSync(path.join(root, '.github/workflows/publish.yml'), 'utf8'));

describe('publish workflow', () => {
  const needs = ([] as string[]).concat(workflow.jobs.publish.needs ?? []);

  it('publish needs a job that runs the tests', () => {
    expect(needs.length).toBeGreaterThan(0);
    const gate = needs.map(n => workflow.jobs[n]).filter(Boolean);
    const runs = gate.flatMap(j => (j.steps ?? []).map((s: { run?: string }) => s.run ?? ''));
    expect(runs).toContain('npm test');
  });

  it('builds before the tests, since the CLI tests run dist/', () => {
    const steps = needs.flatMap(n => (workflow.jobs[n]?.steps ?? []).map((s: { run?: string }) => s.run ?? ''));
    expect(steps.indexOf('npm run build')).toBeGreaterThanOrEqual(0);
    expect(steps.indexOf('npm run build')).toBeLessThan(steps.indexOf('npm test'));
  });
});
