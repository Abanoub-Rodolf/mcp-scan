import { describe, it, expect } from 'vitest';
import fs from 'fs';

describe('publish workflow', () => {
  const yml = fs.readFileSync('.github/workflows/publish.yml', 'utf8');

  it('refuses a tag that does not match package.json, in the test and the publish job', () => {
    const steps = yml.match(/Tag must match package\.json version/g) ?? [];
    expect(steps).toHaveLength(2);
    expect(yml).toContain('"$v" != "$GITHUB_REF_NAME"');
    // the check comes straight after checkout, before any install or build
    for (const job of yml.split(/\n  (?=publish:|test:)/).slice(1)) {
      const body = job.slice(job.indexOf('steps:'));
      expect(body.indexOf('Tag must match')).toBeLessThan(body.indexOf('npm ci'));
    }
  });

  it('fails the release when the shipped action bundle is stale', () => {
    const test = yml.slice(yml.indexOf('  test:'), yml.indexOf('  publish:'));
    expect(test).toContain('npm run build:action');
    expect(test).toContain('git diff --exit-code action/dist');
  });

  it('release also fails on an untracked or modified bundle', () => {
    const test = yml.slice(yml.indexOf('  test:'), yml.indexOf('  publish:'));
    expect(test).toContain('test -z "$(git status --porcelain action/dist)"');
  });

  // the same check has to fail the MR, not only the release
  it.each([
    ['.github/workflows/ci.yml'],
    ['.gitlab-ci.yml'],
  ])('%s fails a stale or untracked action bundle', (file) => {
    const text = fs.readFileSync(file, 'utf8');
    expect(text).toContain('npm run build:action');
    expect(text).toContain('git diff --exit-code action/dist');
    expect(text).toContain('test -z "$(git status --porcelain action/dist)"');
  });
});
