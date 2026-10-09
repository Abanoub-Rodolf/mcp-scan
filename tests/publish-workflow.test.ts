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
});
