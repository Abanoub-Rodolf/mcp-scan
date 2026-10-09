import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import semver from 'semver';

const root = path.resolve(__dirname, '../..');
const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
const installed = (name: string): string => lock.packages[`node_modules/${name}`].version;

// Floors sit just past the last vulnerable release of each advisory, so a
// lockfile regression (or a pin back into the range) fails here.
describe('locked dependency floors', () => {
  it('smol-toml is past GHSA-7w5x-hrqm-74c2 and GHSA-r4xh-jqrq-34v2 (<=1.8.0)', () => {
    expect(semver.gt(installed('smol-toml'), '1.8.0')).toBe(true);
  });

  it('lodash is past GHSA-r5fr-rjxr-66jc, GHSA-f23m-r3pf-42rh, GHSA-xxjr-mmjv-4gpg (<=4.17.23)', () => {
    expect(semver.gt(installed('lodash'), '4.17.23')).toBe(true);
  });
});
