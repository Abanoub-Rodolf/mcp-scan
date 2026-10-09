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
});
