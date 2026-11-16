import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'node:url';
import { scanLive } from '../../src/scanners/live-scanner.js';
import { snapshotOf, diffSnapshots } from '../../src/utils/live-snapshot.js';
import type { LiveCatalog } from '../../src/utils/mcp-client.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../bench/corpus');
const load = (dir: string) => fs.readdirSync(path.join(root, dir)).filter(f => f.endsWith('.json')).sort()
  .map(f => ({ file: f, ...JSON.parse(fs.readFileSync(path.join(root, dir, f), 'utf8')) }));
const catalog = (s: any): LiveCatalog => ({ tools: s.tools ?? [], prompts: s.prompts ?? [], resources: s.resources ?? [], resourceTemplates: [], instructions: s.instructions ?? undefined });
const flagged = (s: any) => scanLive(catalog(s)).some(f => f.severity === 'MEDIUM' || f.severity === 'HIGH');

const poisoned = load('poisoned');
const benign = load('benign');

describe('benchmark corpus', () => {
  it('has labeled, attributed samples whose id is the file name', () => {
    for (const s of poisoned) {
      expect(s.id).toBe(s.file.replace(/\.json$/, ''));
      expect(s.label).toBe('poisoned');
      expect(typeof s.category).toBe('string');
      expect(String(s.source?.url)).toMatch(/^https:\/\//);
    }
    for (const s of benign) {
      expect(s.id).toBe(s.file.replace(/\.json$/, ''));
      expect(s.label).toBe('benign');
      expect(['tuning', 'holdout']).toContain(s.set);
      expect(String(s.source)).toMatch(/^npm:/);
    }
    expect(poisoned.length).toBeGreaterThanOrEqual(50);
    expect(benign.filter(s => s.set === 'holdout').length).toBeGreaterThanOrEqual(10);
  });

  it('keeps invisible characters intact', () => {
    const s = poisoned.find(p => p.id === 'embracethered-motd-unicode-tags')!;
    expect(JSON.stringify(s.tools)).toMatch(/[\u{E0000}-\u{E007F}]/u);
  });

  it('flags no honest server at MEDIUM or above, tuning or holdout', () => {
    const bad = benign.filter(flagged).map(s => s.id);
    expect(bad).toEqual([]);
  });

  it('recall on published proofs of concept stays at or above the floor', () => {
    const hit = poisoned.filter(flagged).length;
    // 34 of 51 when this was written. A drop means a regression; a rise should raise the floor.
    expect(hit).toBeGreaterThanOrEqual(33);
  });

  it('reports every recorded rug pull as a changed or added definition', () => {
    const pulls = poisoned.filter(s => s.before);
    expect(pulls.length).toBeGreaterThanOrEqual(4);
    for (const s of pulls) {
      const f = diffSnapshots(s.id, snapshotOf(catalog(s.before)), snapshotOf(catalog(s)));
      expect(f.some(x => x.id === 'tool-definition-changed' || x.id === 'tool-added'), s.id).toBe(true);
    }
  });
});
