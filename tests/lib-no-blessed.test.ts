import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

const SRC_ROOT = path.resolve(__dirname, '../src');
const DIST_ROOT = path.resolve(__dirname, '../dist');

// blessed/blessed-contrib are optionalDependencies used only by the
// dashboard TUI. The library entry point (src/lib.ts, published as
// dist/lib.js/.cjs) must never pull them in, or every `import { runScan }
// from 'mcp-scan'` consumer downloads 2MB of terminal-UI packages for a
// feature they can't reach.
const IMPORT_RE = /(?:from|import)\s*\(?\s*['"]([^'"]+)['"]\)?/g;

function resolveRelative(fromFile: string, spec: string): string {
  let target = path.resolve(path.dirname(fromFile), spec);
  if (target.endsWith('.js')) target = target.slice(0, -3) + '.ts';
  return target;
}

function collectImportGraph(entry: string, visited = new Set<string>()): Set<string> {
  if (visited.has(entry) || !fs.existsSync(entry)) return visited;
  visited.add(entry);
  const content = fs.readFileSync(entry, 'utf8');
  for (const [, spec] of content.matchAll(IMPORT_RE)) {
    if (spec === 'blessed' || spec === 'blessed-contrib') {
      throw new Error(`${entry} imports ${spec} directly`);
    }
    if (spec.startsWith('.')) collectImportGraph(resolveRelative(entry, spec), visited);
  }
  return visited;
}

describe('library entry point', () => {
  it('never references blessed or blessed-contrib in its import graph', () => {
    const graph = collectImportGraph(path.join(SRC_ROOT, 'lib.ts'));
    expect(graph.size).toBeGreaterThan(1);
    for (const file of graph) {
      expect(fs.readFileSync(file, 'utf8')).not.toMatch(/from\s+['"]blessed(-contrib)?['"]/);
    }
  });

  it.each(['lib.js', 'lib.cjs'])('dist/%s has zero references to blessed once built', (file) => {
    const distFile = path.join(DIST_ROOT, file);
    if (!fs.existsSync(distFile)) return; // build not run yet, source check above still covers this
    const matches = fs.readFileSync(distFile, 'utf8').match(/blessed/g);
    expect(matches).toBeNull();
  });
});
