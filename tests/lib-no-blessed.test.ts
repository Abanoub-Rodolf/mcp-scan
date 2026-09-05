import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

const SRC_ROOT = path.resolve(__dirname, '../src');
const DIST_ROOT = path.resolve(__dirname, '../dist');

// blessed/blessed-contrib are optionalDependencies used only by the
// dashboard TUI. The library entry point (src/lib.ts, published as
// dist/lib.js/.cjs) must never pull them in, or every `import { runScan }
// from 'mcp-scan'` consumer downloads 2MB of terminal-UI packages for a
// feature they can't reach.
const IMPORT_RE = /(?:from|import)\s*\(?\s*['"]([^'"]+)['"]\)?/g;

// Imports in this codebase use the '.js' extension pointing at the actual
// '.ts' source (standard ESM+TS). An extensionless specifier still needs
// resolving against the file system: a walk that can't find the target
// must fail loudly rather than silently dropping that branch of the graph,
// or a bad import quietly stops this test from checking anything past it.
function resolveRelative(fromFile: string, spec: string): string {
  const base = path.resolve(path.dirname(fromFile), spec);
  const candidates = base.endsWith('.js')
    ? [base.slice(0, -3) + '.ts', base]
    : [base, `${base}.ts`, `${base}.js`, path.join(base, 'index.ts')];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
  }
  throw new Error(`cannot resolve import '${spec}' from ${fromFile}`);
}

function collectImportGraph(entry: string, visited = new Set<string>()): Set<string> {
  if (visited.has(entry)) return visited;
  if (!fs.existsSync(entry)) {
    throw new Error(`import graph walk hit a missing file: ${entry}`);
  }
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

describe('import graph walk', () => {
  let tmpDir: string | undefined;

  afterEach(() => {
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
    tmpDir = undefined;
  });

  it('catches a blessed import reached through the graph', () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-blessed-check-'));
    const entry = path.join(tmpDir, 'entry.ts');
    const leaf = path.join(tmpDir, 'leaf.ts');
    fs.writeFileSync(entry, "import { foo } from './leaf.js';\nexport { foo };\n");
    fs.writeFileSync(leaf, "import blessed from 'blessed';\nexport const foo = blessed;\n");

    expect(() => collectImportGraph(entry)).toThrow(/imports blessed directly/);
  });

  it('throws instead of skipping when a relative import cannot be resolved', () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-missing-import-'));
    const entry = path.join(tmpDir, 'entry.ts');
    fs.writeFileSync(entry, "import { missing } from './does-not-exist.js';\nexport { missing };\n");

    expect(() => collectImportGraph(entry)).toThrow(/cannot resolve import/);
  });
});
