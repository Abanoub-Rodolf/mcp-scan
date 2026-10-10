import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

// Several suites run the built CLI in a subprocess. `npm test` builds first,
// but a bare `npx vitest` would test a stale dist, so rebuild when any
// source file is newer than it.
function newest(dir: string): number {
  let t = 0;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    t = Math.max(t, e.isDirectory() ? newest(p) : fs.statSync(p).mtimeMs);
  }
  return t;
}

export default function setup() {
  const outputs = ['dist/index.js', 'dist/lib.js', 'data/cve-snapshot.json'].map(f => path.resolve(f));
  const oldest = outputs.every(f => fs.existsSync(f)) ? Math.min(...outputs.map(f => fs.statSync(f).mtimeMs)) : 0;
  if (oldest < newest(path.resolve('src'))) {
    execSync('npm run build', { stdio: 'ignore' });
  }
}
