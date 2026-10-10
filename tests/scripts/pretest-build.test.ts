import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

// golden.test.ts and ci.test.ts run dist/index.js, so `npm test` on a fresh
// clone fails unless something builds first.
describe('npm test on a fresh clone', () => {
  const pkg = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../package.json'), 'utf8'));

  it('builds first via pretest', () => {
    expect(pkg.scripts.pretest).toBe('npm run build');
  });

  it('the CLI tests that need dist/ exist, so the pretest is not dead weight', () => {
    const golden = fs.readFileSync(path.resolve(__dirname, '../commands/golden.test.ts'), 'utf8');
    expect(golden).toContain('dist/index.js');
  });
});
