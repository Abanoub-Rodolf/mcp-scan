import { describe, it, expect } from 'vitest';
import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const root = path.resolve(__dirname, '../..');

function tracked(): string[] | null {
  try {
    return execFileSync('git', ['ls-files'], { cwd: root, encoding: 'utf8' }).split('\n').filter(Boolean);
  } catch {
    return null; // not a git checkout (e.g. a source tarball)
  }
}

// Planning notes, agent prompts and campaign drafts live on disk but must
// not ship in the public repo.
const INTERNAL = [
  /^\.planning\//,
  /^linkedin-campaign\//,
  /^\.prompts\//,
  /^\.gemini\//,
  /^docs\/social\//,
  /^docs\/GROWTH-ROADMAP\.md$/,
  /^(GEMINI_NEXT|LINKEDIN-LAUNCH-PROMPT|MILESTONE-AUDIT|PRD|RESEARCH-V2)\.md$/,
  /^TASKS[^/]*\.md$/,
];

describe('public repo hygiene', () => {
  it('tracks no internal planning or campaign files', () => {
    const files = tracked();
    if (!files) return;
    const leaked = files.filter(f => INTERNAL.some(re => re.test(f)));
    expect(leaked).toEqual([]);
  });

  it('gitignores the directories so they cannot be re-added by accident', () => {
    const ignore = fs.readFileSync(path.join(root, '.gitignore'), 'utf8').split('\n').map(l => l.trim());
    for (const entry of ['.planning/', '/linkedin-campaign/', '/.prompts/', '/.gemini/', '/docs/social/']) {
      expect(ignore).toContain(entry);
    }
  });
});
