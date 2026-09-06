import { describe, it, expect } from 'vitest';
import os from 'os';
import path from 'path';
import { shortenHomePath } from '../../src/utils/reporter.js';

describe('shortenHomePath', () => {
  const home = os.homedir();

  it('replaces a leading home directory with ~', () => {
    const full = path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
    expect(shortenHomePath(full)).toBe(path.join('~', 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'));
  });

  it('leaves a path outside home untouched', () => {
    const outside = path.join(path.sep, 'tmp', 'mcp-scan-demo', 'home', 'Library', 'config.json');
    expect(shortenHomePath(outside)).toBe(outside);
  });

  it('collapses a path equal to home to ~', () => {
    expect(shortenHomePath(home)).toBe('~');
  });
});
