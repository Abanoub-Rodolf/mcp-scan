import { describe, it, expect, vi } from 'vitest';
import path from 'path';
import os from 'os';
import type fs from 'fs';

// Mock fast-glob for glob paths
vi.mock('fast-glob', () => ({
  default: vi.fn(async (pattern: string) => {
    if (pattern.includes('saoudrizwan.claude-dev*/settings.json')) {
      return [path.join('/mock/home', '.vscode', 'extensions', 'saoudrizwan.claude-dev-1.0.0', 'settings.json')];
    }
    if (pattern.includes('rooveterinaryinc.roo-cline*/settings.json')) {
      return [path.join('/mock/home', '.vscode', 'extensions', 'rooveterinaryinc.roo-cline-1.0.0', 'settings.json')];
    }
    return [];
  }),
}));

// Mock fs to control existsSync behavior for tests
const fsMock: Pick<typeof fs, 'existsSync'> = {
  existsSync: vi.fn((p: fs.PathLike) => {
    const s = String(p);
    // Any path that starts with our mocked home or cwd should exist.
    return s.startsWith('/mock/home') || s.startsWith('/mock/cwd');
  }),
};

// Mock os and process for dependency injection
const osMock: Pick<typeof os, 'homedir' | 'platform'> = {
  homedir: () => '/mock/home',
  platform: () => 'darwin',
};

const processMock: { cwd: () => string; env: NodeJS.ProcessEnv } = {
  cwd: () => '/mock/cwd',
  env: {
    APPDATA: '/mock/home/AppData/Roaming',
    USERPROFILE: '/mock/home',
  },
};

describe('Detector Paths', () => {
  it('should return a list of paths for different tools', async () => {
    const { getConfigPaths } = await import('../../src/config/paths.js');
    const paths = getConfigPaths({ homedir: osMock.homedir, platform: osMock.platform, env: processMock.env });
    expect(paths).toHaveProperty('Claude Desktop');
    expect(paths).toHaveProperty('Cursor');
    expect(paths).toHaveProperty('VS Code');
    expect(paths).toHaveProperty('Claude Code');
    expect(paths).toHaveProperty('Windsurf');
    expect(paths).toHaveProperty('Zed');
    expect(paths).toHaveProperty('Continue.dev');
    expect(paths).toHaveProperty('Amp');
    expect(paths).toHaveProperty('Plandex');
    expect(paths).toHaveProperty('ChatGPT Desktop');
    expect(paths).toHaveProperty('GitHub Copilot');
  });

  it('should format paths correctly based on string type', async () => {
    const { getConfigPaths } = await import('../../src/config/paths.js');
    const paths = getConfigPaths({ homedir: osMock.homedir, platform: osMock.platform, env: processMock.env });
    expect(typeof paths['Cursor']).toBe('string');
  });

  it('should not detect same config path under multiple tool names', async () => {
    const { detectTools } = await import('../../src/config/detector.js');
    const tools = await detectTools({ fs: fsMock, os: osMock, process: processMock });
    const pathCounts = new Map<string, number>();
    for (const tool of tools) {
      const resolved = path.resolve(tool.configPath);
      pathCounts.set(resolved, (pathCounts.get(resolved) || 0) + 1);
    }
    for (const [filePath, count] of pathCounts) {
      expect(count, `${filePath} detected ${count} times`).toBe(1);
    }
  });

  it('should detect newly added tool configs, including globbed and project-level', async () => {
    const { detectTools } = await import('../../src/config/detector.js');
    const detected = await detectTools({ fs: fsMock, os: osMock, process: processMock });
    const detectedNames = detected.map(t => t.name);

    expect(detectedNames).toContain('Zed');
    expect(detectedNames).toContain('Continue.dev');
    expect(detectedNames).toContain('Amp');
    expect(detectedNames).toContain('Plandex');
    expect(detectedNames).toContain('ChatGPT Desktop');
    expect(detectedNames).toContain('GitHub Copilot');
    expect(detectedNames).toContain('Cline');
    expect(detectedNames).toContain('Roo Code');

    // Verify .mcp.json detection
    const mcpJsonDetected = detected.some(t => t.configPath.endsWith('.mcp.json') && t.name === 'Project .mcp.json');
    expect(mcpJsonDetected).toBe(true);

    // Verify specific globbed path content
    const clineConfig = detected.find(t => t.name === 'Cline');
    expect(clineConfig?.configPath).toContain('saoudrizwan.claude-dev-1.0.0');

    const rooCodeConfig = detected.find(t => t.name === 'Roo Code');
    expect(rooCodeConfig?.configPath).toContain('rooveterinaryinc.roo-cline-1.0.0');
  });
});
