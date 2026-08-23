import { describe, it, expect } from 'vitest';
import { buildScanText } from '../../src/utils/scan-text.js';
import { ResolvedServer } from '../../src/types/config.js';

const baseServer: ResolvedServer = {
  name: 'my-server',
  toolName: 'my-tool',
  configPath: '/tmp/config.json',
  command: 'npx',
  args: ['-y', 'some-package'],
  schema: {},
  description: 'A helpful server',
  env: {},
  disabled: false,
};

describe('buildScanText', () => {
  it('includes server name and description', () => {
    const text = buildScanText(baseServer);
    expect(text).toContain('my-server');
    expect(text).toContain('A helpful server');
  });

  it('tolerates an optional description (undefined becomes empty part)', () => {
    const text = buildScanText({ ...baseServer, description: undefined });
    expect(text).toContain('my-server');
  });

  it('collects string args from array form', () => {
    const text = buildScanText(baseServer);
    expect(text).toContain('-y');
    expect(text).toContain('some-package');
  });

  it('collects string args from record form', () => {
    const text = buildScanText({ ...baseServer, args: { flag: '-x', pkg: 'pkg-a' } as unknown as string[] });
    expect(text).toContain('-x');
    expect(text).toContain('pkg-a');
  });

  it('walks nested tool schemas so hidden descriptions are scanned', () => {
    const server: ResolvedServer = {
      ...baseServer,
      schema: {
        tools: [
          {
            name: 'read_file',
            description: 'Reads any file on disk',
            inputSchema: {
              type: 'object',
              properties: {
                path: { type: 'string', description: 'Absolute path to read' },
                mode: { type: 'string', enum: ['full', 'partial'] },
              },
            },
          },
        ],
      },
    };
    const text = buildScanText(server);
    expect(text).toContain('Reads any file on disk');
    expect(text).toContain('Absolute path to read');
    expect(text).toContain('full');
    expect(text).toContain('path');
  });

  it('drops empty parts instead of emitting blank lines', () => {
    const text = buildScanText({ ...baseServer, description: '', args: [] });
    expect(text.split('\n').every(line => line.length > 0)).toBe(true);
  });

  it('ignores non-string args entries', () => {
    const text = buildScanText({ ...baseServer, args: [123, 'ok'] as unknown as string[] });
    expect(text).not.toContain('123');
    expect(text).toContain('ok');
  });
});
