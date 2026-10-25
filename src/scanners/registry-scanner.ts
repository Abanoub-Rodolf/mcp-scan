import { ResolvedServer } from '../types/config.js';
import { Finding } from '../types/scan-result.js';
import { KNOWN_MALICIOUS_PACKAGES } from '../data/known-malicious.js';
import { OFFICIAL_SERVERS, TRUSTED_COMMUNITY_SERVERS } from '../data/official-servers.js';
import { parsePackageSpec, resolveEffectiveVersion, npxPackageArg, NPX_BOOL_OPTS, launcher } from './package-scanner.js';
import { fetchWithTimeout } from '../utils/fetch-with-timeout.js';
import { logger } from '../utils/logger.js';
import semver from 'semver';

interface NpmVersionDoc {
  dist?: {
    attestations?: { provenance?: { predicateType?: string } };
    signatures?: Array<{ keyid?: string; sig?: string }>;
  };
}

interface NpmPackument {
  'dist-tags'?: Record<string, string>;
  versions?: Record<string, unknown>;
}

// A scan run often resolves the same package for several server entries
// (or several tools pointing at the same server). Memoize the registry
// lookups per package+version for the life of the process so we don't hit
// the registry twice for the same thing. A rejected lookup is evicted
// right away so a transient failure doesn't poison every later reference
// to the same package in this run.
const versionDocCache = new Map<string, Promise<NpmVersionDoc | null>>();
const packumentCache = new Map<string, Promise<NpmPackument | null>>();

function cached<T>(cache: Map<string, Promise<T | null>>, key: string, fetcher: () => Promise<T | null>): Promise<T | null> {
  let pending = cache.get(key);
  if (!pending) {
    pending = fetcher();
    pending.catch(() => cache.delete(key));
    cache.set(key, pending);
  }
  return pending;
}

function fetchPackument(packageName: string): Promise<NpmPackument | null> {
  return cached(packumentCache, packageName, async () => {
    const res = await fetchWithTimeout(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`, {}, 8000);
    if (!res.ok) return null;
    return await res.json() as NpmPackument;
  });
}

function fetchVersionDoc(packageName: string, version: string): Promise<NpmVersionDoc | null> {
  return cached(versionDocCache, `${packageName}@${version}`, async () => {
    const res = await fetchWithTimeout(
      `https://registry.npmjs.org/${encodeURIComponent(packageName)}/${encodeURIComponent(version)}`,
      {},
      8000
    );
    if (!res.ok) return null;
    return await res.json() as NpmVersionDoc;
  });
}

/**
 * Resolves a package spec to the concrete version whose registry doc
 * should be checked for provenance. An exact pin and an unpinned/`latest`
 * spec resolve without a packument fetch; a range or a non-latest
 * dist-tag needs the full packument to resolve against. Returns null
 * when resolution isn't possible - the caller must not fall back to
 * checking latest's provenance in that case.
 */
async function resolveVersionForProvenanceCheck(packageName: string, versionSpec: string | null): Promise<string | null> {
  if (!versionSpec) return 'latest';
  if (semver.valid(versionSpec)) return versionSpec;

  const packument = await fetchPackument(packageName);
  if (!packument) return null;
  const publishedVersions = packument.versions ? Object.keys(packument.versions) : [];
  const { version } = resolveEffectiveVersion(versionSpec, packument['dist-tags'], publishedVersions);
  return version;
}

// registry.yarnpkg.com is a CNAME for the npm registry.
const DEFAULT_REGISTRY_HOSTS = new Set(['registry.npmjs.org', 'registry.npmjs.com', 'registry.yarnpkg.com']);

// npm's argv parser (nopt) takes any unique prefix of a flag name, so
// --reg=x sets the registry. 3 chars is the shortest unique prefix.
// npm's env reader takes exact names only, so env keys skip the prefix rule.
export const isRegistryKey = (k: string, exact = false) => /^@[^:]+:registry$/i.test(k)
  || (exact ? k.toLowerCase() === 'registry' : k.length >= 3 && 'registry'.startsWith(k.toLowerCase()));
// These load an .npmrc whose registry line we can't see from the config.
// Shortest prefix npm leaves unambiguous for each (--global wins --globa).
const CONFIG_FILE_KEYS: Record<string, number> = { userconfig: 5, globalconfig: 7, prefix: 5 };
// Flags take unique prefixes like the registry key; env keys must be exact.
export const configKey = (k: string, exact = false) => Object.keys(CONFIG_FILE_KEYS).find(c => exact ? c === k.toLowerCase() : k.length >= CONFIG_FILE_KEYS[c] && c.startsWith(k.toLowerCase()));

type Override = { url: string; scope?: string; file?: boolean; key?: string };

// Registry overrides an npx or npm exec launch would honor, from its flags
// and its env. `scope` is set for `@scope:registry` overrides, `file` when
// the registry comes from a config file instead.
function registryOverrides(server: ResolvedServer, cmd: string): Override[] {
  const out: Override[] = [];
  const add = (key: string, value: string | undefined, exact = false) => {
    const url = value?.trim();
    if (!url) return;
    let o: Override | undefined;
    if (isRegistryKey(key, exact)) o = { url, scope: /^(@[^:]+):/.exec(key)?.[1] };
    else if (configKey(key, exact)) o = { url, file: true, key: configKey(key, exact) };
    if (o && !out.some(r => r.url === o!.url && r.scope === o!.scope && r.key === o!.key)) out.push(o);
  };
  const raw = server.args;
  const args = (Array.isArray(raw) ? raw : raw && typeof raw === 'object' ? Object.values(raw) : [])
    .filter((a): a is string => typeof a === 'string');
  // npx hands everything after the package to the package itself, so a
  // server's own --registry (often a container registry) is not npm's.
  // npm exec keeps parsing its flags past the first positional.
  // npx-cli hands the arg after any non-boolean flag to that flag, so a
  // positional there is a value, not the package.
  let valued = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') break;
    if (!a.startsWith('-')) {
      if (cmd === 'npx' && !valued) break;
      valued = false;
      continue;
    }
    // -yq style bundles are short booleans.
    valued = !a.includes('=') && !NPX_BOOL_OPTS.has(a) && !a.startsWith('--no-') && !/^-[a-z]{2,}$/i.test(a);
    const key = a.replace(/^--?/, '');
    const eq = key.indexOf('=');
    if (eq > 0) add(key.slice(0, eq), key.slice(eq + 1));
    else if ((isRegistryKey(key) || configKey(key)) && args[i + 1] !== undefined && !args[i + 1].startsWith('-')) { add(key, args[++i]); valued = false; }
  }
  for (const [k, v] of Object.entries(server.env ?? {})) {
    const m = /^npm_config_(.+)$/i.exec(k);
    if (m && typeof v === 'string') add(m[1], v, true);
  }
  return out;
}

function registryHost(url: string): string {
  try { return new URL(url).hostname.toLowerCase(); } catch (_e) { return url; }
}

export async function scanRegistry(server: ResolvedServer, offline: boolean = false): Promise<Finding[]> {
  const findings: Finding[] = [];

  const cmd = launcher(server.command);
  const custom = cmd === 'npx' || cmd === 'npm'
    // Plain http to the real npm host is still open to tampering in transit.
    ? registryOverrides(server, cmd).filter(r => r.file || /^http:\/\//i.test(r.url) || !DEFAULT_REGISTRY_HOSTS.has(registryHost(r.url)))
    : [];
  for (const r of custom) {
    if (r.file) {
      // --prefix moves the default globalconfig to <prefix>/etc/npmrc.
      const prefix = r.key === 'prefix';
      findings.push({
        id: 'custom-registry',
        severity: prefix ? 'LOW' : 'MEDIUM',
        description: prefix
          ? `Server sets npm's prefix to ${r.url}, so npm reads ${r.url}/etc/npmrc, which can set the registry. mcp-scan can't see that file's contents.`
          : `Server points npm at the config ${r.url}, which can set the registry it installs from. mcp-scan can't see that file's contents.`,
        fixRecommendation: prefix
          ? `Remove the prefix override, or confirm ${r.url}/etc/npmrc only names registries you control.`
          : `Remove the config override, or confirm ${r.url} only names registries you control.`,
      });
      continue;
    }
    const plain = /^http:\/\//i.test(r.url);
    const target = r.scope ? `${r.scope} packages` : 'the package';
    findings.push({
      id: 'custom-registry',
      severity: plain ? 'HIGH' : 'MEDIUM',
      description: plain
        ? `Server fetches ${target} from ${r.url} over plain http, so anyone on the network path can swap the code it runs.`
        : `Server fetches ${target} from ${registryHost(r.url)}, not the npm registry. Whoever runs that registry decides what code this server runs, whatever the package name.`,
      fixRecommendation: `Remove the registry override, or confirm ${registryHost(r.url)} is a registry you control and pin an exact version.`,
    });
  }

  // Try to determine package name from command or args
  let packageSpec = '';
  if (cmd === 'npx' || cmd === 'npm') {
    // npx -y @modelcontextprotocol/server-postgres
    const pkgArg = npxPackageArg(server.args, server.command);
    if (pkgArg) packageSpec = pkgArg;
  } else {
    packageSpec = server.command || '';
  }

  // Guard: no package name means nothing to scan
  if (!packageSpec) return findings;

  const { name: packageName, versionSpec } = parsePackageSpec(packageSpec);

  if (KNOWN_MALICIOUS_PACKAGES.has(packageName)) {
    findings.push({
      id: 'known-malicious',
      severity: 'CRITICAL',
      description: `Package '${packageName}' is on the known malicious blocklist.`,
      fixRecommendation: `Remove this server immediately.`,
      fixable: false
    });
  } else if (custom.some(r => !r.scope || packageName.startsWith(`${r.scope}/`))) {
    // The name allowlists and the npmjs provenance lookup describe the npm
    // registry's copy of this package, not the one actually installed.
    return findings;
  } else if (OFFICIAL_SERVERS.has(packageName)) {
    findings.push({
      id: 'official-server',
      severity: 'INFO',
      description: `Server '${packageName}' is an official @modelcontextprotocol package.`,
    });
  } else if (TRUSTED_COMMUNITY_SERVERS.has(packageName)) {
    findings.push({
      id: 'trusted-community-server',
      severity: 'INFO',
      description: `Server '${packageName}' is a widely trusted community package.`,
    });
  } else if (!packageName.startsWith('@modelcontextprotocol/') && (cmd === 'npx' || cmd === 'npm')) {
    const isScoped = packageName.startsWith('@');

    let predicateType: string | undefined;
    if (!offline) {
      try {
        const resolvedVersion = await resolveVersionForProvenanceCheck(packageName, versionSpec);
        const doc = resolvedVersion ? await fetchVersionDoc(packageName, resolvedVersion) : null;
        const rawPredicateType = doc?.dist?.attestations?.provenance?.predicateType;
        predicateType = typeof rawPredicateType === 'string' && rawPredicateType.length > 0 ? rawPredicateType : undefined;
      } catch (_error) {
        logger.warn(`Registry: provenance lookup for '${packageName}' failed or timed out. Falling back to unverified-source check.`);
      }
    }

    if (predicateType) {
      findings.push({
        id: 'provenance-verified',
        severity: 'INFO',
        description: `Package '${packageName}' was published from a build pipeline with a signed provenance statement (${predicateType}).`,
      });
    } else {
      findings.push({
        id: 'unverified-source',
        severity: isScoped ? 'LOW' : 'MEDIUM',
        description: isScoped
          ? `Server '${packageName}' is a scoped package from an unverified publisher.`
          : `Server '${packageName}' is an unscoped package from an unverified source (typosquatting risk).`,
        fixRecommendation: `Verify the publisher of '${packageName}' on npmjs.com before trusting this server, or ask the maintainer to publish with npm provenance (npm publish --provenance from GitHub Actions or GitLab CI) so mcp-scan can confirm it automatically.`,
      });
    }
  }

  return findings;
}
