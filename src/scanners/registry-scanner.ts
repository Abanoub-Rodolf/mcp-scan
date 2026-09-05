import { ResolvedServer } from '../types/config.js';
import { Finding } from '../types/scan-result.js';
import { KNOWN_MALICIOUS_PACKAGES } from '../data/known-malicious.js';
import { OFFICIAL_SERVERS, TRUSTED_COMMUNITY_SERVERS } from '../data/official-servers.js';
import { parsePackageSpec, resolveEffectiveVersion } from './package-scanner.js';
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
// the registry twice for the same thing.
const versionDocCache = new Map<string, Promise<NpmVersionDoc | null>>();
const packumentCache = new Map<string, Promise<NpmPackument | null>>();

function fetchPackument(packageName: string): Promise<NpmPackument | null> {
  let pending = packumentCache.get(packageName);
  if (!pending) {
    pending = (async () => {
      const res = await fetchWithTimeout(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`, {}, 8000);
      if (!res.ok) return null;
      return await res.json() as NpmPackument;
    })();
    packumentCache.set(packageName, pending);
  }
  return pending;
}

function fetchVersionDoc(packageName: string, version: string): Promise<NpmVersionDoc | null> {
  const cacheKey = `${packageName}@${version}`;

  let pending = versionDocCache.get(cacheKey);
  if (!pending) {
    pending = (async () => {
      const res = await fetchWithTimeout(
        `https://registry.npmjs.org/${encodeURIComponent(packageName)}/${encodeURIComponent(version)}`,
        {},
        8000
      );
      if (!res.ok) return null;
      return await res.json() as NpmVersionDoc;
    })();
    versionDocCache.set(cacheKey, pending);
  }
  return pending;
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

export async function scanRegistry(server: ResolvedServer, offline: boolean = false): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Try to determine package name from command or args
  let packageSpec = '';
  if (server.command === 'npx' || server.command === 'npm') {
    // npx -y @modelcontextprotocol/server-postgres
    const pkgArg = (Array.isArray(server.args) ? server.args : (server.args ? Object.values(server.args) : [])).find(a => typeof a === 'string' && !a.startsWith('-'));
    if (pkgArg) packageSpec = pkgArg as string;
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
  } else if (!packageName.startsWith('@modelcontextprotocol/') && (server.command === 'npx' || server.command === 'npm')) {
    const isScoped = packageName.startsWith('@');

    let predicateType: string | undefined;
    if (!offline) {
      try {
        const resolvedVersion = await resolveVersionForProvenanceCheck(packageName, versionSpec);
        const doc = resolvedVersion ? await fetchVersionDoc(packageName, resolvedVersion) : null;
        predicateType = doc?.dist?.attestations?.provenance?.predicateType;
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
