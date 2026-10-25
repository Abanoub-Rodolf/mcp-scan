import { ResolvedServer } from '../types/config.js';
import { Finding, FindingId } from '../types/scan-result.js';
import { Severity } from '../types/severity.js';
import { logger } from '../utils/logger.js';
import { fetchWithTimeout } from '../utils/fetch-with-timeout.js';
import { loadCveSnapshot } from '../utils/cve-snapshot.js';
import { OFFICIAL_SERVERS, TRUSTED_COMMUNITY_SERVERS } from '../data/official-servers.js';
import { KNOWN_MALICIOUS_PACKAGES } from '../data/known-malicious.js';
import { parseCvssVector } from 'vuln-vects';
import semver from 'semver';

interface NpmRegistryResponse {
  'dist-tags'?: Record<string, string>;
  time?: Record<string, string>;
  versions?: Record<string, unknown>;
}

interface OsvResponse {
  vulns?: OsvVuln[];
}

export interface OsvAffectedRangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface OsvAffected {
  package?: { ecosystem?: string; name?: string };
  ranges?: Array<{ type: string; events?: OsvAffectedRangeEvent[] }>;
  versions?: string[];
}

export interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string };
  affected?: OsvAffected[];
  fixed_in?: string[];
  references?: Array<{ type?: string; url?: string }>;
}

/**
 * Extracts a numeric CVSS score from OSV severity entries. Handles
 * CVSS v3 vectors, CVSS v4 vectors, and plain numeric scores; never
 * throws and never guesses - returns null when nothing is parseable
 * so the caller can fall back to qualitative severity.
 */
export function extractCvssScore(severities: Array<{ type: string; score: string }>): number | null {
  if (!Array.isArray(severities)) return null;
  for (const s of severities) {
    if (!s || typeof s.score !== 'string' || s.score.length === 0) continue;
    const numeric = parseFloat(s.score);
    if (!Number.isNaN(numeric) && String(numeric) === s.score.trim()) {
      return numeric; // plain numeric score, e.g. "9.8"
    }
    try {
      const parsed = parseCvssVector(s.score);
      if (parsed && typeof parsed.baseScore === 'number') return parsed.baseScore;
    } catch (_e) {
      // CVSS v4 vectors or unknown formats: fall through to the next entry
    }
  }
  return null;
}

const QUALITATIVE_SEVERITY: Record<string, Severity> = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MODERATE: 'MEDIUM',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
};

function vulnSeverityToFinding(severity: Severity): { id: FindingId; severity: Severity } {
  switch (severity) {
    case 'CRITICAL': return { id: 'known-vulnerability-critical', severity: 'CRITICAL' };
    case 'HIGH': return { id: 'known-vulnerability-high', severity: 'HIGH' };
    case 'MEDIUM': return { id: 'known-vulnerability-medium', severity: 'MEDIUM' };
    default: return { id: 'known-vulnerability-low', severity: 'LOW' };
  }
}

// npx/npm options whose value is the next arg, not the package.
const NPX_VALUE_OPTS = new Set([
    '--registry', '--cache', '--userconfig', '--prefix', '-w', '--workspace', '--loglevel', '--before',
  '--otp', '--tag', '--node-options', '--script-shell', '--proxy', '--https-proxy', '--cafile', '--include', '--shell', '-C', '--globalconfig', '--omit', '--fetch-timeout', '--fetch-retries',
  '--scope', '--auth-type', '--install-strategy', '--min-release-age', '--audit-level', '--ca', '--cert', '--key', '--cpu', '--os', '--libc',
  '--noproxy', '--local-address', '--user-agent', '--maxsockets', '--fetch-retry-mintimeout', '--fetch-retry-maxtimeout',
]);
// Flags that take no value. A dash flag in neither set might take one, so the
// package is then ambiguous and the riskiest candidate is graded.
export const NPX_BOOL_OPTS = new Set([
  '-y', '--yes', '--no', '--no-install', '-q', '--quiet', '--silent', '--verbose', '-d', '-f', '--force', '--offline',
  '--prefer-online', '--prefer-offline', '--no-audit', '--no-fund', '--ignore-scripts', '--legacy-peer-deps', '--json',
  '-g', '--global', '--workspaces', '-ws', '--include-workspace-root', '--if-present', '--dry-run', '--no-update-notifier',
  '--ignore-existing', '--no-progress', '--foreground-scripts', '--strict-peer-deps',
  '--audit', '--fund', '--timing', '--color', '--strict-ssl', '--usage', '--long', '--parseable', '--unicode', '--progress',
]);
// npm subcommands that run no package. npm resolves unique prefixes and
// aliases of exec/init too, so those are matched loosely below instead.
const NPM_NON_EXEC_SUBS = new Set([
  'install', 'i', 'in', 'ins', 'inst', 'add', 'ci', 'run', 'run-script', 'rum', 'urn', 'test', 't', 'tst', 'start', 'stop',
  'restart', 'view', 'info', 'v', 'ls', 'list', 'la', 'll', 'update', 'up', 'upgrade', 'uninstall', 'remove', 'rm', 'un',
  'publish', 'pack', 'audit', 'outdated', 'cache', 'config', 'set', 'get', 'login', 'logout', 'whoami', 'version', 'help',
  'link', 'ln', 'prune', 'dedupe', 'explain', 'why', 'doctor', 'fund', 'search', 's', 'se', 'find', 'pkg', 'prefix', 'root',
  'bin', 'repo', 'docs', 'home', 'bugs', 'rebuild', 'shrinkwrap', 'star', 'stars', 'unstar', 'team', 'token', 'unpublish',
  'hook', 'org', 'owner', 'access', 'adduser', 'completion', 'diff', 'edit', 'explore', 'query', 'sbom', 'ping', 'profile',
  'deprecate', 'dist-tag', 'find-dupes', 'install-test', 'it', 'install-ci-test', 'cit', 'sit',
]);
const isExecSub = (w: string) => w === 'x' || (w.length >= 2 && 'exec'.startsWith(w));
const isCreateSub = (w: string) => w === 'innit' || (w.length >= 2 && w !== 'in' && 'init'.startsWith(w)) || (w.length >= 2 && 'create'.startsWith(w));
const MAX_CANDIDATES = 4;
const MAX_PACKAGES = 32;

/** npm init/create <spec> runs create-<name>; scoped @s -> @s/create, @s/n -> @s/create-n. */
function createPackage(spec: string): string {
  const { name, versionSpec } = parsePackageSpec(spec);
  const v = versionSpec ? `@${versionSpec}` : '';
  if (name.startsWith('@')) {
    const [scope, rest] = name.split('/');
    return `${scope}/${rest ? `create-${rest}` : 'create'}${v}`;
  }
  return `create-${name}${v}`;
}

const isKnownPkg = (spec: string) => {
  const { name } = parsePackageSpec(spec);
  return OFFICIAL_SERVERS.has(name) || TRUSTED_COMMUNITY_SERVERS.has(name);
};

/**
 * Every package an npx/npm launch might run. Normally one. When an unknown
 * flag could be swallowing the next arg as its value, the real package is
 * ambiguous and up to four leading positionals that are valid package names
 * come back, so callers can grade all of them. With --package the named
 * packages are the answer and the first positional is only the bin.
 */
// npx.cmd on Windows, full paths and case-insensitive filesystems all run
// the same launcher, so compare the bare lowercase name.
export function launcher(command: unknown): string {
  return (typeof command === 'string' ? command : '').split(/[\\/]/).pop()!.replace(/\.(cmd|exe|bat|ps1)$/i, '').toLowerCase();
}

export function npxPackageCandidates(args: unknown, command?: string): string[] {
  const list = (Array.isArray(args) ? args : args && typeof args === 'object' ? Object.values(args) : [])
    .filter((a): a is string => typeof a === 'string');
  const cmd = launcher(command);
  const pkgs: string[] = [];
  const pos: string[] = [];
  let ambiguous = false;
  let sub = cmd !== 'npm';
  let create = false;
  let endOpts = false;
  for (let i = 0; i < list.length; i++) {
    const a = list[i];
    // npx options end at the first positional; anything after it is the
    // server's own args (-p is often a port there), unless a flag we do not
    // know may have eaten the package.
    if (pos.length > 0) {
      // npm exec, unlike npx, still reads --package after the bin
      if (cmd === 'npm' && !create && !endOpts) {
        if (a === '--') { endOpts = true; continue; }
        if (a.startsWith('--package=') || a.startsWith('--no-package=')) { pkgs.push(a.slice(a.indexOf('=') + 1)); continue; }
        if (a.startsWith('-p=')) { pkgs.push(a.slice(3)); continue; }
        if ((a === '--package' || a === '-p' || a === '--no-package') && i + 1 < list.length) { pkgs.push(list[++i]); continue; }
        if (NPX_VALUE_OPTS.has(a) || a === '-c' || a === '--call') { i++; continue; }
        if (!ambiguous) continue;
      }
      if (!ambiguous) { if (cmd === 'npm') continue; break; }
      // The unknown flag may have eaten the first positional, so --package
      // can still be live here. Keep scanning to the end for it; only the
      // positional candidates are capped.
      if (!create && !endOpts) {
        if (a === '--') { endOpts = true; continue; }
        if (a.startsWith('--package=') || a.startsWith('--no-package=')) { pkgs.push(a.slice(a.indexOf('=') + 1)); continue; }
        if (a.startsWith('-p=')) { pkgs.push(a.slice(3)); continue; }
        if ((a === '--package' || a === '-p' || a === '--no-package') && i + 1 < list.length) { pkgs.push(list[++i]); continue; }
      }
      if (a === '-c' || a === '--call' || NPX_VALUE_OPTS.has(a) || /^--@[^:]+:registry$/.test(a)) i++;
      else if (!a.startsWith('-') && pos.length < MAX_CANDIDATES) pos.push(a);
      continue;
    }
    if (!endOpts && a === '--') endOpts = true;
    else if (!endOpts && a.startsWith('-')) {
      if (a.startsWith('--package=') || a.startsWith('--no-package=')) pkgs.push(a.slice(a.indexOf('=') + 1));
      else if (a.startsWith('-p=')) pkgs.push(a.slice(3));
      else if ((a === '--package' || a === '-p' || a === '--no-package') && i + 1 < list.length) pkgs.push(list[++i]);
      // -c runs a command string, not a package: the AST scanner grades it,
      // and it must never reach a registry lookup.
      else if (a === '-c' || a === '--call') i++;
      else if (a.startsWith('--call=') || a.startsWith('-c=')) continue;
      else if (NPX_VALUE_OPTS.has(a) || /^--@[^:]+:registry$/.test(a)) i++;
      else if (!a.includes('=') && !NPX_BOOL_OPTS.has(a) && !a.startsWith('--no-')) ambiguous = true;
    } else if (!sub) {
      if (isExecSub(a)) sub = true;
      else if (isCreateSub(a)) sub = create = true;
      else if (NPM_NON_EXEC_SUBS.has(a)) return [];
      else if (!ambiguous) { sub = true; pos.push(a); }
      // else: the value of an unknown flag before the subcommand
    } else pos.push(a);
  }
  if (pkgs.length > 0) {
    // Risk first, so the cap can only ever drop allowlisted packages.
    const rank = (p: string) => KNOWN_MALICIOUS_PACKAGES.has(parsePackageSpec(p).name) ? 0 : isKnownPkg(p) ? 2 : 1;
    // After an unknown flag the positionals may still be what runs, so keep them.
    const all = ambiguous ? [...pkgs, ...pos.filter(c => !/^\.{0,2}\/|\s/.test(c))] : pkgs;
    return [...new Set(all)].sort((x, y) => rank(x) - rank(y)).slice(0, MAX_PACKAGES);
  }
  let cands = create ? pos.map(createPackage) : pos;
  if (ambiguous && cands.length > 1) {
    const valid = cands.filter(c => validatePackageName(c).valid);
    if (valid.length > 0) cands = valid;
  }
  return cands;
}

/**
 * The one package the single-package checks grade. With several candidates
 * the riskiest wins: known-malicious, then the first not on an allowlist.
 * scan.ts also grades the others, so a flag value can never hide a package.
 */
export function npxPackageArg(args: unknown, command?: string): string | undefined {
  const cands = npxPackageCandidates(args, command);
  if (cands.length <= 1) return cands[0];
  return cands.find(c => KNOWN_MALICIOUS_PACKAGES.has(parsePackageSpec(c).name))
    ?? cands.find(c => !isKnownPkg(c))
    ?? cands[0];
}

/**
 * Splits a package spec (as it appears in `npx <spec>` / `npm exec <spec>`)
 * into its registry name and version specifier. Handles scoped packages
 * (`@scope/name@1.2.3`) by skipping the leading `@` before looking for the
 * version-separating `@`. Returns versionSpec: null for unpinned specs
 * (`pkg`) and for the literal `latest` tag, since both resolve the same way.
 */
export function parsePackageSpec(spec: string): { name: string; versionSpec: string | null } {
  const isScoped = spec.startsWith('@');
  const rest = isScoped ? spec.slice(1) : spec;
  const atIndex = rest.indexOf('@');
  if (atIndex === -1) return { name: spec, versionSpec: null };
  const name = (isScoped ? '@' : '') + rest.slice(0, atIndex);
  const versionSpec = rest.slice(atIndex + 1);
  if (!versionSpec || versionSpec === 'latest') return { name, versionSpec: null };
  return { name, versionSpec };
}

const NPM_PACKAGE_NAME_RE = /^(?:@[a-z0-9-][a-z0-9-._~]*\/)?[a-z0-9][a-z0-9-._~]*$/;

/**
 * Validates an npm registry package name (lowercase, URL-safe, optional
 * @scope/, <=214 chars). Runs the input through parsePackageSpec first so
 * a spec with a pinned version (`pkg@1.2.3`) validates the bare name.
 */
export function validatePackageName(input: string): { valid: true; name: string } | { valid: false; error: string } {
  const { name } = parsePackageSpec(input);
  if (!name || name.length > 214 || !NPM_PACKAGE_NAME_RE.test(name)) {
    return { valid: false, error: `'${input}' is not a valid npm package name.` };
  }
  return { valid: true, name };
}

export type VersionMatch = true | false | 'unknown';

/**
 * Walks an OSV SEMVER range event list (introduced/fixed/last_affected/limit)
 * and decides whether `version` falls inside any of the affected intervals.
 * Mirrors OSV's documented range semantics: events are ordered, an
 * `introduced` opens an interval (0 means "since the beginning of time"),
 * and a `fixed` (exclusive), `last_affected` (inclusive), or `limit`
 * (exclusive) closes it. An interval left open by the data (no closing
 * event) is still affected today.
 */
function versionInSemverEvents(version: string, events: OsvAffectedRangeEvent[]): boolean {
  let introduced: string | null = null;
  for (const e of events) {
    if (e.introduced !== undefined) {
      introduced = e.introduced === '0' ? '0.0.0' : e.introduced;
      continue;
    }
    if (introduced === null || !semver.valid(introduced)) continue;
    if (e.fixed !== undefined) {
      if (semver.valid(e.fixed) && semver.gte(version, introduced) && semver.lt(version, e.fixed)) return true;
      introduced = null;
    } else if (e.last_affected !== undefined) {
      if (semver.valid(e.last_affected) && semver.gte(version, introduced) && semver.lte(version, e.last_affected)) return true;
      introduced = null;
    } else if (e.limit !== undefined) {
      if (semver.valid(e.limit) && semver.gte(version, introduced) && semver.lt(version, e.limit)) return true;
      introduced = null;
    }
  }
  if (introduced !== null && semver.valid(introduced) && semver.gte(version, introduced)) return true;
  return false;
}

/**
 * Determines whether a resolved package version actually falls inside an
 * OSV advisory's affected range - not just whether the package name
 * matches. Returns 'unknown' when the advisory carries no structured
 * version/range data to compare against, so the caller can avoid treating
 * an unmatchable advisory as a confirmed hit.
 */
export function matchVersionAgainstVuln(version: string, vuln: OsvVuln, packageName: string): VersionMatch {
  if (!semver.valid(version)) return 'unknown';
  const affectedEntries = vuln.affected || [];
  if (affectedEntries.length === 0) return 'unknown';

  let hasRangeData = false;
  for (const affected of affectedEntries) {
    if (affected.package?.name && affected.package.name !== packageName) continue;

    if (Array.isArray(affected.versions) && affected.versions.length > 0) {
      hasRangeData = true;
      if (affected.versions.includes(version)) return true;
    }

    for (const range of affected.ranges || []) {
      if (range.type !== 'SEMVER' || !Array.isArray(range.events)) continue;
      hasRangeData = true;
      if (versionInSemverEvents(version, range.events)) return true;
    }
  }

  return hasRangeData ? false : 'unknown';
}

/**
 * Resolves what version would actually be installed for a package spec:
 * an exact pin is used as-is, a semver range is resolved against the
 * registry's published versions, a dist-tag (`beta`, `next`, ...)
 * resolves through dist-tags, and an unpinned spec resolves to
 * dist-tags.latest. Returns version: null when resolution isn't
 * possible (registry lookup failed, tag unknown, or nothing satisfies
 * the range) - callers must not assume a vulnerable version, or a clean
 * one, in that case.
 */
export function resolveEffectiveVersion(
  versionSpec: string | null,
  distTags: Record<string, string> | undefined,
  publishedVersions: string[]
): { version: string | null; pinned: boolean } {
  if (versionSpec) {
    if (semver.valid(versionSpec)) {
      return { version: versionSpec, pinned: true };
    }
    if (semver.validRange(versionSpec)) {
      const max = publishedVersions.length > 0 ? semver.maxSatisfying(publishedVersions, versionSpec) : null;
      return { version: max, pinned: false };
    }
    const tagged = distTags?.[versionSpec];
    if (tagged && semver.valid(tagged)) {
      return { version: tagged, pinned: false };
    }
    // Unparseable version spec (e.g. a git URL, or an unknown tag) - can't resolve.
    return { version: null, pinned: false };
  }
  const latestVersion = distTags?.latest;
  if (latestVersion && semver.valid(latestVersion)) {
    return { version: latestVersion, pinned: false };
  }
  return { version: null, pinned: false };
}

/**
 * Deep audit of a package, either online or using a bundled snapshot.
 */
export async function scanPackageDeep(server: ResolvedServer, offline: boolean = false): Promise<Finding[]> {
  const findings: Finding[] = [];

  let packageSpec = '';
  const cmd = launcher(server.command);
  if (cmd === 'npx' || cmd === 'npm') {
    const pkgArg = npxPackageArg(server.args, server.command);
    if (pkgArg) packageSpec = pkgArg;
  }

  if (!packageSpec) return findings;

  const { name: packageName, versionSpec } = parsePackageSpec(packageSpec);

  if (offline) {
    return scanPackageOffline(packageName, versionSpec);
  }

  let latestVersion = '';
  let distTags: Record<string, string> | undefined;
  let publishedVersions: string[] = [];
  try {
    const res = await fetchWithTimeout(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`, {}, 8000);

    if (!res.ok) {
      logger.warn(`Failed to fetch package info for ${packageName} from npm registry.`);
    } else {
      const data = await res.json() as NpmRegistryResponse;
      distTags = data['dist-tags'];
      latestVersion = distTags?.latest || '';
      publishedVersions = data.versions ? Object.keys(data.versions) : [];
      if (data && typeof data === 'object' && data.time && typeof data.time.modified === 'string') {
        const lastModified = new Date(data.time.modified);
        const now = new Date();
        const diffMonths = (now.getTime() - lastModified.getTime()) / (1000 * 60 * 60 * 24 * 30);

        if (diffMonths > 6) {
          findings.push({
            id: 'stale-server',
            severity: 'HIGH',
            description: `npm package '${packageName}' has not been updated in over 6 months.`,
          });
        }
      }
    }
  } catch (_error) {
    logger.warn(`Network error fetching npm registry for ${packageName}. Switching to offline mode.`);
    return scanPackageOffline(packageName, versionSpec);
  }

  const { version: resolvedVersion, pinned } = resolveEffectiveVersion(versionSpec, distTags, publishedVersions);
  const versionResolutionFailed = resolvedVersion === null;
  if (versionResolutionFailed) {
    logger.warn(`Could not resolve an installable version for '${packageSpec}'; vulnerability matching will be degraded to an unresolved-version finding.`);
  }

  // OSV.dev integration
  try {
    const osvRes = await fetchWithTimeout('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package: { name: packageName, ecosystem: 'npm' } }),
    }, 5000);

    if (!osvRes.ok) {
      logger.warn(`OSV.dev API request failed for ${packageName}.`);
      return findings;
    }

    const osvData = await osvRes.json() as OsvResponse;
    const vulns: OsvVuln[] = osvData.vulns || [];

    if (vulns.length > 0) {
      const unresolvedVulnIds: string[] = [];

      for (const vuln of vulns) {
        const matchStatus: VersionMatch = resolvedVersion === null
          ? 'unknown'
          : matchVersionAgainstVuln(resolvedVersion, vuln, packageName);

        if (matchStatus === false) {
          // Resolved version is confirmed outside the advisory's affected
          // range: this is exactly the false-positive this scanner used to
          // produce (name-only match, version ignored). Do not fire.
          continue;
        }

        if (matchStatus === 'unknown') {
          // Either the version couldn't be resolved, or the advisory has
          // no structured range/versions data to compare against. Either
          // way we cannot confirm the resolved version is affected, so we
          // must not report it as a confirmed vulnerability - collect it
          // for a single lower-severity "unresolved" finding instead.
          unresolvedVulnIds.push(vuln.id);
          continue;
        }

        // matchStatus === true: resolved version is confirmed inside the
        // advisory's affected range. Fire at full severity.
        let cvssScore: number | null = null;
        let severityFromDb: Severity | undefined;
        if (vuln.severity && Array.isArray(vuln.severity)) {
          cvssScore = extractCvssScore(vuln.severity);
        }
        const dbSeverity = vuln.database_specific?.severity?.toUpperCase();
        if (dbSeverity && dbSeverity in QUALITATIVE_SEVERITY) {
          severityFromDb = QUALITATIVE_SEVERITY[dbSeverity];
        }

        // Never silently drop a known vulnerability: if no score and no
        // qualitative severity is available, report it as MEDIUM rather
        // than producing a false negative.
        const effectiveSeverity: Severity =
          cvssScore === null
            ? (severityFromDb ?? 'MEDIUM')
            : cvssScore >= 9.0
              ? 'CRITICAL'
              : cvssScore >= 7.0
                ? 'HIGH'
                : cvssScore >= 4.0
                  ? 'MEDIUM'
                  : 'LOW';

        const { id, severity } = vulnSeverityToFinding(effectiveSeverity);
        findings.push({
          id,
          severity,
          description: `${effectiveSeverity} vulnerability found in '${packageName}@${resolvedVersion}': ${vuln.id} - ${vuln.summary || vuln.details || 'no summary available'}`,
          fixRecommendation: effectiveSeverity === 'LOW' ? 'Review and patch when convenient.' : `Upgrade package or remove it.`,
          fixable: true,
        });
      }

      if (unresolvedVulnIds.length > 0) {
        const reason = versionResolutionFailed
          ? `the installed version of '${packageName}' could not be resolved (spec: '${versionSpec ?? 'unpinned/latest'}')`
          : `the advisory data for these does not specify a version range to check '${packageName}@${resolvedVersion}' against`;
        findings.push({
          id: 'known-vulnerability-unresolved',
          severity: 'LOW',
          description: `Package '${packageName}' has ${unresolvedVulnIds.length} known advisor${unresolvedVulnIds.length === 1 ? 'y' : 'ies'} (${unresolvedVulnIds.join(', ')}) that could not be confirmed against the resolved version: ${reason}. This is not a confirmed vulnerability - verify manually.`,
          fixRecommendation: `Pin '${packageName}' to an exact version and re-scan to get a confirmed verdict.`,
          fixable: false,
        });
      }
    }

    // Upgrade Advisor Logic - only meaningful for a pinned version; an
    // unpinned/`latest` spec always resolves to latestVersion already.
    if (latestVersion && pinned && resolvedVersion && semver.valid(resolvedVersion) && semver.valid(latestVersion) && semver.gt(latestVersion, resolvedVersion)) {
      const fixedVersions: string[] = [];
      for (const v of vulns) {
        for (const a of v.affected || []) {
          for (const r of a.ranges || []) {
            for (const e of r.events || []) {
              if (e.fixed && semver.valid(e.fixed)) fixedVersions.push(e.fixed);
            }
          }
        }
        if (v.fixed_in) fixedVersions.push(...v.fixed_in.filter(fv => semver.valid(fv)));
      }
      const resolvesVulns = fixedVersions.some(fv => semver.gte(latestVersion, fv));

      findings.push({
        id: 'upgrade-available',
        severity: 'INFO',
        description: `A newer version of '${packageName}' is available: ${resolvedVersion} → ${latestVersion}.`,
        fixRecommendation: resolvesVulns
          ? `UPGRADE RECOMMENDED: Version ${latestVersion} may resolve known vulnerabilities. Run: npm install ${packageName}@${latestVersion}`
          : `Run: npm install ${packageName}@${latestVersion} to update.`,
        fixable: true
      });
    }

  } catch (_error) {
    logger.warn(`OSV.dev API request for ${packageName} failed or timed out. Switching to offline snapshot.`);
    return [...findings, ...scanPackageOffline(packageName, versionSpec)];
  }

  return findings;
}

let staleSnapshotWarned = false;

function scanPackageOffline(packageName: string, versionSpec: string | null): Finding[] {
  const findings: Finding[] = [];
  try {
    const snapshot = loadCveSnapshot();
    if (!snapshot) return findings;

    const data = snapshot.raw;

    // Check if snapshot is stale (> 30 days). Missing/invalid dates yield
    // NaN here, which never trips the warning - same as the untyped
    // original.
    const updatedAt = new Date(data.updatedAt ?? NaN);
    const now = new Date();
    const diffDays = (now.getTime() - updatedAt.getTime()) / (1000 * 60 * 60 * 24);
    if (diffDays > 30 && !staleSnapshotWarned) {
      // Once per process, not per server. The update script only exists in
      // a source checkout, so installed users are told to upgrade instead.
      staleSnapshotWarned = true;
      logger.warn(`CVE snapshot is ${Math.floor(diffDays)} days old. Upgrade mcp-scan to get a newer one.`);
    }

    const pkgData = data.packages?.[packageName];
    if (pkgData && pkgData.vulns && pkgData.vulns.length > 0) {
      // The offline snapshot only records vulnerabilities observed against
      // one specific version (pkgData.version) at snapshot time - it has
      // no per-advisory range data. We can only confirm a match when the
      // config pins that exact same version; anything else (unpinned, or
      // pinned to a different version) is unresolved against this data.
      const pinnedVersion = versionSpec && semver.valid(versionSpec) ? versionSpec : null;
      const confirmedMatch = pinnedVersion !== null && pkgData.version !== undefined && pinnedVersion === pkgData.version;

      if (confirmedMatch) {
        for (const vuln of pkgData.vulns) {
          const severity = String(vuln.severity || 'MEDIUM').toUpperCase() as Severity;
          const { id } = vulnSeverityToFinding(severity);
          findings.push({
            id,
            severity,
            description: `Bundled snapshot found ${severity} vulnerability in '${packageName}@${pinnedVersion}': ${vuln.id} - ${vuln.summary || 'no summary available'}`,
            fixRecommendation: `Upgrade package or remove it. (Offline info)`
          });
        }
      } else {
        const ids = pkgData.vulns.map(v => v.id || 'unknown').join(', ');
        findings.push({
          id: 'known-vulnerability-unresolved',
          severity: 'LOW',
          description: `Package '${packageName}' has ${pkgData.vulns.length} known advisor${pkgData.vulns.length === 1 ? 'y' : 'ies'} (${ids}) in the offline snapshot (recorded against version ${pkgData.version ?? 'unknown'}), but the resolved version could not be confirmed against it while offline. This is not a confirmed vulnerability - verify manually.`,
          fixRecommendation: `Pin '${packageName}' to an exact version and re-scan online to get a confirmed verdict.`,
          fixable: false,
        });
      }
    }
  } catch (error) {
    // A snapshot of an unexpected shape used to read as "no known
    // vulnerabilities". Say the check did not finish.
    // stderr, not logger.warn: --json and --ci silence the logger, and CI is where this must show.
    // Once per message: a bad snapshot fails for every package, on every watch rescan.
    // The name comes from the scanned config, so control characters never reach the terminal.
    const name = packageName.replace(/[\x00-\x1f\x7f]/g, '?');
    const msg = `Offline CVE check for '${name}' failed (${error instanceof Error ? error.message : String(error)}); its vulnerability results may be incomplete.`;
    if (!warnedOffline.has(msg)) {
      if (warnedOffline.size >= 200) warnedOffline.clear();
      warnedOffline.add(msg);
      process.stderr.write(`mcp-scan: ${msg}\n`);
    }
  }
  return findings;
}
const warnedOffline = new Set<string>();
