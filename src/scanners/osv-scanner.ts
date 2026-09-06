import semver from 'semver';
import { Finding } from '../types/scan-result.js';
import { Severity } from '../types/severity.js';
import { logger } from '../utils/logger.js';
import { fetchWithTimeout } from '../utils/fetch-with-timeout.js';
import { extractCvssScore, matchVersionAgainstVuln, resolveEffectiveVersion, OsvVuln } from './package-scanner.js';

// scanPackageDeep already checks a target package's own name against OSV;
// this scanner covers the gap the campaign was actually named after: the
// package's *dependency tree*. A vulnerable transitive dep (e.g. an old
// lodash pulled in by an MCP server) never shows up in a name-only check
// against the top-level package.

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns';
const BATCH_CHUNK_SIZE = 100;
const VULN_FETCH_CONCURRENCY = 8;
const MAX_RETRIES = 3;
const BASE_BACKOFF_MS = 500;

export interface ResolvedDependency {
  name: string;
  version: string;
}

export interface PackageJsonLike {
  dependencies?: Record<string, string>;
}

// Minimal shape covering both npm lockfile v1 ("dependencies") and v2/v3
// ("packages", keyed "node_modules/<name>") formats.
export interface LockfileLike {
  dependencies?: Record<string, { version?: string }>;
  packages?: Record<string, { version?: string }>;
}

const QUALITATIVE_SEVERITY: Record<string, Severity> = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MODERATE: 'MEDIUM',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function chunk<T>(items: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += size) chunks.push(items.slice(i, i + size));
  return chunks;
}

async function runPool<T, R>(items: T[], limit: number, worker: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  async function runNext(): Promise<void> {
    const i = next++;
    if (i >= items.length) return;
    results[i] = await worker(items[i]);
    await runNext();
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, runNext));
  return results;
}

/**
 * fetch() that retries on 429 and 5xx with exponential backoff. Returns
 * null (never throws) once retries are exhausted, so one flaky chunk
 * degrades the scan instead of aborting the whole campaign run.
 */
async function fetchWithBackoff(url: string, init: RequestInit, label: string): Promise<Response | null> {
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    let res: Response;
    try {
      res = await fetchWithTimeout(url, init, 15000);
    } catch (err) {
      if (attempt === MAX_RETRIES) {
        logger.warn(`OSV request failed for ${label}: ${err instanceof Error ? err.message : String(err)}`);
        return null;
      }
      await sleep(BASE_BACKOFF_MS * 2 ** attempt);
      continue;
    }
    if (res.ok) return res;
    if ((res.status === 429 || res.status >= 500) && attempt < MAX_RETRIES) {
      const retryAfter = Number(res.headers.get('retry-after'));
      const backoff = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : BASE_BACKOFF_MS * 2 ** attempt;
      await sleep(backoff);
      continue;
    }
    logger.warn(`OSV request for ${label} returned ${res.status}.`);
    return null;
  }
  return null;
}

/**
 * Resolves the version npm would actually install for each direct
 * dependency: a shipped lockfile wins (it records what was actually
 * installed), otherwise each range is resolved against the registry's
 * published versions via the same logic package-scanner.ts uses for the
 * top-level package.
 */
export async function resolveDependencies(
  pkgJson: PackageJsonLike,
  lockfile?: LockfileLike | null
): Promise<ResolvedDependency[]> {
  const direct = Object.entries(pkgJson.dependencies ?? {});
  if (direct.length === 0) return [];

  const lockfileVersion = (name: string): string | null => {
    if (!lockfile) return null;
    const fromPackages = lockfile.packages?.[`node_modules/${name}`]?.version;
    if (fromPackages) return fromPackages;
    const fromDeps = lockfile.dependencies?.[name]?.version;
    return fromDeps ?? null;
  };

  return runPool(direct, VULN_FETCH_CONCURRENCY, async ([name, range]) => {
    const locked = lockfileVersion(name);
    if (locked) return { name, version: locked };

    if (semver.valid(range)) return { name, version: range };

    try {
      const res = await fetchWithTimeout(`https://registry.npmjs.org/${encodeURIComponent(name)}`, {}, 8000);
      if (!res.ok) return null;
      const data = (await res.json()) as { 'dist-tags'?: Record<string, string>; versions?: Record<string, unknown> };
      const publishedVersions = data.versions ? Object.keys(data.versions) : [];
      const { version } = resolveEffectiveVersion(range, data['dist-tags'], publishedVersions);
      return version ? { name, version } : null;
    } catch (err) {
      logger.warn(`Failed to resolve dependency version for ${name}@${range}: ${err instanceof Error ? err.message : String(err)}`);
      return null;
    }
  }).then((results) => results.filter((r): r is ResolvedDependency => r !== null));
}

export interface OsvBatchResult {
  vulnIdsByDep: string[][];
  // Dependency names whose chunk never got a usable response after
  // retries - these must not read as "no vulnerabilities found", since
  // the query for them never actually completed.
  failedDepNames: string[];
}

/**
 * Queries OSV's batch endpoint (id + modified only per the documented
 * response shape) in chunks of 100, returning the vuln ids found for
 * each dependency at the same index as the input array.
 */
export async function queryOsvBatch(deps: ResolvedDependency[]): Promise<OsvBatchResult> {
  const vulnIdsByDep: string[][] = deps.map(() => []);
  const failedDepNames: string[] = [];
  const chunks = chunk(deps.map((d, i) => ({ d, i })), BATCH_CHUNK_SIZE);

  for (const c of chunks) {
    const body = JSON.stringify({
      queries: c.map(({ d }) => ({ package: { name: d.name, ecosystem: 'npm' }, version: d.version })),
    });
    const res = await fetchWithBackoff(OSV_BATCH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    }, `querybatch (${c.length} deps)`);
    if (!res) {
      failedDepNames.push(...c.map(({ d }) => d.name));
      continue;
    }

    let results: Array<{ vulns?: Array<{ id: string }> }>;
    try {
      const data = (await res.json()) as { results?: Array<{ vulns?: Array<{ id: string }> }> };
      results = data.results ?? [];
    } catch (err) {
      // A malformed/non-JSON 200 response must degrade the same as a
      // failed request - not throw out of the whole campaign scan.
      logger.warn(`Failed to parse querybatch response: ${err instanceof Error ? err.message : String(err)}`);
      failedDepNames.push(...c.map(({ d }) => d.name));
      continue;
    }

    results.forEach((entry, idx) => {
      const { i } = c[idx];
      vulnIdsByDep[i] = (entry.vulns ?? []).map((v) => v.id);
    });
    // OSV documents pagination past 1000 vulns for one query / 3000 for
    // the whole batch; a shorter `results` array than the chunk means some
    // queries in this chunk got no answer at all - those must count as
    // failed, not as "queried, zero vulnerabilities."
    if (results.length < c.length) {
      failedDepNames.push(...c.slice(results.length).map(({ d }) => d.name));
    }
  }

  return { vulnIdsByDep, failedDepNames };
}

export interface VulnDetailsResult {
  found: Map<string, OsvVuln>;
  // ids querybatch confirmed exist for a dependency, but whose full
  // advisory (severity, affected ranges) could not be hydrated - must not
  // be silently dropped, since querybatch already proved a vuln is there.
  failedIds: string[];
}

/**
 * Hydrates vuln ids into full advisory records via GET /v1/vulns/{id} -
 * querybatch only returns id+modified. Deduplicated and pooled, since the
 * same CVE (e.g. a lodash prototype pollution) recurs across many
 * dependents in one campaign run.
 */
export async function fetchVulnDetails(ids: string[]): Promise<VulnDetailsResult> {
  const unique = [...new Set(ids)];
  const found = new Map<string, OsvVuln>();
  const failedIds: string[] = [];

  await runPool(unique, VULN_FETCH_CONCURRENCY, async (id) => {
    const res = await fetchWithBackoff(`${OSV_VULN_URL}/${encodeURIComponent(id)}`, {}, id);
    if (!res) {
      failedIds.push(id);
      return;
    }
    try {
      const vuln = (await res.json()) as OsvVuln;
      found.set(id, vuln);
    } catch (err) {
      failedIds.push(id);
      logger.warn(`Failed to parse OSV advisory ${id}: ${err instanceof Error ? err.message : String(err)}`);
    }
  });

  return { found, failedIds };
}

function severityFromVuln(vuln: OsvVuln): Severity {
  const cvssScore = vuln.severity ? extractCvssScore(vuln.severity) : null;
  const dbSeverity = vuln.database_specific?.severity?.toUpperCase();
  const severityFromDb = dbSeverity && dbSeverity in QUALITATIVE_SEVERITY ? QUALITATIVE_SEVERITY[dbSeverity] : undefined;
  if (cvssScore === null) return severityFromDb ?? 'MEDIUM';
  if (cvssScore >= 9.0) return 'CRITICAL';
  if (cvssScore >= 7.0) return 'HIGH';
  if (cvssScore >= 4.0) return 'MEDIUM';
  return 'LOW';
}

function findingIdForSeverity(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL': return 'dependency-known-vulnerability-critical';
    case 'HIGH': return 'dependency-known-vulnerability-high';
    case 'MEDIUM': return 'dependency-known-vulnerability-medium';
    default: return 'dependency-known-vulnerability-low';
  }
}

function advisoryUrl(vuln: OsvVuln): string {
  const advisory = (vuln.references ?? []).find((r) => r.type === 'ADVISORY' && r.url);
  return advisory?.url ?? (vuln.references ?? []).find((r) => r.url)?.url ?? `https://osv.dev/vulnerability/${vuln.id}`;
}

/** Renders the SEMVER range(s) for `packageName` as ">=introduced <fixed" text. */
function affectedRangeText(vuln: OsvVuln, packageName: string): string {
  const parts: string[] = [];
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.name && affected.package.name !== packageName) continue;
    for (const range of affected.ranges ?? []) {
      if (range.type !== 'SEMVER' || !range.events) continue;
      let introduced: string | null = null;
      for (const event of range.events) {
        if (event.introduced !== undefined) {
          introduced = event.introduced === '0' ? '0' : event.introduced;
          continue;
        }
        const upper = event.fixed ?? event.last_affected ?? event.limit;
        if (upper !== undefined) {
          const op = event.last_affected !== undefined ? '<=' : '<';
          parts.push(`>=${introduced ?? '0'} ${op}${upper}`);
          introduced = null;
        }
      }
      if (introduced !== null) parts.push(`>=${introduced}`);
    }
  }
  return parts.length > 0 ? parts.join('; ') : 'unspecified';
}

function fixedVersionText(vuln: OsvVuln, packageName: string): string | null {
  const fixed: string[] = [];
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.name && affected.package.name !== packageName) continue;
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) fixed.push(event.fixed);
      }
    }
  }
  if (vuln.fixed_in) fixed.push(...vuln.fixed_in);
  return fixed.length > 0 ? [...new Set(fixed)].join(', ') : null;
}

/**
 * Full dependency-CVE pass for one package: resolves the dependency tree,
 * batch-queries OSV, hydrates matched advisories, and confirms each hit
 * against the resolved version before reporting it (name-only matches are
 * downgraded to a single low-severity "unresolved" finding, same policy
 * as scanPackageDeep's own-package check).
 */
export async function scanDependencyCves(
  pkgJson: PackageJsonLike,
  lockfile?: LockfileLike | null
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const deps = await resolveDependencies(pkgJson, lockfile);
  if (deps.length === 0) return findings;

  const { vulnIdsByDep, failedDepNames } = await queryOsvBatch(deps);
  const allIds = vulnIdsByDep.flat();

  const vulnDetails = allIds.length > 0
    ? await fetchVulnDetails(allIds)
    : { found: new Map<string, OsvVuln>(), failedIds: [] as string[] };
  let unresolvedCount = 0;
  const unresolvedIds = new Set<string>();

  deps.forEach((dep, i) => {
    for (const vulnId of vulnIdsByDep[i]) {
      const vuln = vulnDetails.found.get(vulnId);
      if (!vuln) continue; // counted in failedIds below; not silently treated as clean

      const matchStatus = matchVersionAgainstVuln(dep.version, vuln, dep.name);
      if (matchStatus === false) continue;

      if (matchStatus === 'unknown') {
        unresolvedCount++;
        unresolvedIds.add(vulnId);
        continue;
      }

      const severity = severityFromVuln(vuln);
      const fixedVersion = fixedVersionText(vuln, dep.name);
      findings.push({
        id: findingIdForSeverity(severity),
        severity,
        description: `${severity} vulnerability in dependency '${dep.name}@${dep.version}': ${vuln.id} ` +
          `(affected ${affectedRangeText(vuln, dep.name)}, fixed ${fixedVersion ?? 'no fix published'}) - ` +
          `${vuln.summary || vuln.details || 'no summary available'}. Advisory: ${advisoryUrl(vuln)}`,
        fixRecommendation: fixedVersion
          ? `Upgrade '${dep.name}' to ${fixedVersion} or later.`
          : `No fixed version published yet for '${dep.name}'; track ${vuln.id} for an update.`,
        fixable: fixedVersion !== null,
      });
    }
  });

  if (unresolvedCount > 0) {
    findings.push({
      id: 'dependency-known-vulnerability-unresolved',
      severity: 'LOW',
      description: `${unresolvedCount} dependency advisor${unresolvedCount === 1 ? 'y matches' : 'ies match'} ` +
        `(${[...unresolvedIds].join(', ')}) by name but carry no structured version range to confirm against the ` +
        `resolved dependency version. Not a confirmed vulnerability - verify manually.`,
      fixRecommendation: 'Check each advisory manually against the resolved dependency version.',
      fixable: false,
    });
  }

  // A batch query that failed after retries, or a vuln id querybatch
  // confirmed but whose detail fetch failed, must read as "not checked" -
  // never as the same silence a genuinely clean dependency would produce.
  if (failedDepNames.length > 0 || vulnDetails.failedIds.length > 0) {
    const parts: string[] = [];
    if (failedDepNames.length > 0) parts.push(`${failedDepNames.length} dependenc${failedDepNames.length === 1 ? 'y' : 'ies'} (${failedDepNames.join(', ')}) could not be queried against OSV`);
    if (vulnDetails.failedIds.length > 0) parts.push(`${vulnDetails.failedIds.length} advisory record${vulnDetails.failedIds.length === 1 ? '' : 's'} (${vulnDetails.failedIds.join(', ')}) matched but could not be hydrated`);
    findings.push({
      id: 'dependency-osv-lookup-incomplete',
      severity: 'INFO',
      description: `OSV dependency check was incomplete: ${parts.join('; ')}, after retries. This is not evidence these dependencies are clean.`,
      fixRecommendation: 'Re-run the scan; if it persists, check OSV.dev API status.',
      fixable: false,
    });
  }

  return findings;
}
