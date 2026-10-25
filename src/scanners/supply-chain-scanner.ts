import { ResolvedServer } from '../types/config.js';
import { Finding, PackageMetadata } from '../types/scan-result.js';
import { logger } from '../utils/logger.js';
import { loadCveSnapshot } from '../utils/cve-snapshot.js';
import { npxPackageArg, launcher } from './package-scanner.js';

interface NpmPackageData {
  'dist-tags'?: { latest?: string };
  // Legacy package.json shapes put an object here ({"type":"MIT"}), or an array.
  license?: unknown;
  licenses?: Array<{ type?: unknown }>;
  author?: { name?: string } | string;
  repository?: { url?: string } | string;
  maintainers?: Array<{ name: string }>;
}

// Downstream code (license scanner, policy license_type match) calls string
// methods on metadata.license, so only a non-empty string may be stored.
export function normalizeLicense(...candidates: unknown[]): string | undefined {
  for (const c of candidates) {
    if (typeof c === 'string' && c.trim()) return c;
    if (typeof c === 'object' && c !== null) {
      const t = (c as { type?: unknown }).type;
      if (typeof t === 'string' && t.trim()) return t;
    }
  }
  return undefined;
}

interface GitHubRepoData {
  stargazers_count: number;
  forks_count: number;
  updated_at: string;
  pushed_at: string;
  owner: { login: string };
}

interface RepoMetadata {
  stars: number;
  forks: number;
  updatedAt: string;
  pushedAt: string;
  owner: string;
}

export interface SupplyChainResult {
  findings: Finding[];
  trustScore: number;
  metadata?: PackageMetadata;
}

// What the registry is asked about. A bare name or `name@latest` runs the
// registry's latest, so look up the bare name (scoped names keep their
// leading @). Any other spec (pin, range, tag) is left as written, as before:
// it is not what latest resolves to, and the baseline does not track it.
function registryName(spec: string): string {
  const at = spec.indexOf('@', 1);
  return at > 0 && spec.slice(at + 1) === 'latest' ? spec.slice(0, at) : spec;
}

export async function scanSupplyChain(server: ResolvedServer, offline: boolean = false): Promise<SupplyChainResult> {
  const findings: Finding[] = [];
  let trustScore = 50; // Neutral starting point
  const metadata: SupplyChainResult['metadata'] = { source: 'local' };

  let packageName = '';
  const cmd = launcher(server.command);
  if (cmd === 'npx' || cmd === 'npm') {
    const pkgArg = npxPackageArg(server.args, server.command);
    if (pkgArg) packageName = pkgArg;
  }

  if (!packageName) return { findings, trustScore: 100, metadata };

  const lookupName = registryName(packageName);

  if (offline) {
    return scanSupplyChainOffline(packageName, lookupName);
  }

  metadata.source = 'npm';
  metadata.packageName = packageName;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const npmRes = await fetch(`https://registry.npmjs.org/${encodeURIComponent(lookupName)}`, { signal: controller.signal });
    clearTimeout(timeout);

    if (!npmRes.ok) {
      logger.warn(`Supply Chain: Failed to fetch npm registry data for ${packageName}. Switching to offline snapshot.`);
      return scanSupplyChainOffline(packageName, lookupName);
    }

    const npmData = await npmRes.json() as NpmPackageData;
    const repoUrl = extractRepoUrl(npmData);
    
    metadata.version = npmData['dist-tags']?.latest;
    metadata.versionSource = 'registry';
    metadata.license = normalizeLicense(npmData.license, npmData.licenses?.[0]);
    // A successful, parsed registry response is authoritative for license
    // presence/absence, regardless of what happens next (no repo URL, dead
    // GitHub link, etc. below still return this metadata).
    metadata.licenseVerified = true;
    metadata.author = typeof npmData.author === 'object' ? npmData.author?.name : npmData.author;
    metadata.repositoryUrl = repoUrl || undefined;

    if (!repoUrl) {
      findings.push({
        id: 'supply-chain-low-trust',
        severity: 'MEDIUM',
        description: `Package '${packageName}' has no public repository URL linked.`,
        fixRecommendation: 'Verify the authenticity of this package manually.'
      });
      return { findings, trustScore: 20, metadata };
    }

    const githubResult = await fetchGitHubMetadata(repoUrl);
    if (!githubResult.ok) {
      if (githubResult.reason === 'not-found') {
        // The API call itself succeeded (not rate-limited, not a network
        // error) and GitHub says this repo doesn't exist: a genuine
        // low-trust signal, not a lookup failure.
        findings.push({
          id: 'supply-chain-low-trust',
          severity: 'MEDIUM',
          description: `Package '${packageName}' links a repository URL that does not resolve on GitHub (${repoUrl}).`,
          fixRecommendation: 'Verify the authenticity of this package manually; the linked repository may be deleted, renamed, or fabricated.'
        });
        return { findings, trustScore: 20, metadata };
      }

      // Rate-limited or a network/timeout failure: the scanner learned
      // nothing about the repo either way, so this must not read as "no
      // repo found" (unauthenticated GitHub API calls are capped at 60/hr
      // and a campaign scanning 100+ packages exhausts that fast).
      logger.warn(`Supply Chain: Failed to fetch GitHub metadata for ${repoUrl} (${githubResult.reason}).`);
      findings.push({
        id: 'github-metadata-unverified',
        severity: 'INFO',
        description: `Package '${packageName}' repository metadata could not be verified via GitHub (${githubResult.reason === 'rate-limited' ? 'GitHub API rate limit' : 'network failure'}). This is not evidence the repository is missing or untrustworthy.`,
        fixRecommendation: 'Re-run with a GITHUB_TOKEN environment variable set, or verify the repository manually.'
      });
      return { findings, trustScore: 40, metadata };
    }

    const githubMeta = githubResult.data;
    trustScore = calculateTrustScore(githubMeta);

    if (trustScore < 40) {
      findings.push({
        id: 'supply-chain-low-trust',
        severity: 'MEDIUM',
        description: `Package '${packageName}' has a low supply chain trust score (${trustScore}/100).`,
        fixRecommendation: 'This package has low activity, few stars, or is unmaintained. Audit the source code before use.'
      });
    }

    // Check for rug pull (very basic check: compare owner in registry vs owner in current repo if we had history)
    // For now, just a placeholder for more advanced logic
    const currentOwner = githubMeta.owner;
    if (npmData.maintainers && !npmData.maintainers.some((m) => currentOwner.toLowerCase().includes(m.name.toLowerCase()))) {
        // This is a weak signal but could indicate a disconnect
        logger.detail(`Supply Chain: Owner mismatch detected between npm maintainers and GitHub owner for ${packageName}.`);
    }

  } catch (error: any) {
    if (error.name === 'AbortError') {
      logger.warn(`Supply Chain: Fetch timed out for ${packageName}. Switching to offline mode.`);
      return scanSupplyChainOffline(packageName, lookupName);
    }
    logger.warn(`Supply Chain: Error during scan for ${packageName}: ${error instanceof Error ? error.message : String(error)}. Switching to offline mode.`);
    return scanSupplyChainOffline(packageName, lookupName);
  }

  return { findings, trustScore, metadata };
}

function scanSupplyChainOffline(packageName: string, lookupName: string = packageName): SupplyChainResult {
  const result: SupplyChainResult = { findings: [], trustScore: 30, metadata: { source: 'npm', packageName } };
  try {
    const snapshot = loadCveSnapshot();
    if (!snapshot) return result;
    const pkgData = snapshot.raw.packages?.[lookupName];
    if (pkgData) {
      result.metadata!.version = pkgData.version;
      result.metadata!.versionSource = 'snapshot';
      result.metadata!.license = normalizeLicense(pkgData.license);
      const hasKnownCves = Array.isArray(pkgData.vulns) && pkgData.vulns.length > 0;
      result.trustScore = hasKnownCves ? 40 : 100;
    }
  } catch (_error) {}
  return result;
}

function extractRepoUrl(npmData: NpmPackageData): string | null {
  const repo = npmData.repository;
  if (!repo) return null;
  
  let url = typeof repo === 'string' ? repo : repo.url;
  if (!url) return null;

  // Clean up git+https, .git, etc.
  url = url.replace(/^git\+/, '').replace(/\.git$/, '').replace(/^git:/, 'https:');
  if (url.includes('github.com')) {
    return url;
  }
  return null;
}

type GitHubFetchResult =
  | { ok: true; data: RepoMetadata }
  | { ok: false; reason: 'rate-limited' | 'not-found' | 'network' };

async function fetchGitHubMetadata(repoUrl: string): Promise<GitHubFetchResult> {
  try {
    const parts = repoUrl.split('github.com/')[1].split('/');
    const owner = parts[0];
    const repo = parts[1];
    const apiUrl = `https://api.github.com/repos/${owner}/${repo}`;

    const headers: Record<string, string> = {
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'mcp-scan'
    };

    if (process.env.GITHUB_TOKEN) {
      headers['Authorization'] = `token ${process.env.GITHUB_TOKEN}`;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const res = await fetch(apiUrl, { headers, signal: controller.signal });
    clearTimeout(timeout);

    // 403 covers both the primary and secondary GitHub rate limits;
    // unauthenticated requests are capped at 60/hr, which a campaign scan
    // of 100+ packages burns through well before it finishes.
    if (res.status === 403 || res.status === 429) return { ok: false, reason: 'rate-limited' };
    if (res.status === 404) return { ok: false, reason: 'not-found' };
    if (!res.ok) return { ok: false, reason: 'network' };

    const data = await res.json() as GitHubRepoData;
    return {
      ok: true,
      data: {
        stars: data.stargazers_count,
        forks: data.forks_count,
        updatedAt: data.updated_at,
        pushedAt: data.pushed_at,
        owner: data.owner.login
      }
    };
  } catch (_error) {
    return { ok: false, reason: 'network' };
  }
}

function calculateTrustScore(meta: RepoMetadata): number {
  let score = 0;

  // Stars: up to 30 points
  if (meta.stars > 5000) score += 30;
  else if (meta.stars > 1000) score += 25;
  else if (meta.stars > 100) score += 15;
  else if (meta.stars > 10) score += 5;

  // Forks: up to 20 points
  if (meta.forks > 500) score += 20;
  else if (meta.forks > 100) score += 15;
  else if (meta.forks > 10) score += 8;

  // Activity (pushed in last 6 months): 40 points
  const lastPush = new Date(meta.pushedAt);
  const sixMonthsAgo = new Date();
  sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
  
  if (lastPush > sixMonthsAgo) {
    score += 40;
  } else {
    const oneYearAgo = new Date();
    oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);
    if (lastPush > oneYearAgo) {
      score += 20;
    }
  }

  return Math.min(100, score);
}
