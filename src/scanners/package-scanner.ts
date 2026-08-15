import { ResolvedServer } from '../types/config.js';
import { Finding, FindingId } from '../types/scan-result.js';
import { Severity } from '../types/severity.js';
import { logger } from '../utils/logger.js';
import { parseCvssVector } from 'vuln-vects';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import semver from 'semver';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SNAPSHOT_PATH = path.join(__dirname, '../data/cve-snapshot.json');

interface NpmRegistryResponse {
  'dist-tags'?: { latest?: string };
  time?: Record<string, string>;
}

interface OsvResponse {
  vulns?: OsvVuln[];
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string };
  affected?: Array<{ ranges?: Array<{ type: string; events?: Array<{ fixed?: string }> }> }>;
  fixed_in?: string[];
}

/**
 * Extracts a numeric CVSS score from OSV severity entries. Handles
 * CVSS v3 vectors, CVSS v4 vectors, and plain numeric scores; never
 * throws and never guesses - returns null when nothing is parseable
 * so the caller can fall back to qualitative severity.
 */
function extractCvssScore(severities: Array<{ type: string; score: string }>): number | null {
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

/**
 * Deep audit of a package, either online or using a bundled snapshot.
 */
export async function scanPackageDeep(server: ResolvedServer, offline: boolean = false): Promise<Finding[]> {
  const findings: Finding[] = [];
  
  let packageName = '';
  if (server.command === 'npx' || server.command === 'npm') {
    const pkgArg = (Array.isArray(server.args) ? server.args : (server.args ? Object.values(server.args) : [])).find(a => typeof a === 'string' && !a.startsWith('-'));
    if (pkgArg) packageName = pkgArg as string;
  }

  if (!packageName) return findings;

  if (offline) {
    return scanPackageOffline(packageName);
  }

  let latestVersion = '';
  try {
    const npmController = new AbortController();
    const npmTimeoutId = setTimeout(() => npmController.abort(), 8000);
    let res;
    try {
      res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`, {
        signal: npmController.signal,
      });
    } finally {
      clearTimeout(npmTimeoutId);
    }
    
    if (!res.ok) {
      logger.warn(`Failed to fetch package info for ${packageName} from npm registry.`);
    } else {
      const data = await res.json() as NpmRegistryResponse;
      latestVersion = data['dist-tags']?.latest || '';
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
    return scanPackageOffline(packageName);
  }

  // OSV.dev integration
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    let osvRes;
    try {
      osvRes = await fetch('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ package: { name: packageName, ecosystem: 'npm' } }),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeoutId);
    }

    if (!osvRes.ok) {
      logger.warn(`OSV.dev API request failed for ${packageName}.`);
      return findings;
    }

    const osvData = await osvRes.json() as OsvResponse;
    const vulns: OsvVuln[] = osvData.vulns || [];

    if (vulns.length > 0) {
      for (const vuln of vulns) {
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
          description: `${effectiveSeverity} vulnerability found in '${packageName}': ${vuln.id} - ${vuln.summary || vuln.details || 'no summary available'}`,
          fixRecommendation: effectiveSeverity === 'LOW' ? 'Review and patch when convenient.' : `Upgrade package or remove it.`,
          fixable: true,
        });
      }
    }

    // Upgrade Advisor Logic
    if (latestVersion) {
        const currentVersion = (server as ResolvedServer & { metadata?: { version?: string } }).metadata?.version;
        if (currentVersion && semver.valid(currentVersion) && semver.valid(latestVersion) && semver.gt(latestVersion, currentVersion)) {
            // The upgrade resolves a vuln when the latest version is at or
            // after the version that fixed it. (This was previously
            // inverted, recommending the upgrade exactly when it would not
            // fix anything.)
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
                description: `A newer version of '${packageName}' is available: ${currentVersion} → ${latestVersion}.`,
                fixRecommendation: resolvesVulns 
                    ? `UPGRADE RECOMMENDED: Version ${latestVersion} may resolve known vulnerabilities. Run: npm install ${packageName}@${latestVersion}`
                    : `Run: npm install ${packageName}@${latestVersion} to update.`,
                fixable: true
            });
        }
    }

  } catch (_error) {
    logger.warn(`OSV.dev API request for ${packageName} failed or timed out. Switching to offline snapshot.`);
    return [...findings, ...scanPackageOffline(packageName)];
  }

  return findings;
}

function scanPackageOffline(packageName: string): Finding[] {
  const findings: Finding[] = [];
  try {
    if (!fs.existsSync(SNAPSHOT_PATH)) return findings;
    
    let snapshot;
    try {
      snapshot = JSON.parse(fs.readFileSync(SNAPSHOT_PATH, 'utf8'));
    } catch (parseError) {
      logger.warn(`Failed to parse offline CVE snapshot: ${parseError instanceof Error ? parseError.message : String(parseError)}`);
      return findings;
    }
    
    // Check if snapshot is stale (> 30 days)
    const updatedAt = new Date(snapshot.updatedAt);
    const now = new Date();
    const diffDays = (now.getTime() - updatedAt.getTime()) / (1000 * 60 * 60 * 24);
    if (diffDays > 30) {
      logger.warn(`CVE snapshot is ${Math.floor(diffDays)} days old. Run 'npm run update-cve-snapshot' to update.`);
    }

    const pkgData = snapshot.packages[packageName];
    if (pkgData && pkgData.vulns) {
      for (const vuln of pkgData.vulns) {
        const severity = String(vuln.severity || 'MEDIUM').toUpperCase() as Severity;
        const { id } = vulnSeverityToFinding(severity);
        findings.push({
          id,
          severity,
          description: `Bundled snapshot found ${severity} vulnerability in '${packageName}': ${vuln.id} - ${vuln.summary || 'no summary available'}`,
          fixRecommendation: `Upgrade package or remove it. (Offline info)`
        });
      }
    }
  } catch (_error) {}
  return findings;
}
