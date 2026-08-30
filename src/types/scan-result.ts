import { Severity } from './severity.js';

// Single source of truth for finding identities. The FindingId union is
// derived from this list, so adding a new scanner finding means adding it
// here exactly once.
export const FINDING_IDS = [
  'no-malicious-package',
  'malicious-package',
  'no-typosquatting',
  'typosquatting-package',
  'outdated-package',
  'unmaintained-package',
  'known-vulnerability-critical',
  'known-vulnerability-high',
  'prompt-injection-pattern',
  'unicode-injection',
  'tool-name-shadow',
  'schema-bypass-risk',
  'exposed-secret',
  'missing-referenced-env-var',
  'duplicate-server',
  'supply-chain-low-trust',
  'supply-chain-rug-pull',
  'hidden-instruction-risk',
  'capability-escalation-risk',
  'tool-exfiltration-risk',
  'env-var-scope-leak',
  'high-entropy-value',
  'license-risk',
  'exfiltration-vector',
  'blocked-package-policy',
  'env-var-prefix-risk',
  'server-mutation',
  'upgrade-available',
  'data-exfiltration-risk',
  'credential-relay-risk',
  'cross-server-flow',
  'temp-storage-risk',
  'network-egress-suspicious',
  'network-egress-non-standard-port',
  'network-egress-obfuscated',
  'network-egress-raw-ip',
  'network-egress-telemetry',
  'network-egress-api',
  'network-egress-cdn',
  'network-egress-unknown',
  'network-egress-data-in-url',
  'network-egress-bypass-attempt',
  'data-controls-pii',
  'data-controls-consent-gap',
  'data-controls-retention-gap',
  'data-controls-deletion-gap',
  'data-controls-encryption-gap',
  'data-controls-prompt-logging',
  'env-secret-exposed',
  'data-controls-sharing',
  'data-controls-old-temp-files',
  'data-controls-minimization-risk',
  'data-controls-stale-temp-files',
  'known-vulnerability-medium',
  'known-vulnerability-low',
  'insecure-transport',
  'http-transport-no-auth',
  'outdated-transport',
  'stale-server',
] as const;

export type FindingId = typeof FINDING_IDS[number];

export interface Finding {
  id: string;
  severity: Severity;
  description: string;
  fixRecommendation?: string;
  fixable?: boolean;
  remediationConfidence?: number; // 1-100
}

/**
 * Single contract for package metadata gathered by scanners. Both the
 * supply-chain scanner's result and ServerScanResult.metadata use this,
 * so peer scanners never borrow each other's types.
 */
export interface PackageMetadata {
  packageName?: string;
  version?: string;
  license?: string;
  // True only when license came from a live, authoritative registry lookup.
  // The offline CVE snapshot is a small curated set (~70 packages); a miss
  // there means "we don't know", not "no license" - license-scanner reads
  // this to avoid reporting an absence of data as an absence of license.
  licenseVerified?: boolean;
  repositoryUrl?: string;
  author?: string;
  integrity?: string;
  source?: 'npm' | 'local' | 'unknown';
}

export interface ServerScanResult {
  serverName: string;
  toolName: string;
  configPath: string;
  findings: Finding[];
  scanDurationMs: number;
  trustScore?: number;
  /** Original server connection details from MCP config */
  connection?: {
    command?: string;
    args?: string[];
    url?: string;
    type?: string;
    env?: string[]; // Sorted keys for fingerprinting
  };
  metadata?: PackageMetadata;
}

export interface ScanReport {
  results: ServerScanResult[];
  totalScanned: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  totalDurationMs: number;
  version?: string;
}
