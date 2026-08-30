import { describe, it, expect } from 'vitest';
import { scanLicense } from '../../src/scanners/license-scanner.js';

describe('license-scanner', () => {
  it('should flag copyleft licenses as MEDIUM', () => {
    const metadata = {
      source: 'npm' as const,
      packageName: 'test-pkg',
      license: 'GPL-3.0'
    };
    const findings = scanLicense(metadata);
    expect(findings.some(f => f.id === 'license-risk' && f.severity === 'MEDIUM')).toBe(true);
  });

  it('should flag unlicensed packages as HIGH', () => {
    const metadata = {
      source: 'npm' as const,
      packageName: 'test-pkg',
      license: 'UNLICENSED'
    };
    const findings = scanLicense(metadata);
    expect(findings.some(f => f.id === 'license-risk' && f.severity === 'HIGH')).toBe(true);
  });

  it('should flag missing license as HIGH when a live registry lookup confirmed it', () => {
    const metadata = {
      source: 'npm' as const,
      packageName: 'test-pkg',
      licenseVerified: true
    };
    const findings = scanLicense(metadata);
    expect(findings.some(f => f.id === 'license-risk' && f.severity === 'HIGH')).toBe(true);
  });

  // Regression: registry.npmjs.org confirmed real licenses (two MIT, one
  // Apache-2.0) for packages that this scanner reported as "no license
  // specified" HIGH. Root cause was in supply-chain-scanner: any failed/
  // offline registry lookup falls back to a ~70-package curated snapshot,
  // and a miss there left metadata.license undefined - indistinguishable
  // from a package that genuinely ships with no license. Without
  // licenseVerified, absence of data got reported as a security finding.
  it('should NOT flag missing license as HIGH when the lookup was not verified (offline/failed fallback)', () => {
    const metadata = {
      source: 'npm' as const,
      packageName: 'notion-mcp-server'
      // licenseVerified omitted, as it is whenever scanSupplyChainOffline
      // supplies the metadata (fetch failure, --offline, or timeout).
    };
    const findings = scanLicense(metadata);
    expect(findings.some(f => f.id === 'license-risk' && f.severity === 'HIGH')).toBe(false);
    expect(findings.some(f => f.id === 'license-risk' && f.severity === 'INFO')).toBe(true);
  });

  it('should allow permissive licenses', () => {
    const metadata = {
      source: 'npm' as const,
      packageName: 'test-pkg',
      license: 'MIT'
    };
    const findings = scanLicense(metadata);
    expect(findings).toHaveLength(0);
  });

  it('should flag unknown licenses as LOW', () => {
    const metadata = {
      source: 'npm' as const,
      packageName: 'test-pkg',
      license: 'Custom-License-123'
    };
    const findings = scanLicense(metadata);
    expect(findings.some(f => f.id === 'license-risk' && f.severity === 'LOW')).toBe(true);
  });
});
