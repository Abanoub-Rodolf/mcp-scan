import { runScan } from './commands/scan.js';
import { detectTools } from './config/detector.js';
import { generateHtmlReport } from './utils/html-reporter.js';
import { generateSarif } from './utils/sarif-reporter.js';
import { generateSbom, generateSpdx } from './utils/sbom-generator.js';
import { scanRegistry } from './scanners/registry-scanner.js';
import { scanTyposquat } from './scanners/typosquat-scanner.js';
import { scanPackageDeep } from './scanners/package-scanner.js';
import { scanSupplyChain } from './scanners/supply-chain-scanner.js';
import { scanLicense } from './scanners/license-scanner.js';

export {
  runScan,
  detectTools,
  generateHtmlReport,
  generateSarif,
  generateSbom,
  generateSpdx,
  // Per-package checks, exported so callers (e.g. scripts/ecosystem-scan.mjs)
  // can run the supply-chain/package analysis path against an arbitrary
  // package name instead of only against locally detected tool configs.
  scanRegistry,
  scanTyposquat,
  scanPackageDeep,
  scanSupplyChain,
  scanLicense,
};

export type {
  ScanReport,
  ServerScanResult,
  Finding,
  ScanOptions,
} from './types/index.js';

export type { ResolvedServer } from './types/config.js';
