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
import { scanAst } from './scanners/ast-scanner.js';
import { scanAstSource } from './scanners/ast-source-scanner.js';
import { scanSecrets } from './scanners/secret-scanner.js';
import { scanToolPoisoning } from './scanners/tool-poisoning-scanner.js';
import { scanPromptInjection } from './scanners/prompt-injection-scanner.js';
import { scanTransport } from './scanners/transport-scanner.js';
import { scanEnvLeak } from './scanners/env-leak-scanner.js';
import { scanNetworkEgress } from './scanners/network-egress-scanner.js';
import { scanDataFlow } from './scanners/data-flow-scanner.js';
import { scanDependencyCves } from './scanners/osv-scanner.js';

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
  // Code-level checks. Take a ResolvedServer, so a caller that wants to
  // point them at real package source (not just a locally detected MCP
  // config) builds a synthetic server whose command/args/env carry the
  // file content to scan - see scripts/ecosystem-scan.mjs.
  scanAst,
  // Source-aware sibling of scanAst for exactly that whole-file case -
  // see ast-source-scanner.ts. scanAst itself must stay untouched for
  // real MCP config scans; never call scanAst on package source.
  scanAstSource,
  scanSecrets,
  scanToolPoisoning,
  scanPromptInjection,
  scanTransport,
  scanEnvLeak,
  scanNetworkEgress,
  scanDataFlow,
  // Dependency-tree CVE lookup against OSV.dev, independent of the
  // single-package check scanPackageDeep already does against the
  // top-level package name.
  scanDependencyCves,
};

export type {
  ScanReport,
  ServerScanResult,
  Finding,
  ScanOptions,
} from './types/index.js';

export type { ResolvedServer } from './types/config.js';
