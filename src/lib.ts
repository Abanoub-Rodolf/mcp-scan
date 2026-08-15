import { runScan } from './commands/scan.js';
import { detectTools } from './config/detector.js';
import { generateHtmlReport } from './utils/html-reporter.js';
import { generateSarif } from './utils/sarif-reporter.js';
import { generateSbom, generateSpdx } from './utils/sbom-generator.js';

export {
  runScan,
  detectTools,
  generateHtmlReport,
  generateSarif,
  generateSbom,
  generateSpdx,
};

export type {
  ScanReport,
  ServerScanResult,
  Finding,
  ScanOptions,
} from './types/index.js';
