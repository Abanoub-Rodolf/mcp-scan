import chalk from 'chalk';
import { BRAND_COLOR, SEVERITY_COLORS } from '../types/severity.js';

const brandColor = chalk.hex(BRAND_COLOR);
const criticalColor = chalk.hex(SEVERITY_COLORS.CRITICAL).bold;
const highColor = chalk.hex(SEVERITY_COLORS.HIGH);
const mediumColor = chalk.hex(SEVERITY_COLORS.MEDIUM).bold;
const lowColor = chalk.dim;
const passColor = chalk.hex('#3FB950');
const dimColor = chalk.dim;

// In `mcp-scan proxy` stdout carries the MCP protocol, so the proxy flips
// this to send every log line to stderr (so does `report --json`). Scan
// output is untouched.
const out = (...args: unknown[]) => (logger.toStderr ? console.error(...args) : console.log(...args));

export const logger = {
  toStderr: false,
  isSilent: false,
  isVerbose: false,
  
  brand: (msg: string) => !logger.isSilent && out(brandColor.bold(msg)),
  critical: (msg: string) => !logger.isSilent && out(criticalColor('✖ CRITICAL:'), msg),
  high: (msg: string) => !logger.isSilent && out(highColor('▲ HIGH:'), msg),
  medium: (msg: string) => !logger.isSilent && out(mediumColor('■ MEDIUM:'), msg),
  low: (msg: string) => !logger.isSilent && out(lowColor('• LOW:'), msg),
  pass: (msg: string) => !logger.isSilent && out(passColor.bold('✓ PASS:'), msg),
  info: (msg: string) => !logger.isSilent && out(brandColor('ℹ INFO:'), msg),
  fix: (msg: string) => !logger.isSilent && out(dimColor(`  ↳ ${msg}`)),
  detail: (msg: string) => !logger.isSilent && logger.isVerbose && out(dimColor(`    ${msg}`)),
  divider: () => !logger.isSilent && out(dimColor('──────────────────────────────────────────────────')),
  warn: (msg: string) => !logger.isSilent && out(chalk.yellow.bold('! WARN:'), msg),
  error: (msg: string) => console.error(chalk.red.bold('✖ ERROR:'), msg),
  log: (msg: string) => !logger.isSilent && out(msg),
  emptyLine: () => !logger.isSilent && out(''),
};
