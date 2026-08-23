import ora from 'ora';
import chalk from 'chalk';
import { BRAND_COLOR } from '../types/severity.js';

export const createSpinner = (text: string, isEnabled: boolean = true) => {
  // Disable spinner in CI environments (no TTY) to prevent broken output
  const ciMode = !process.stdout.isTTY || process.env.CI === 'true' || process.env.NO_COLOR !== undefined;
  return ora({
    text: chalk.hex(BRAND_COLOR)(text),
    color: 'blue',
    spinner: 'dots',
    isEnabled: isEnabled && !ciMode,
  });
};
