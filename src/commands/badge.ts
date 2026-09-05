import { validatePackageName } from '../scanners/package-scanner.js';

export interface BadgeOptions {
  json?: boolean;
}

/**
 * Prints a ready-to-paste badge snippet for a scanned npm package, pointing
 * at the hosted report on thynkq.com. No network calls: the URLs are built
 * from the package name alone.
 */
export function runBadge(pkg: string, options: BadgeOptions = {}): void {
  const validated = validatePackageName(pkg);
  if (!validated.valid) {
    console.error(`Error: ${validated.error}`);
    process.exitCode = 1;
    return;
  }

  const encoded = encodeURIComponent(validated.name);
  const badgeUrl = `https://thynkq.com/api/mcp-scan/badge/${encoded}.svg`;
  const reportUrl = `https://thynkq.com/mcp-scan/check/${encoded}`;
  const markdown = `[![mcp-scan](${badgeUrl})](${reportUrl})`;

  if (options.json) {
    console.log(JSON.stringify({ package: validated.name, badgeUrl, reportUrl, markdown }));
    return;
  }

  console.log(markdown);
  console.log(reportUrl);
}
