import { ScanReport } from '../types/scan-result.js';
import fs from 'fs';
import path from 'path';

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri: string;
  properties: { precision: string; problem: { severity: string } };
}

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: Array<{ physicalLocation: { artifactLocation: { uri: string; uriBaseId: string }; region: { startLine: number } } }>;
}


const SARIF_RULES: Record<string, { short: string, full: string, helpUri?: string }> = {
  // Single-sourced from the ids the scanners emit; the reporter
  // falls back to finding text for any id missing here, so the
  // table can never silently drift out of sync.
  'blocked-package-policy': {
     short: 'Blocked package policy',
     full: 'Package is explicitly blocked by company policy.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/blocked-package-policy'
  },
  'broad-filesystem-access': {
     short: 'Broad filesystem access',
     full: 'Server requests broad filesystem access.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/broad-filesystem-access'
  },
  'capability-escalation-risk': {
     short: 'Capability escalation',
     full: 'Tool claims a read-only role but its description claims write actions.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/capability-escalation-risk'
  },
  'credential-relay-risk': {
     short: 'Credential relay risk',
     full: 'Server forwards sensitive environment variables or credentials to an external sink.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/credential-relay-risk'
  },
  'cross-server-flow': {
     short: 'Cross-server data flow',
     full: 'One server references another server, enabling cross-server data movement.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/cross-server-flow'
  },
  'data-controls-consent-gap': {
     short: 'Consent gap',
     full: 'PII handling without a consent mechanism or privacy policy reference.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/data-controls-consent-gap'
  },
  'data-controls-deletion-gap': {
     short: 'Deletion gap',
     full: 'PII handling without user-initiated deletion capability.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/data-controls-deletion-gap'
  },
  'data-controls-encryption-gap': {
     short: 'Encryption gap',
     full: 'PII handling without encryption at rest.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/data-controls-encryption-gap'
  },
  'data-controls-minimization-risk': {
     short: 'Data minimization risk',
     full: 'Tool requests more data fields than necessary.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/data-controls-minimization-risk'
  },
  'data-controls-pii': {
     short: 'PII handling',
     full: 'Server handles personally identifiable information.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/data-controls-pii'
  },
  'data-controls-prompt-logging': {
     short: 'Prompt logging',
     full: 'Server appears to log raw user prompts or interactions.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/data-controls-prompt-logging'
  },
  'data-controls-retention-gap': {
     short: 'Retention gap',
     full: 'PII handling without a data retention policy.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/data-controls-retention-gap'
  },
  'data-controls-stale-temp-files': {
     short: 'Stale temp files',
     full: 'System contains a large number of temporary files.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/data-controls-stale-temp-files'
  },
  'data-exfiltration-risk': {
     short: 'Data exfiltration risk',
     full: 'A tool has both local read and external network egress capabilities.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/data-exfiltration-risk'
  },
  'data-flow-source-sink': {
     short: 'Sensitive data flow',
     full: 'Data flows from a sensitive source to an external sink.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/data-flow-source-sink'
  },
  'duplicate-server': {
     short: 'Duplicate server',
     full: 'Same server definition found across multiple tools.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/duplicate-server'
  },
  'env-secret-exposed': {
     short: 'Env file secret exposed',
     full: 'A .env file contains a real-looking secret value.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/env-secret-exposed'
  },
  'env-var-prefix-risk': {
     short: 'Env var prefix risk',
     full: 'Environment variable does not match the required prefix.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/env-var-prefix-risk'
  },
  'env-var-scope-leak': {
     short: 'Env var scope leak',
     full: 'Reference to an environment variable outside this server scope.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/env-var-scope-leak'
  },
  'excessive-permissions': {
     short: 'Excessive permissions',
     full: 'Server requests access to dangerous or sensitive paths.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/excessive-permissions'
  },
  'exfiltration-vector': {
     short: 'Data exfiltration vector',
     full: 'Tool arguments or capabilities reference external endpoints alongside sensitive data.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/exfiltration-vector'
  },
  'exposed-secret': {
     short: 'Exposed secret detected',
     full: 'A hardcoded secret, API key, or credential was found in the configuration.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/exposed-secret'
  },
  'hidden-instruction-risk': {
     short: 'Hidden instructions',
     full: 'Excessive whitespace padding hides instructions in a description.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/hidden-instruction-risk'
  },
  'high-entropy-value': {
     short: 'High-entropy value',
     full: 'A value with unusually high entropy that may be an undocumented secret.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/high-entropy-value'
  },
  'http-transport-no-auth': {
     short: 'HTTP transport without auth',
     full: 'Server exposes an HTTP endpoint without authentication.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/http-transport-no-auth'
  },
  'insecure-transport': {
     short: 'Insecure transport',
     full: 'Server communicates over unencrypted transport.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/insecure-transport'
  },
  'known-malicious': {
     short: 'Known malicious package',
     full: 'The server uses a package that is on the known malicious blocklist.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/known-malicious'
  },
  'known-vulnerability-critical': {
     short: 'Critical known vulnerability',
     full: 'Package has a known critical-severity vulnerability.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/known-vulnerability-critical'
  },
  'known-vulnerability-high': {
     short: 'High known vulnerability',
     full: 'Package has a known high-severity vulnerability.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/known-vulnerability-high'
  },
  'known-vulnerability-low': {
     short: 'Low known vulnerability',
     full: 'Package has a known low-severity vulnerability.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/known-vulnerability-low'
  },
  'known-vulnerability-medium': {
     short: 'Medium known vulnerability',
     full: 'Package has a known medium-severity vulnerability.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/known-vulnerability-medium'
  },
  'known-vulnerability-unresolved': {
     short: 'Unresolved package version',
     full: 'Package has known advisories but the installed/resolved version could not be verified against them.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/known-vulnerability-unresolved'
  },
  'large-arg-list': {
     short: 'Large argument list',
     full: 'Server has a suspiciously large number of arguments.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/large-arg-list'
  },
  'license-risk': {
     short: 'License compliance risk',
     full: 'Package license is missing, unknown, or carries legal risk.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/license-risk'
  },
  'missing-referenced-env-var': {
     short: 'Missing referenced env var',
     full: 'Configuration references an environment variable that is not set.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/missing-referenced-env-var'
  },
  'network-egress-api': {
     short: 'Known API endpoint',
     full: 'Server contacts a known API endpoint.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/network-egress-api'
  },
  'network-egress-bypass-attempt': {
     short: 'Egress bypass attempt',
     full: 'Server uses child_process with curl/wget, bypassing policy controls.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/network-egress-bypass-attempt'
  },
  'network-egress-cdn': {
     short: 'CDN resource load',
     full: 'Server loads resources from a CDN.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/network-egress-cdn'
  },
  'network-egress-data-in-url': {
     short: 'Data in URL',
     full: 'Long data appears in URL query parameters.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/network-egress-data-in-url'
  },
  'network-egress-non-standard-port': {
     short: 'Non-standard port',
     full: 'Server connects to external non-standard ports.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/network-egress-non-standard-port'
  },
  'network-egress-obfuscated': {
     short: 'Obfuscated endpoint',
     full: 'Server contains base64, hex, or reversed obfuscated URLs.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/network-egress-obfuscated'
  },
  'network-egress-raw-ip': {
     short: 'Raw IP endpoint',
     full: 'Server connects directly to a raw external IP address.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/network-egress-raw-ip'
  },
  'network-egress-suspicious': {
     short: 'Suspicious network egress',
     full: 'Server contacts a known suspicious or malicious endpoint.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/network-egress-suspicious'
  },
  'network-egress-telemetry': {
     short: 'Telemetry endpoint',
     full: 'Server contacts known telemetry or analytics domains.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/network-egress-telemetry'
  },
  'network-egress-unknown': {
     short: 'Unknown external endpoint',
     full: 'Server contacts an unrecognized external endpoint.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/network-egress-unknown'
  },
  'node-inline-execution': {
     short: 'Node inline execution',
     full: 'Node.js runs inline code via the -e flag.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/node-inline-execution'
  },
  'official-server': {
     short: 'Official MCP server',
     full: 'Server is a known official reference implementation.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/official-server'
  },
  'outdated-transport': {
     short: 'Outdated transport',
     full: 'Server uses an outdated transport configuration.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/outdated-transport'
  },
  'provenance-verified': {
     short: 'Provenance verified',
     full: 'Package was published with a signed npm provenance attestation.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/provenance-verified'
  },
  'prompt-injection-pattern': {
     short: 'Prompt injection risk',
     full: 'Suspicious instruction patterns detected in descriptions or arguments.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/prompt-injection-pattern'
  },
  'python-inline-execution': {
     short: 'Python inline execution',
     full: 'Python runs code via -c with exec() or eval().',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/python-inline-execution'
  },
  'reverse-shell-risk': {
     short: 'Reverse shell risk',
     full: 'Command contains netcat-style connection patterns that could open a reverse shell.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/reverse-shell-risk'
  },
  'scanner-error': {
     short: 'Scanner failure',
     full: 'An internal scanner error occurred for this server.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/scanner-error'
  },
  'schema-bypass-risk': {
     short: 'Schema bypass risk',
     full: 'Schema allows additional properties.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/schema-bypass-risk'
  },
  'sensitive-glob-pattern': {
     short: 'Sensitive glob pattern',
     full: 'Glob argument may expose sensitive directories.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/sensitive-glob-pattern'
  },
  'server-mutation': {
     short: 'Server mutation',
     full: 'Server configuration changed since the last scan.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/server-mutation'
  },
  'shell-injection-risk': {
     short: 'Shell injection risk',
     full: 'Argument contains command substitution or complex shell expressions.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/shell-injection-risk'
  },
  'stale-server': {
     short: 'Stale package',
     full: 'Package has not been updated in over six months.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/stale-server'
  },
  'supply-chain-low-trust': {
     short: 'Low-trust supply chain',
     full: 'Package has low history, few stars, or no maintainers.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/supply-chain-low-trust'
  },
  'suspicious-execution': {
     short: 'Suspicious execution pattern',
     full: 'Command uses shell -c, eval, or exec patterns.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/suspicious-execution'
  },
  'tool-exfiltration-risk': {
     short: 'Tool exfiltration instructions',
     full: 'Description instructs moving data outside the intended scope.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/tool-exfiltration-risk'
  },
  'tool-name-shadow': {
     short: 'Tool name shadowing',
     full: 'Tool name mimics built-in operations.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/tool-name-shadow'
  },
  'trusted-community-server': {
     short: 'Trusted community server',
     full: 'Server is a widely trusted community implementation.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/trusted-community-server'
  },
  'typosquat-detection': {
     short: 'Potential typosquatting',
     full: 'Package name closely resembles a trusted package (Levenshtein/homoglyph).',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/typosquat-detection'
  },
  'unicode-injection': {
     short: 'Unicode injection',
     full: 'Zero-width or direction-reversal characters used for obfuscation.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/unicode-injection'
  },
  'unverified-source': {
     short: 'Unverified package source',
     full: 'Package comes from an unverified publisher, raising typosquatting risk.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/unverified-source'
  },
  'upgrade-available': {
     short: 'Upgrade available',
     full: 'A newer version of the package is available.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/upgrade-available'
  },
  'windows-path-on-unix': {
     short: 'Windows path on Unix',
     full: 'Server args contain a Windows-style path on a Unix system.',
     helpUri: 'https://thynkq.com/docs/mcp-scan/rules/windows-path-on-unix'
  },
}

export function generateSarif(report: ScanReport) {
  const sarif = {
    $schema: 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcp-scan',
            fullName: 'MCP Security Scanner',
            version: report.version || '2.0.0',
            informationUri: 'https://github.com/Abanoub-Rodolf/mcp-scan',
            rules: [] as SarifRule[],
          },
        },
        results: [] as SarifResult[],
        originalUriBaseIds: {
          SRCROOT: { uri: 'file:///' + process.cwd().replace(/\\/g, '/') },
        },
      },
    ],
  };

  const rulesMap = new Map<string, SarifRule>();

  for (const result of report.results) {
    for (const finding of result.findings) {
      if (!rulesMap.has(finding.id)) {
        const metadata = SARIF_RULES[finding.id];
        rulesMap.set(finding.id, {
          id: finding.id,
          name: finding.id.replace(/-/g, '_'),
          shortDescription: {
            text: metadata?.short || finding.description.split('\n')[0],
          },
          fullDescription: {
            text: metadata?.full || finding.description,
          },
          helpUri: metadata?.helpUri || 'https://thynkq.com/docs/mcp-scan/rules',
          properties: {
            precision: 'high',
            problem: {
              severity: mapSeverityToSarifProblemSeverity(finding.severity),
            },
          },
        });
      }

      const level = mapSeverityToSarifLevel(finding.severity);
      const artifactPath = path.relative(process.cwd(), result.configPath).split(path.sep).join('/');

      sarif.runs[0].results.push({
        ruleId: finding.id,
        level: level,
        message: {
          text: finding.description,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: artifactPath,
                uriBaseId: '%SRCROOT%',
              },
              region: {
                startLine: 1, // point to the top of the config file
              },
            },
          },
        ],
      });
    }
  }

  sarif.runs[0].tool.driver.rules = Array.from(rulesMap.values());

  return sarif;
}

function mapSeverityToSarifLevel(severity: string): string {
  switch (severity.toUpperCase()) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
    case 'INFO':
    default:
      return 'note';
  }
}

function mapSeverityToSarifProblemSeverity(severity: string): string {
  switch (severity.toUpperCase()) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    default:
      return 'recommendation';
  }
}

export function writeSarifReport(report: ScanReport, outputPath: string) {
  const sarif = generateSarif(report);
  fs.writeFileSync(outputPath, JSON.stringify(sarif, null, 2));
}
