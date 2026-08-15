import { ResolvedServer } from '../types/config.js';
import { Finding } from '../types/scan-result.js';

const DANGEROUS_PATHS = ['/', '~', '/etc', '/var', '/usr'];
const SENSITIVE_PATHS = ['.ssh', '.aws', '.gnupg', '.env', '.kube', '.docker', '.npmrc', '.netrc', '.config', 'credentials', 'id_rsa', 'id_ed25519'];
const BROAD_PATHS = ['/Users', '/home', '/root'];

export function scanPermissions(server: ResolvedServer): Finding[] {
  const findings: Finding[] = [];
  
  if (!server.args) return findings;

  for (const arg of server.args) {
    if (typeof arg !== 'string') continue;
    // Strip --flag=/path prefixes so '--dir=/etc' is evaluated like '/etc'.
    const value = arg.startsWith('-') ? (arg.includes('=') ? arg.split('=').pop()! : '') : arg;
    if (!value) continue;

    if (DANGEROUS_PATHS.some(p => value === p || value.startsWith(p + '/'))) {
      // Exact match missed '/etc/passwd', '/usr/bin', '/var/log' and
      // prefixed forms like --dir=/; anything under those roots is
      // equally dangerous.
      findings.push({
        id: 'excessive-permissions',
        severity: 'HIGH',
        description: `Server requests access to dangerous path: '${value}'.`,
        fixRecommendation: `Restrict access to a specific, non-sensitive directory.`,
        fixable: false
      });
    } else if (SENSITIVE_PATHS.some(p => value.includes(p))) {
        findings.push({
            id: 'excessive-permissions',
            severity: 'HIGH',
            description: `Server requests access to sensitive path: '${value}'.`,
            fixRecommendation: `Restrict access to a specific, non-sensitive directory.`,
            fixable: false
        });
    } else if (BROAD_PATHS.some(p => value.startsWith(p) && value.split('/').length <= 3)) {
      findings.push({
        id: 'broad-filesystem-access',
        severity: 'MEDIUM',
        description: `Server requests broad filesystem access: '${value}'.`,
        fixRecommendation: `Restrict access to a narrower project directory.`,
        fixable: false
      });
    }
  }

  return findings;
}
