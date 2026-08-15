import { ResolvedServer } from '../types/config.js';
import { Finding } from '../types/scan-result.js';

export function scanConfig(server: ResolvedServer): Finding[] {
  const findings: Finding[] = [];
  
  if (server.args) {
    for (const arg of server.args) {
      if (typeof arg !== 'string') continue;

      // Real command substitution ($(...) or backticks) is CRITICAL: in a
      // JSON arg array nothing is shell-expanded, so it can only be there
      // to smuggle execution. A complex ${...} expression (e.g.
      // --url=${BASE}/api) is a config smell, not code execution, so it
      // reports as MEDIUM. Simple ${VAR} refs (any case) are allowed.
      const isSimpleEnvVar = /^\$\{[A-Z0-9_]+\}$/i.test(arg);
      const hasCommandSubstitution = /\$\(.*\)|`.*`/.test(arg);
      const hasComplexExpression = /\$\{.*\}/.test(arg) && !isSimpleEnvVar;
      
      if (hasCommandSubstitution) {
        findings.push({
          id: 'shell-injection-risk',
          severity: 'CRITICAL',
          description: `Argument contains shell command substitution (\$(...) or backticks): '${arg}'`,
          fixRecommendation: 'Remove command substitution from arguments. Arguments are passed directly, never through a shell.'
        });
      } else if (hasComplexExpression) {
        findings.push({
          id: 'shell-injection-risk',
          severity: 'MEDIUM',
          description: `Argument contains a complex \${...} expression: '${arg}'`,
          fixRecommendation: 'Use a simple environment variable reference (e.g. ${VAR}) or resolve the value before passing it.'
        });
      }
    }

    if (server.args.length > 20) {
      findings.push({
        id: 'large-arg-list',
        severity: 'LOW',
        description: `Server has a suspiciously large number of arguments (${server.args.length}).`,
        fixRecommendation: 'Review all arguments and remove any that are unnecessary or suspicious.',
      });
    }

    // Check for absolute Windows-style paths on non-Windows (suspicious on macOS/Linux)
    const winPathArg = server.args.find(a => typeof a === 'string' && /^[A-Z]:\\/i.test(a));
    if (winPathArg) {
      findings.push({
        id: 'windows-path-on-unix',
        severity: 'LOW',
        description: `Server args contain a Windows-style path: '${winPathArg}'. May indicate misconfiguration or cross-platform issue.`,
        fixRecommendation: 'Replace Windows-style paths with POSIX paths for Unix/macOS environments.',
      });
    }
  }

  // Check for missing env vars mentioned in args (very basic heuristic)
  if (server.args) {
    for (const arg of server.args) {
      if (typeof arg !== 'string') continue;
      const match = arg.match(/\$([A-Z0-9_]+)/i);
      if (match) {
        const envVar = match[1];
        const inServerEnv = server.env && envVar in server.env;
        const inProcessEnv = envVar in process.env || envVar.toUpperCase() in process.env;
        if (!inServerEnv && !inProcessEnv) {
           findings.push({
            id: 'missing-env-var',
            severity: 'MEDIUM',
            description: `Server config references environment variable '${envVar}' which is not set in config.`,
          });
        }
      }
    }
  }

  return findings;
}
