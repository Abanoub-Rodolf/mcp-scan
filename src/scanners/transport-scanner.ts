import { ResolvedServer } from '../types/config.js';
import { Finding } from '../types/scan-result.js';

// Loopback traffic never leaves the machine.
function isLoopback(url: string): boolean {
  let host = '';
  try { host = new URL(url).hostname; } catch (_e) {}
  return host === 'localhost' || host === '[::1]' || /^127(\.\d{1,3}){3}$/.test(host);
}

export function scanTransport(server: ResolvedServer, allowedDomains: string[] = []): Finding[] {
  const findings: Finding[] = [];
  
  // A simplistic check - if it's an HTTP URL in args but no headers/auth are visible
  const httpArgs = (server.args ?? []).filter((a): a is string =>
    typeof a === 'string' && /^https?:\/\//i.test(a) && !allowedDomains.some(d => a.includes(d)));
  const hasAuthEnv = server.env && Object.keys(server.env).some(k => k.toLowerCase().includes('token') || k.toLowerCase().includes('key'));

  if (httpArgs.length && !hasAuthEnv) {
    // Rewriting a loopback URL to https:// would break the local server.
    findings.push(httpArgs.every(isLoopback) ? {
      id: 'http-transport-no-auth',
      severity: 'LOW',
      description: `Server connects to a loopback HTTP URL with no authentication credentials in env. Any local process can reach it.`,
      fixRecommendation: `Require a token on the local server, or run it over stdio.`,
    } : {
      id: 'http-transport-no-auth',
      severity: 'MEDIUM',
      description: `Server connects via HTTP but no authentication credentials were found in env.`,
      fixRecommendation: `Upgrade to HTTPS if supported by the server.`,
      fixable: true,
      remediationConfidence: 90
    });
  }

  // Check for insecure URL-based server. Loopback traffic never leaves the
  // machine, so it is LOW, not HIGH: what is left is that any local process
  // or a DNS-rebinding page can reach it. Rewriting it to https:// would
  // just break a local dev server, so it is not auto-fixable.
  // Schemes are case-insensitive: HTTP:// is just as plain.
  const plainHttp = /^http:\/\//i.test(server.url ?? '');
  if (plainHttp && isLoopback(server.url!)) {
    findings.push({
      id: 'http-transport-no-auth',
      severity: 'LOW',
      description: `Server uses plain http:// on loopback (${new URL(server.url!).hostname}). Traffic stays on this machine, but any local process can reach the server.`,
      fixRecommendation: `Require a token on the local server, or run it over stdio.`,
    });
  } else if (plainHttp) {
    findings.push({
      id: 'http-transport-no-auth',
      severity: 'HIGH',
      description: `Server uses insecure http:// protocol for connection.`,
      fixRecommendation: `Change the URL to use https://.`,
      fixable: true,
      remediationConfidence: 95
    });
  }

  // Check for deprecated transport mentioned in args
  if (server.args?.includes('--transport=sse')) {
     findings.push({
      id: 'outdated-transport',
      severity: 'LOW',
      description: `Server uses deprecated 'sse' transport.`,
      fixRecommendation: 'Upgrade to streamable-http transport.',
      fixable: true,
      remediationConfidence: 80
    });
  }

  // Check for explicit ws:// (unencrypted WebSocket)
  const hasInsecureWs = server.args?.some(a => typeof a === 'string' && /^ws:\/\//i.test(a));
  if (hasInsecureWs || /^ws:\/\//i.test(server.url ?? '')) {
    findings.push({
      id: 'insecure-transport',
      severity: 'HIGH',
      description: `Server uses unencrypted WebSocket (ws://). Data transmitted in plaintext.`,
      fixRecommendation: `Switch to encrypted WebSocket (wss://).`,
      fixable: true,
      remediationConfidence: 95
    });
  }

  return findings;
}
