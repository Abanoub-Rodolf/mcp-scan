import { ResolvedServer } from '../types/config.js';
import { Finding } from '../types/scan-result.js';
import { KNOWN_ENDPOINTS } from '../data/known-endpoints.js';

export function scanNetworkEgress(server: ResolvedServer): Finding[] {
  const findings: Finding[] = [];
  
  // No /g flags: these regexes are reused across strings and .test() on a
  // global regex carries lastIndex between calls, silently alternating
  // detections (the same bug fixed in the PII patterns).
  const urlRegex = /https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:\/[^\s"']*)?/;
  const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
  const ipv6Regex = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/;
  const b64UrlRegex = /aHR0c[A-Za-z0-9+/=]+|c2h0dH[A-Za-z0-9+/=]+/;
  const hexUrlRegex = /68747470[A-Fa-f0-9]+/;
  const reversedUrlRegex = /\/\/:ptth|\/\/:sptth/;
  
  const endpoints = new Set<string>();

  /** True for loopback, RFC1918, link-local, CGNAT, and invalid octets. */
  const isPrivateOrInvalidIp = (ip: string): boolean => {
    const octets = ip.split('.').map(Number);
    if (octets.length !== 4 || octets.some(o => Number.isNaN(o) || o < 0 || o > 255)) return true;
    const [a, b] = octets;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a === 169 && b === 254) return true; // link-local
    if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918 (all of 172.16/12)
    if (a === 192 && b === 168) return true;
    if (a >= 224) return true; // multicast + reserved
    return false;
  };
  
  const checkString = (str: string) => {
      if (str.length > 10_000) str = str.slice(0, 10_000);
      const urls = str.match(urlRegex);
      if (urls) urls.forEach(u => endpoints.add(u));
      
      const ipv6s = str.match(ipv6Regex);
      if (ipv6s) {
          ipv6s.forEach(ip => {
            if (!ip.startsWith('::') && !ip.startsWith('fe80:') && !ip.startsWith('fc') && !ip.startsWith('fd')) {
              endpoints.add(`ipv6:${ip}`);
            }
          });
      }

      const ips = str.match(ipRegex);
      if (ips) {
          ips.forEach(ip => {
             if (!isPrivateOrInvalidIp(ip)) endpoints.add(ip);
          });
      }
      
      if (b64UrlRegex.test(str)) endpoints.add('obfuscated:base64');
      if (hexUrlRegex.test(str)) endpoints.add('obfuscated:hex');
      if (reversedUrlRegex.test(str)) endpoints.add('obfuscated:reversed');

      const dataInUrlMatch = str.match(/[?&][a-zA-Z0-9_-]+=[a-zA-Z0-9+/]{32,}[=]{0,2}/);
      if (dataInUrlMatch && (str.includes('http') || str.includes('wss'))) {
          findings.push({
             id: 'network-egress-data-in-url',
             severity: 'HIGH',
             description: `Potential data exfiltration via URL query parameter: ${dataInUrlMatch[0]}`,
             fixRecommendation: 'Avoid transmitting large amounts of data in URL query parameters. Use POST request bodies with encryption.'
          });
      }
  };

  if (server.args) {
    for (const arg of server.args) {
      if (typeof arg !== 'string') continue;
      checkString(arg);
    }
  }

  const serverStr = JSON.stringify(server).toLowerCase();
  
  if (serverStr.includes('child_process') && (serverStr.includes('exec') || serverStr.includes('spawn')) && 
      (serverStr.includes('curl') || serverStr.includes('wget'))) {
      findings.push({
          id: 'network-egress-bypass-attempt',
          severity: 'HIGH',
          description: `Server uses child_process with curl/wget, which can bypass network restrictions and policy controls.`
      });
  }

  checkString(JSON.stringify(server));

  // Non-standard port detection
  const wssRegex = /wss?:\/\/[^\s"']+/g;
  const wssMatches = serverStr.match(wssRegex);
  if (wssMatches) {
      wssMatches.forEach(w => endpoints.add(w));
  }

  if (/(https?|wss?):\/\/[a-zA-Z0-9.-]+:[0-9]{4,5}/.test(JSON.stringify(server))) {
     const isLocalhostPort = /localhost:[0-9]+/.test(JSON.stringify(server)) || /127\.0\.0\.1:[0-9]+/.test(JSON.stringify(server));
     if (!isLocalhostPort) {
         findings.push({
            id: 'network-egress-non-standard-port',
            severity: 'MEDIUM',
            description: `Server connects to external non-standard ports (e.g., above 1024).`
         });
     }
  }

  for (const endpoint of endpoints) {
     if (endpoint.startsWith('ipv6:')) {
        findings.push({
           id: 'network-egress-raw-ip',
           severity: 'HIGH',
           description: `Server connects to raw IPv6 address: ${endpoint.slice(5)}`,
           fixRecommendation: 'Use domain names instead of raw IP addresses for better auditability.'
        });
        continue;
     }

     if (endpoint.startsWith('obfuscated:')) {
        findings.push({
           id: 'network-egress-obfuscated',
           severity: 'HIGH',
           description: `Server contains obfuscated URLs (${endpoint.split(':')[1]}).`,
           fixRecommendation: 'Remove obfuscated network endpoints. Use clear configuration.'
        });
        continue;
     }

     if (/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/.test(endpoint)) {
        findings.push({
           id: 'network-egress-raw-ip',
           severity: 'HIGH',
           description: `Server connects directly to raw external IP address: ${endpoint}`,
           fixRecommendation: 'Use domain names instead of raw IP addresses to allow for better policy enforcement.'
        });
        continue;
     }

     let category = 'unknown';
     const host = endpoint.replace(/^(?:https?|wss?):\/\//, '').split(/[/:]/)[0].toLowerCase();
     for (const [cat, domains] of Object.entries(KNOWN_ENDPOINTS)) {
         // Registered-domain matching: 'api.openai.com.evil.io' must not be
         // classified as OpenAI, and 'telemetry' must not match any URL
         // that merely contains the word.
         if (domains.some(d => host === d.toLowerCase() || host.endsWith('.' + d.toLowerCase()))) {
             category = cat;
             break;
         }
     }

     if (category === 'telemetry') {
         findings.push({
             id: 'network-egress-telemetry',
             severity: 'MEDIUM',
             description: `Server contacts telemetry/analytics endpoints: ${endpoint}`,
             fixRecommendation: 'Review if telemetry collection is necessary and complies with privacy policy.'
         });
     } else if (category === 'suspicious') {
         findings.push({
             id: 'network-egress-suspicious',
             severity: 'HIGH',
             description: `Server contacts known suspicious or exfiltration endpoints: ${endpoint}`,
             fixRecommendation: 'Immediately audit this server for potential malicious activity.'
         });
     } else if (category === 'api') {
         findings.push({
             id: 'network-egress-api',
             severity: 'INFO',
             description: `Server contacts known API endpoint: ${endpoint}`
         });
     } else if (category === 'cdn') {
         findings.push({
             id: 'network-egress-cdn',
             severity: 'INFO',
             description: `Server loads resources from CDN: ${endpoint}`
         });
     } else if (category === 'unknown' && !endpoint.includes('localhost') && !endpoint.includes('127.0.0.1')) {
         findings.push({
             id: 'network-egress-unknown',
             severity: 'MEDIUM',
             description: `Server contacts unknown external endpoint: ${endpoint}`
         });
     }
  }

  // Deduplicate findings
  const uniqueFindings = [];
  const seen = new Set();
  for (const f of findings) {
      const key = `${f.id}-${f.description}`;
      if (!seen.has(key)) {
          seen.add(key);
          uniqueFindings.push(f);
      }
  }

  return uniqueFindings;
}
