import { describe, it, expect } from 'vitest';
import { scanAst } from '../../src/scanners/ast-scanner.js';
import { scanDataControls } from '../../src/scanners/data-controls-scanner.js';
import { scanNetworkEgress } from '../../src/scanners/network-egress-scanner.js';
import { PII_PATTERNS } from '../../src/data/pii-patterns.js';
import { ResolvedServer } from '../../src/types/config.js';

const phonePattern = PII_PATTERNS.find(p => p.name === 'Phone Number')!;

function freshPhoneRegex(): RegExp {
  return new RegExp(phonePattern.regex.source, phonePattern.regex.flags);
}

describe('Scanner false-positive regressions', () => {
  describe('Phone Number regex', () => {
    it('does not match the trailing 10 digits of a GitHub PAT', () => {
      const pat = 'ghp_' + 'aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678901234567';
      expect(freshPhoneRegex().test(pat)).toBe(false);
    });

    it('does not match the trailing 10 digits of an env-var-style token value', () => {
      const tokenValue = 'GITHUB_PERSONAL_ACCESS_TOKEN=ghp_abcDEFghiJKL1234567890';
      expect(freshPhoneRegex().test(tokenValue)).toBe(false);
    });

    it('still matches a US phone number with dashes', () => {
      expect(freshPhoneRegex().test('Call me at 415-555-1234')).toBe(true);
    });

    it('still matches a US phone number with parens and country code', () => {
      expect(freshPhoneRegex().test('Office: +1 (415) 555-1234')).toBe(true);
    });

    it('still matches a phone number at line start', () => {
      expect(freshPhoneRegex().test('415 555 1234')).toBe(true);
    });
  });

  describe('data-controls API Key keyword detection', () => {
    const baseServer = (description: string): ResolvedServer => ({
      name: 'test',
      toolName: 'test',
      configPath: '/tmp/test.json',
      schema: {
        tools: [{ name: 'tool', description, inputSchema: { properties: {} } }],
      },
    } as unknown as ResolvedServer);

    it('does not flag a tool description containing the word "tokenize"', () => {
      const server = baseServer('Tokenize the input text into BPE tokens for the LLM');
      const findings = scanDataControls(server);
      expect(findings.find(f => f.id === 'data-controls-pii' && f.description.includes('API Key'))).toBeUndefined();
    });

    it('still flags a tool description mentioning access_token', () => {
      const server = baseServer('Send the request with the user access_token in the Authorization header');
      const findings = scanDataControls(server);
      const apiKeyFinding = findings.find(f => f.id === 'data-controls-pii' && f.description.includes('API Key'));
      expect(apiKeyFinding).toBeDefined();
    });

    it('still flags a tool description mentioning bearer_token', () => {
      const server = baseServer('Authenticate via bearer_token passed as parameter');
      const findings = scanDataControls(server);
      const apiKeyFinding = findings.find(f => f.id === 'data-controls-pii' && f.description.includes('API Key'));
      expect(apiKeyFinding).toBeDefined();
    });
  });

  describe('ast-scanner domain regex', () => {
    it('does not flag a local script path arg as an exfiltration vector', () => {
      const findings = scanAst({
        name: 'test', toolName: 't', configPath: 'p', command: 'node',
        args: ['/path/to/mcp-server-starter-pro/dist/index.js'],
      } as unknown as ResolvedServer);
      expect(findings.find(f => f.id === 'exfiltration-vector')).toBeUndefined();
    });

    it('does not flag a python script path arg', () => {
      const findings = scanAst({
        name: 'test', toolName: 't', configPath: 'p', command: 'python3',
        args: ['/path/to/server.py'],
      } as unknown as ResolvedServer);
      expect(findings.find(f => f.id === 'exfiltration-vector')).toBeUndefined();
    });

    it('still flags a bare external domain without a scheme', () => {
      const findings = scanAst({
        name: 'test', toolName: 't', configPath: 'p', command: 'node',
        args: ['--host', 'api.malicious-tld.example'],
      } as unknown as ResolvedServer);
      expect(findings.some(f => f.id === 'exfiltration-vector')).toBe(true);
    });
  });

  describe('network-egress 1.7.x exemption removal', () => {
    it('does not silently exempt 1.7.x.x as if it were a version string', () => {
      const server: ResolvedServer = {
        name: 'test',
        toolName: 'test',
        configPath: '/tmp/test.json',
        url: 'http://1.7.4.2/api',
      } as unknown as ResolvedServer;
      const findings = scanNetworkEgress(server);
      expect(findings.length).toBeGreaterThan(0);
      const endpointFindings = findings.filter(f => f.id.includes('endpoint') || f.id.includes('egress'));
      expect(endpointFindings.length).toBeGreaterThan(0);
    });
  });
});
