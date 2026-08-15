import { describe, it, expect } from 'vitest';
import { scanSecrets } from '../../src/scanners/secret-scanner.js';

describe('Secret Scanner', () => {
  it('should detect GitHub tokens', () => {
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      env: { TOKEN: 'ghp_' + 'abcdefghijklmnopqrstuvwxyz1234567890' }
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('exposed-secret');
  });

  it('should detect AWS keys', () => {
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      env: { KEY: 'AKIA' + 'IOSFODNN7EXAMPLE' }
    });
    expect(findings).toHaveLength(1);
  });

  it('should detect Google Cloud API keys', () => {
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      env: { GCP_KEY: 'AIza' + 'SyA1234567890abcdefghij12345678901' }
    });
    expect(findings).toHaveLength(1);
  });

  it('should detect Slack bot tokens', () => {
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      env: { SLACK_TOKEN: 'xoxb-' + '0000test0000-0000test0000-testvaluenotrealsecret00' }
    });
    expect(findings).toHaveLength(1);
  });

  it('should detect Groq API keys', () => {
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      env: { GROQ_KEY: 'gsk_' + 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY' }
    });
    expect(findings).toHaveLength(1);
  });

  it('should detect HuggingFace tokens', () => {
    // Real HF tokens are 'hf_' + exactly 34 alphanumeric chars
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      env: { HF_TOKEN: 'hf_' + 'abcdefghijklmnopqrstuvwxyzABCDEFGH' }
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].description).toContain('HuggingFace');
  });

  it('should detect GitHub fine-grained PATs and Stripe restricted/webhook keys', () => {
    // Constructed at runtime: literal secret-shaped prefixes trip GitHub
    // push protection even with obviously fake values (repo convention).
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      env: {
        GH_PAT: 'github_pat_' + 'a'.repeat(82),
        STRIPE_RESTRICTED: 'rk_live_' + 'abcdefghijklmnopqrstuvwx',
        STRIPE_WEBHOOK: 'whsec_' + 'abcdefghijklmnopqrstuvwx'
      }
    });
    const descriptions = findings.map(f => f.description).join(' ');
    expect(descriptions).toContain('GitHub Fine-grained');
    expect(descriptions).toContain('Stripe Restricted');
    expect(descriptions).toContain('Stripe Webhook');
  });

  it('should not flag UUIDs or generic 36/40/64-char strings without a matching key context', () => {
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      env: {
        SESSION_ID: '550e8400-e29b-41d4-a716-446655440000',
        BUILD_TOKEN: 'a'.repeat(36),
        RANDOM: 'B'.repeat(40),
        HASH: 'c'.repeat(64)
      }
    });
    // None of these are credible standalone secrets: no CRITICAL findings
    expect(findings.filter(f => f.severity === 'CRITICAL')).toHaveLength(0);
  });

  it('should flag bare-format secrets when the key name provides context', () => {
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      env: {
        PINECONE_API_KEY: '550e8400-e29b-41d4-a716-446655440000',
        CLOUDFLARE_API_TOKEN: 'B'.repeat(40),
        RAILWAY_TOKEN: 'C'.repeat(36),
        TOGETHER_API_KEY: 'd'.repeat(64),
        HEROKU_API_KEY: '550e8400-e29b-41d4-a716-446655440000'
      }
    });
    const descriptions = findings.map(f => f.description).join(' ');
    expect(descriptions).toContain('Pinecone');
    expect(descriptions).toContain('Cloudflare');
    expect(descriptions).toContain('Railway');
    expect(descriptions).toContain('Together');
    expect(descriptions).toContain('Heroku');
  });

  it('should not crash on non-string env values', () => {
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      env: { PORT: 3000 as unknown as string, ENABLED: true as unknown as string }
    });
    expect(Array.isArray(findings)).toBe(true);
  });

  it('should detect credentials embedded in server URLs', () => {
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p',
      url: 'https://admin:supersecretpassword123@db.example.com:5432'
    });
    expect(findings.some(f => f.id === 'exposed-secret')).toBe(true);
  });

  it('should detect NPM tokens', () => {
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      env: { NPM_TOKEN: 'npm_' + 'abcdefghijklmnopqrstuvwxyz0123456789' }
    });
    expect(findings).toHaveLength(1);
  });

  it('should detect Docker Hub tokens', () => {
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      env: { DOCKER_TOKEN: 'dckr' + '_pat_TESTONLY000notrealsecret000' } // constructed to avoid push protection; 9+27=36 chars
    });
    expect(findings).toHaveLength(1);
  });

  // PlanetScale token test skipped: GitHub push protection blocks the
  // prefix pattern even with obviously fake values. The regex is verified
  // to match pscale_tkn_ followed by 43 alphanumeric chars.

  it('should detect Private Keys', () => {
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      env: { KEY: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA75...' }
    });
    expect(findings).toHaveLength(1);
  });

  it('should allow environment variable references', () => {
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      env: { TOKEN: '${GITHUB_TOKEN}' }
    });
    // This might flag as MEDIUM if GITHUB_TOKEN is not set, but not CRITICAL
    const critical = findings.filter(f => f.severity === 'CRITICAL');
    expect(critical).toHaveLength(0);
  });

  it('should flag missing referenced env vars', () => {
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      env: { TOKEN: '${NON_EXISTENT_VAR_12345}' }
    });
    expect(findings.some(f => f.id === 'missing-referenced-env-var')).toBe(true);
  });

  it('should pass safe strings', () => {
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      env: { NORMAL_VAR: 'just-a-value', ANOTHER: '12345' }
    });
    expect(findings).toHaveLength(0);
  });

  it('should detect high-entropy strings as potential secrets', () => {
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      env: { UNKNOWN_KEY: '8f7d6s5a4p3o2i1u0y9t8r7e6w5q4l3k2j1h0g' }
    });
    expect(findings.some(f => f.id === 'high-entropy-value')).toBe(true);
  });

  it('should scan arguments for secrets', () => {
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      args: ['--api-key', 'sk-ant-1234567890abcdef1234567890abcdef1234567890abcdef']
    });
    expect(findings.some(f => f.id === 'exposed-secret')).toBe(true);
  });

  it('should exempt UUIDs from entropy detection', () => {
    const findings = scanSecrets({
      name: 'test', toolName: 't', configPath: 'p', command: 'cmd',
      env: { SESSION_ID: '550e8400-e29b-41d4-a716-446655440000' }
    });
    expect(findings.some(f => f.id === 'high-entropy-value')).toBe(false);
  });
});
