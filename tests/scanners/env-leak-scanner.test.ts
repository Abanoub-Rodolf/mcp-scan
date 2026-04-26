import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import { scanEnvLeak } from '../../src/scanners/env-leak-scanner.js';
import { ResolvedServer } from '../../src/types/config.js';

vi.mock('fs');

describe('Env Leak Scanner', () => {
  const mockServer: ResolvedServer = {
    name: 'test-server',
    toolName: 'test-tool',
    configPath: '/test/path/config.json',
    command: 'test-command',
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should detect exposed secrets in .env file', () => {
    const envContent = `
      API_KEY=this_is_a_very_long_secret_key_that_should_be_detected
      DB_PASSWORD=another_long_password_1234567890
      SAFE_VAR=short
      # COMMENT=this_should_be_ignored
    `;

    vi.mocked(fs.existsSync).mockImplementation((p) => String(p) === '/test/path/.env');
    vi.mocked(fs.readFileSync).mockReturnValue(envContent);

    const findings = scanEnvLeak(mockServer, '/test/path/config.json');

    expect(findings).toHaveLength(2);
    expect(findings[0].id).toBe('env-secret-exposed');
    expect(findings[0].severity).toBe('HIGH');
    expect(findings[0].description).toContain('API_KEY');
    expect(findings[1].description).toContain('DB_PASSWORD');
  });

  it('should skip placeholder values', () => {
    const envContent = `
      API_KEY=YOUR_API_KEY_HERE
      STRIPE_SECRET=REPLACE_ME_WITH_ACTUAL_SECRET
    `;

    vi.mocked(fs.existsSync).mockImplementation((p) => String(p) === '/test/path/.env');
    vi.mocked(fs.readFileSync).mockReturnValue(envContent);

    const findings = scanEnvLeak(mockServer, '/test/path/config.json');

    expect(findings).toHaveLength(0);
  });

  it('should search parent directories for .env file', () => {
    vi.mocked(fs.existsSync).mockImplementation((p) => String(p) === '/test/.env');
    vi.mocked(fs.readFileSync).mockReturnValue('API_KEY=this_is_a_very_long_secret_key_that_should_be_detected');

    const findings = scanEnvLeak(mockServer, '/test/path/config.json');

    expect(findings).toHaveLength(1);
    expect(findings[0].description).toContain('API_KEY');
    expect(vi.mocked(fs.existsSync)).toHaveBeenCalledWith('/test/path/.env');
    expect(vi.mocked(fs.existsSync)).toHaveBeenCalledWith('/test/.env');
  });

  it('should stop climbing after finding env files in a directory', () => {
    vi.mocked(fs.existsSync).mockImplementation((p) => {
      const s = String(p);
      return s === '/test/path/.env' || s === '/test/.env';
    });
    vi.mocked(fs.readFileSync).mockReturnValue('API_KEY=first_one_detected_long_enough_123');

    const findings = scanEnvLeak(mockServer, '/test/path/config.json');

    expect(findings).toHaveLength(1);
    expect(vi.mocked(fs.readFileSync)).toHaveBeenCalledWith('/test/path/.env', 'utf-8');
    expect(vi.mocked(fs.readFileSync)).not.toHaveBeenCalledWith('/test/.env', 'utf-8');
  });

  it('should scan all env file variants in the same directory', () => {
    const envPaths: Record<string, string> = {
      '/test/path/.env': 'API_KEY=template_value_long_enough_to_count_xx',
      '/test/path/.env.production': 'PROD_DB_PASSWORD=production_secret_long_enough_to_count_xx',
      '/test/path/.env.staging': 'STAGE_TOKEN=staging_secret_long_enough_to_count_xx',
    };
    vi.mocked(fs.existsSync).mockImplementation((p) => String(p) in envPaths);
    vi.mocked(fs.readFileSync).mockImplementation(((p: unknown) => envPaths[String(p)]) as unknown as typeof fs.readFileSync);

    const findings = scanEnvLeak(mockServer, '/test/path/config.json');

    expect(findings).toHaveLength(3);
    expect(findings.find(f => f.description.includes('.env.production'))).toBeDefined();
    expect(findings.find(f => f.description.includes('.env.staging'))).toBeDefined();
  });

  it('should return empty array if no .env file found', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);

    const findings = scanEnvLeak(mockServer, '/test/path/config.json');

    expect(findings).toHaveLength(0);
  });
});
