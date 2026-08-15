import { describe, it, expect, vi } from 'vitest';
import { generateHtmlReport, escapeHtml } from '../../src/utils/html-reporter.js';
import { ScanReport } from '../../src/types/scan-result.js';

describe('html-reporter', () => {
  it('escapes server-controlled strings to prevent stored XSS', () => {
    const payload = '<script>alert(1)</script>';
    const mockReport: ScanReport = {
      results: [
        {
          serverName: 'evil" onmouseover="alert(2)',
          toolName: payload,
          configPath: '/path/to/<img src=x onerror=alert(3)>',
          scanDurationMs: 100,
          findings: [
            {
              id: 'prompt-injection-pattern',
              severity: 'HIGH',
              description: `Injected: ${payload} & "quoted"`,
              fixRecommendation: `Fix: ${payload}`
            }
          ]
        }
      ],
      totalScanned: 1,
      criticalCount: 0,
      highCount: 1,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 0,
      totalDurationMs: 100,
      version: '2.0.2'
    };

    const html = generateHtmlReport(mockReport);

    // Raw payloads must never appear
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).not.toContain('<img src=x onerror=alert(3)>');
    // Escaped forms must appear
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).toContain('&lt;img src=x onerror=alert(3)&gt;');
    // Attribute context: quotes escaped
    expect(html).toContain('evil&quot; onmouseover=&quot;alert(2)');
    // Ampersands and quotes in finding text
    expect(html).toContain('&amp; &quot;quoted&quot;');
  });

  it('escapeHtml handles null, numbers, and empty strings', () => {
    expect(escapeHtml(null)).toBe('');
    expect(escapeHtml(undefined)).toBe('');
    expect(escapeHtml(42)).toBe('42');
    expect(escapeHtml('')).toBe('');
    expect(escapeHtml("a'b")).toBe('a&#39;b');
  });

  it('should generate a valid HTML report string', () => {
    const mockReport: ScanReport = {
      results: [
        {
          serverName: 'test-server',
          toolName: 'test-tool',
          configPath: '/path/to/config',
          scanDurationMs: 100,
          findings: [
            {
              id: 'exposed-secret',
              severity: 'CRITICAL',
              description: 'Hardcoded API key found',
              fixRecommendation: 'Use environment variables',
              fixable: true
            }
          ]
        }
      ],
      totalScanned: 1,
      criticalCount: 1,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 0,
      totalDurationMs: 100,
      version: '1.0.3'
    };

    const html = generateHtmlReport(mockReport);

    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('mcp-scan');
    expect(html).toContain('test-server');
    expect(html).toContain('exposed-secret');
    expect(html).toContain('CRITICAL');
    expect(html).toContain('Hardcoded API key found');
  });

  it('should handle empty reports', () => {
    const emptyReport: ScanReport = {
      results: [],
      totalScanned: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 0,
      totalDurationMs: 10,
      version: '1.0.3'
    };

    const html = generateHtmlReport(emptyReport);
    expect(html).toContain('No MCP servers detected');
  });
});
