import { ResolvedServer } from '../types/config.js';
import { Finding } from '../types/scan-result.js';

/**
 * Source-aware sibling of ast-scanner.ts's scanAst(). scanAst's regexes were
 * tuned for a short CLI argument string; scripts/source-scan.mjs instead
 * stuffs an entire package source file into a single fake `args` entry
 * (toFileServer), which made those same regexes fire on almost anything
 * (316 of 378 HIGH/CRITICAL findings in the 2026-09-05 ecosystem sweep).
 * This runs the same checks one string literal at a time, on comment-
 * stripped code, so a doc-comment URL or an ordinary template literal can no
 * longer combine with an unrelated part of the file to produce a false HIGH.
 * scanAst itself is untouched and must stay byte-identical for real MCP
 * config scans - do not merge these two paths.
 */

const MAX_QUOTE_LEN = 120;
function quote(s: string): string {
  return s.length > MAX_QUOTE_LEN ? s.slice(0, MAX_QUOTE_LEN) : s;
}

interface Literal {
  text: string;
  line: number; // 1-based, into strippedLines
}

/**
 * Minimal string/comment-aware tokenizer - not a real JS/TS parser. Strips
 * // and /* comments (so a doc-comment URL or a "TODO: .env" note can never
 * feed a rule) and collects every quoted string's raw contents as a
 * separate literal, tagged with the line it starts on so rules can check
 * "is this URL on a line that also calls fetch(" without rejoining the
 * whole file into one blob.
 */
function tokenize(source: string): { strippedLines: string[]; literals: Literal[] } {
  let i = 0;
  const n = source.length;
  let out = '';
  const literals: Literal[] = [];
  let line = 1;

  while (i < n) {
    const c = source[i];
    if (c === '/' && source[i + 1] === '/') {
      while (i < n && source[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && source[i + 1] === '*') {
      i += 2;
      while (i < n && !(source[i] === '*' && source[i + 1] === '/')) {
        if (source[i] === '\n') { line++; out += '\n'; }
        i++;
      }
      i += 2;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      const quoteChar = c;
      const startLine = line;
      let j = i + 1;
      let buf = '';
      while (j < n) {
        if (source[j] === '\\') { buf += source[j] + (source[j + 1] ?? ''); j += 2; continue; }
        if (source[j] === '\n') line++;
        if (source[j] === quoteChar) { j++; break; }
        buf += source[j];
        j++;
      }
      literals.push({ text: buf, line: startLine });
      out += quoteChar + buf + quoteChar;
      i = j;
      continue;
    }
    if (c === '\n') line++;
    out += c;
    i++;
  }
  return { strippedLines: out.split('\n'), literals };
}

// Whole trimmed text must be exactly one quoted literal (no `+` concat,
// no template interpolation) to count as "plain" - anything else (a bare
// identifier, string concatenation, an interpolated template) is dynamic.
function isPlainStringArg(argText: string): boolean {
  const t = argText.trim();
  if (/^(['"])(?:\\.|(?!\1)[^\\])*\1$/.test(t)) return true;
  const backtick = /^`((?:\\.|[^`\\])*)`$/.exec(t);
  if (backtick) return !backtick[1].includes('${');
  return false;
}

// Best-effort match of a call's FIRST argument only, up to its top-level
// comma or closing paren - so `execSync('a' + b)` reads as dynamic while
// `execSync('a', { encoding: 'utf8' })` still reads its command as the
// plain literal 'a' instead of being poisoned by the options object.
function extractFirstArg(code: string, openParenIndex: number): string {
  let depth = 1;
  let j = openParenIndex + 1;
  let inString: string | null = null;
  let buf = '';
  while (j < code.length && depth > 0) {
    const ch = code[j];
    if (inString) {
      buf += ch;
      if (ch === '\\') { buf += code[j + 1] ?? ''; j += 2; continue; }
      if (ch === inString) inString = null;
      j++;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') { inString = ch; buf += ch; j++; continue; }
    if (ch === '(' || ch === '[' || ch === '{') { depth++; buf += ch; j++; continue; }
    if (ch === ')' || ch === ']' || ch === '}') { depth--; if (depth === 0) break; buf += ch; j++; continue; }
    if (ch === ',' && depth === 1) break;
    buf += ch;
    j++;
  }
  return buf;
}

const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
const DOMAIN_RE = /\b(?:https?:\/\/)?(?:[\w-]+\.)+[\w-]{2,}\b/;
const FILE_EXTENSIONS = new Set([
  'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'py', 'json', 'yaml', 'yml', 'sh', 'bash',
  'exe', 'dll', 'so', 'dylib', 'txt', 'md', 'html', 'css', 'xml', 'csv', 'log', 'sql',
  'rb', 'go', 'rs', 'java', 'c', 'cpp', 'h', 'hpp', 'php', 'pl', 'ps1', 'bat', 'cmd',
  'jar', 'war', 'zip', 'tar', 'gz', 'env', 'lock', 'toml', 'ini', 'cfg', 'conf',
]);
// Documentation/schema hosts a legitimate zod/json-schema file routinely
// quotes verbatim (e.g. a `$schema` field) - never a real exfiltration target.
const DOC_HOST_RE = /(?:^|\.)(?:json-schema\.org|w3\.org|spdx\.org|schema\.org)$/i;
const NETWORK_CALL_CTX_RE = /\b(?:fetch|axios|got|undici|ky|XMLHttpRequest)\s*\(|https?\.(?:request|get)\s*\(|new\s+WebSocket\s*\(|new\s+URL\s*\(/;
const SENSITIVE_PATH_RE = /(?:^|[/~])\.(?:ssh|aws|gnupg)(?:\/|$)|(?:^|[/~])\.env(?:\.[\w.-]+)?(?:\/|$)/;

function isAllowedHost(host: string, allowedDomains: string[]): boolean {
  const h = host.toLowerCase();
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1' || h.endsWith('.localhost')) return true;
  return allowedDomains.some(d => {
    const dh = d.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    return h === dh || h.endsWith('.' + dh);
  });
}

function isImportOrRequireLine(line: string): boolean {
  return /^\s*import\b/.test(line) || /\brequire\s*\(\s*$/.test(line.split(/['"`]/)[0] ?? '');
}

export function scanAstSource(server: ResolvedServer, allowedDomains: string[] = []): Finding[] {
  if (!server.command) return [];
  const argsArray = server.args ? (Array.isArray(server.args) ? server.args : Object.values(server.args)) : [];
  const findings: Finding[] = [];

  for (const arg of argsArray) {
    if (typeof arg !== 'string') continue;
    const { strippedLines, literals } = tokenize(arg);
    const strippedCode = strippedLines.join('\n');

    // 1. eval(/new Function( are dangerous by construction; exec/execSync
    // need a dynamic (non-literal) argument to count as dangerous - a
    // hardcoded `execSync('npm run build')` is noise, and `someRegex.exec(x)`
    // (a RegExp method call, not child_process) must not match at all.
    // Puppeteer/Cheerio's page.$eval(/el.$$eval( are extremely common and
    // not global eval() - a `.` or `$` immediately before "eval(" means
    // it's a method call on some other object, not the dangerous builtin.
    for (const m of strippedCode.matchAll(/(?<![.$])\beval\s*\(/g)) {
      findings.push({
        id: 'suspicious-execution', severity: 'HIGH',
        description: `Source calls eval(: '${quote(strippedCode.slice(m.index, m.index! + 60))}'.`,
        fixRecommendation: 'Avoid eval(). Use JSON.parse or an explicit parser instead.',
      });
    }
    for (const m of strippedCode.matchAll(/\bnew\s+Function\s*\(/g)) {
      findings.push({
        id: 'suspicious-execution', severity: 'HIGH',
        description: `Source calls new Function(: '${quote(strippedCode.slice(m.index, m.index! + 60))}'.`,
        fixRecommendation: 'Avoid the Function constructor with dynamic bodies.',
      });
    }
    const execRe = /(?<!\.)\bexec\s*\(|\bexecSync\s*\(/g;
    for (const m of strippedCode.matchAll(execRe)) {
      const openParen = m.index! + m[0].length - 1;
      const firstArg = extractFirstArg(strippedCode, openParen);
      const dynamic = !isPlainStringArg(firstArg);
      findings.push({
        id: 'suspicious-execution', severity: dynamic ? 'HIGH' : 'MEDIUM',
        description: `Command execution call ${dynamic ? 'with a dynamic/built argument' : 'on a hardcoded literal'}: '${quote(m[0] + firstArg)}'.`,
        fixRecommendation: 'Avoid shell exec with dynamic input. Use execFile with an argument array instead.',
      });
    }

    // Per-literal checks. Real dangerous shell strings, glob patterns, and
    // env-var-fed URLs are attacker-controlled content living inside one
    // string literal - evaluating each literal on its own is what stops an
    // unrelated URL or template literal elsewhere in the file from
    // combining into a false finding.
    for (const lit of literals) {
      const text = lit.text;

      // 2. curl/wget piping to/from another tool - the pipe must be a real
      // shell pipe inside this literal, not a `||` that happens to share a
      // line with the words "curl"/"wget".
      if (/\|\s*(?:curl|wget|nc|netcat|socat)\b/.test(text) || /\b(?:curl|wget)\b[^|]*\|(?!\|)/.test(text)) {
        findings.push({
          id: 'data-exfiltration-risk', severity: 'CRITICAL',
          description: `Command string pipes data to/from a network transfer tool: '${quote(text)}'.`,
          fixRecommendation: 'Never pipe sensitive data to network tools. Use authenticated HTTPS APIs instead.',
        });
      }

      // 6. Reverse shells - unchanged connection-intent requirement from
      // ast-scanner.ts, scoped to one literal instead of the whole file.
      if (/\b(?:nc|netcat)\b.*\s(?:-[ec]\b|--exec\b)/.test(text) ||
          /\b(?:nc|netcat)\s+(?:-[a-z]+\s+)*\d{1,3}(?:\.\d{1,3}){3}\s+\d{1,5}/.test(text)) {
        findings.push({
          id: 'reverse-shell-risk', severity: 'CRITICAL',
          description: `Command string contains a netcat reverse-shell pattern: '${quote(text)}'.`,
        });
      }

      // 7. Python -c ... exec()/eval().
      if (/\bpython\d*\b.*-c.*(?:exec|eval)\s*\(/.test(text)) {
        findings.push({
          id: 'python-inline-execution', severity: 'CRITICAL',
          description: `Python inline command uses exec()/eval(): '${quote(text)}'.`,
        });
      }

      // 8. Node -e as its own token.
      if (/\bnode\b.*\s-e(?:\s|$)/.test(text)) {
        findings.push({
          id: 'node-inline-execution', severity: 'HIGH',
          description: `Node.js runs inline code via -e: '${quote(text)}'.`,
        });
      }

      // 9. Sensitive glob - both signals must be in the SAME literal, which
      // fixes the whole-file "/** anywhere + .env anywhere" bug by
      // construction (a comment mentioning .env can't feed this at all,
      // since comments never become literals).
      if (/\/\*\*/.test(text) && SENSITIVE_PATH_RE.test(text)) {
        findings.push({
          id: 'sensitive-glob-pattern', severity: 'HIGH',
          description: `Glob pattern may expose a sensitive directory: '${quote(text)}'.`,
        });
      }

      // 3/4. Network endpoint + optional co-located env-var interpolation.
      const hasIp = IP_RE.test(text);
      const domainMatch = text.match(DOMAIN_RE);
      const matchStr = domainMatch ? domainMatch[0] : '';
      const isPathLike = text.startsWith('/') || text.startsWith('./') || text.startsWith('../') ||
        text.startsWith('~/') || text.startsWith('file://');
      const isFilePath = !!domainMatch && !/^https?:\/\//i.test(matchStr) &&
        FILE_EXTENSIONS.has(matchStr.split('.').pop()!.toLowerCase());
      const host = matchStr.replace(/^https?:\/\//i, '').split(/[/:]/)[0];
      const isDocHost = DOC_HOST_RE.test(host);
      const hasExternalDomain = !!domainMatch && !isPathLike && !isFilePath && !isDocHost && !isAllowedHost(host, allowedDomains);

      const lineText = strippedLines[lit.line - 1] ?? '';
      const inNetworkContext = NETWORK_CALL_CTX_RE.test(lineText);
      const isModuleSpecifier = isImportOrRequireLine(lineText);

      if ((hasIp || hasExternalDomain) && inNetworkContext && !isModuleSpecifier) {
        findings.push({
          id: 'exfiltration-vector', severity: 'MEDIUM',
          description: `Network call targets a potential external endpoint: '${quote(text)}'.`,
          fixRecommendation: 'Review if this code should be making outbound network calls to this endpoint.',
        });

        // Env-var-style interpolation in the very same literal that
        // constructs the network call - dropping the original regex's
        // case-insensitive flag means an ordinary `${foo}` template no
        // longer counts, only a real ALL-CAPS env-var-shaped name does.
        // Minimum length 3 excludes minified bundles' single/double-letter
        // renamed variables (`${Z}`, `${S}`) that otherwise trivially match
        // - a real secret name (TOKEN, API_KEY, GITHUB_TOKEN) is never that
        // short.
        if (/\$\{[A-Z0-9_]{3,}\}/.test(text)) {
          findings.push({
            id: 'exfiltration-vector', severity: 'HIGH',
            description: `Network call interpolates an env-var-style value into the request: '${quote(text)}'.`,
            fixRecommendation: 'This is a high-risk exfiltration vector. Avoid passing secrets to external endpoints.',
          });
        }
      }

      // 5. Filesystem access to a sensitive path anywhere in the file,
      // combined with a real (call-context-verified) network endpoint
      // anywhere in the file - both sides are now the narrowed checks
      // above, not raw substring tests.
      if (SENSITIVE_PATH_RE.test(text) && (isPathLike || /^[\w.-]+$/.test(text) === false)) {
        const hasNetworkElsewhere = literals.some(other => {
          const otherLine = strippedLines[other.line - 1] ?? '';
          if (!NETWORK_CALL_CTX_RE.test(otherLine) || isImportOrRequireLine(otherLine)) return false;
          const otherDomain = other.text.match(DOMAIN_RE);
          return IP_RE.test(other.text) || (!!otherDomain && !DOC_HOST_RE.test(otherDomain[0].replace(/^https?:\/\//i, '').split(/[/:]/)[0]));
        });
        if (hasNetworkElsewhere) {
          findings.push({
            id: 'exfiltration-vector', severity: 'HIGH',
            description: `Filesystem path '${quote(text)}' is read alongside code that makes real network calls elsewhere in the file.`,
            fixRecommendation: 'Restrict the tool to either filesystem access or network access, but not both if possible.',
          });
        }
      }
    }
  }

  return findings;
}
