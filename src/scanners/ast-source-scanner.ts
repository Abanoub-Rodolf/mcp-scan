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

// Chars after which a `/` cannot be division - a value can't precede a
// regex, so these are the operator/punctuator/start-of-expression contexts
// where a regex literal is legal. Not exhaustive (this is a heuristic, not
// a parser): a `)` or `}` closing a previous expression is deliberately
// left out even though `}` closing a *block* (not an object literal) can
// legally precede a regex too - the tokenizer can't tell those two `}`
// cases apart, and treating both as division-only is the safer default
// for a security scanner (it can miss a regex there and fall back to the
// pre-fix behavior on that one `/`, but it will never mis-consume a real
// division as a regex and eat code past it).
const REGEX_PRECEDING_CHARS = new Set(['(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';']);
const REGEX_PRECEDING_KEYWORDS = new Set([
  'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void',
  'throw', 'case', 'do', 'else', 'yield', 'await',
]);

// Looks at the last significant (non-whitespace) token already written to
// `out` to decide whether a `/` at the current position could legally
// start a regex literal. `out` only ever contains already-processed code
// (comments are stripped as we go), so this reflects real preceding syntax.
function canPrecedeRegex(out: string): boolean {
  let k = out.length - 1;
  while (k >= 0 && /\s/.test(out[k])) k--;
  if (k < 0) return true; // start of file/arg string
  const c = out[k];
  if (REGEX_PRECEDING_CHARS.has(c)) return true;
  if (!/[A-Za-z0-9_$]/.test(c)) return false;
  let wordStart = k;
  while (wordStart >= 0 && /[A-Za-z0-9_$]/.test(out[wordStart])) wordStart--;
  return REGEX_PRECEDING_KEYWORDS.has(out.slice(wordStart + 1, k + 1));
}

// Attempts to consume a regex literal starting at source[start] (source[start]
// is '/'). Returns the index just past the literal (including any trailing
// flags), or -1 if this can't be a valid regex here (unterminated before a
// newline or end of input) - callers fall back to treating the '/' as an
// ordinary character, same as before this function existed. Handles
// backslash escapes and character classes (`[...]`, where an unescaped `/`
// does not close the literal) since both are routine in real regexes
// (`/^https?:\/\//`, `/[/]/`). Not a full parser: does not validate that
// bracket/escape nesting inside an adversarially malformed literal is
// well-formed, only that it does not run past a newline.
function consumeRegexLiteral(source: string, start: number): number {
  const n = source.length;
  let j = start + 1;
  let inClass = false;
  while (j < n) {
    const ch = source[j];
    if (ch === '\n') return -1;
    if (ch === '\\') { j += 2; continue; }
    if (ch === '[') { inClass = true; j++; continue; }
    if (ch === ']') { inClass = false; j++; continue; }
    if (ch === '/' && !inClass) {
      j++;
      while (j < n && /[a-zA-Z]/.test(source[j])) j++;
      return j;
    }
    j++;
  }
  return -1;
}

/**
 * Minimal string/comment/regex-aware tokenizer - not a real JS/TS parser.
 * Strips // and /* comments (so a doc-comment URL or a "TODO: .env" note
 * can never feed a rule), skips over regex literals without treating their
 * contents as comment syntax (a `\/` immediately before a regex's closing
 * `/` looks exactly like a `//` line-comment opener to a tokenizer with no
 * regex concept - see canPrecedeRegex/consumeRegexLiteral), and collects
 * every quoted string's raw contents as a separate literal, tagged with the
 * line it starts on so rules can check "is this URL on a line that also
 * calls fetch(" without rejoining the whole file into one blob.
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
    if (c === '/' && canPrecedeRegex(out)) {
      const end = consumeRegexLiteral(source, i);
      if (end !== -1) {
        out += source.slice(i, end);
        i = end;
        continue;
      }
      // Not actually a valid regex here (unterminated) - fall through and
      // treat the '/' as an ordinary character below.
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

// Shared string/paren/bracket-depth-aware scan from just past a call's `(`
// up to either its top-level comma (stopAtTopComma) or its matching closing
// paren - the building block for extractFirstArg (one argument) and
// extractCallArgs (the whole argument list).
function extractCallSpan(code: string, openParenIndex: number, stopAtTopComma: boolean): string {
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
    if (stopAtTopComma && ch === ',' && depth === 1) break;
    buf += ch;
    j++;
  }
  return buf;
}

// Best-effort match of a call's FIRST argument only, up to its top-level
// comma or closing paren - so `execSync('a' + b)` reads as dynamic while
// `execSync('a', { encoding: 'utf8' })` still reads its command as the
// plain literal 'a' instead of being poisoned by the options object.
function extractFirstArg(code: string, openParenIndex: number): string {
  return extractCallSpan(code, openParenIndex, true);
}

// Full argument list of a call, up to its matching closing paren - used by
// rules that need to see two arguments together (e.g. a shell name in arg
// 0 and a `-c` flag in arg 1 of a spawn()/execFile() call).
function extractCallArgs(code: string, openParenIndex: number): string {
  return extractCallSpan(code, openParenIndex, false);
}

function unquote(literalToken: string): string {
  return literalToken.slice(1, -1);
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
// scanAst (ast-scanner.ts) flagged a bare "bash|sh|zsh|fish|ksh|csh -c"
// anywhere in the joined command string; the source-mode rewrite dropped
// that coverage entirely since spawn('bash', ['-c', payload]) never puts
// the shell name and -c adjacent with only whitespace between them the way
// a CLI argv join does. This regex is scoped to one call's argument list
// (see extractCallArgs) rather than the whole file, so a 40-char window
// between the shell name and -c is enough to span the array/quote/comma
// punctuation of a real spawn()/execFile() call without over-matching
// unrelated code elsewhere. Known false-positive: a literal package name
// containing one of these shell names as its own token (e.g. "fish-cli")
// within 40 chars of an unrelated "-c" flag.
const SHELL_EXEC_C_RE = /\b(?:bash|sh|zsh|fish|ksh|csh)\b[\s\S]{0,40}-c\b/;

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

    // 1b. spawn/execFile(Sync) invoking a shell with -c - the capability
    // scanAst covered on the whole joined command line (see SHELL_EXEC_C_RE
    // comment) and the per-literal exec/execSync checks above don't, since
    // the shell name and the -c flag are two separate array elements here,
    // not a substring of one command string.
    for (const m of strippedCode.matchAll(/\b(?:spawn|execFile)(?:Sync)?\s*\(/g)) {
      const openParen = m.index! + m[0].length - 1;
      const callArgs = extractCallArgs(strippedCode, openParen);
      if (SHELL_EXEC_C_RE.test(callArgs)) {
        findings.push({
          id: 'suspicious-execution', severity: 'HIGH',
          description: `Shell exec via ${m[0].trim()} with a shell -c argument: '${quote(m[0] + callArgs)}'.`,
          fixRecommendation: 'Avoid spawning a shell with -c and untrusted input. Pass the command and its arguments directly instead of invoking a shell.',
        });
      }
    }

    // 9b. Sensitive-glob evasion via string concatenation - joins a run of
    // two or more string literals connected only by `+` (whitespace
    // allowed) into one virtual string and re-checks the glob rule against
    // it, so '/home/user/' + '.ssh' + '/**' is caught the same as a single
    // literal would be. Deliberately narrow: a chain broken by a bare
    // identifier ('/home/' + dir + '/**') stops there, since that value is
    // truly dynamic and can't be evaluated statically.
    {
      const literalTokenRe = /'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`/g;
      let match: RegExpExecArray | null;
      let prevEnd = -1;
      let joined = '';
      let count = 0;
      const flushChain = () => {
        if (count >= 2 && /\/\*\*/.test(joined) && SENSITIVE_PATH_RE.test(joined)) {
          findings.push({
            id: 'sensitive-glob-pattern', severity: 'HIGH',
            description: `Glob pattern assembled from concatenated string literals may expose a sensitive directory: '${quote(joined)}'.`,
            fixRecommendation: 'Avoid building sensitive glob patterns from concatenated string literals; write the path directly so it is reviewable.',
          });
        }
        joined = '';
        count = 0;
      };
      while ((match = literalTokenRe.exec(strippedCode)) !== null) {
        const text = unquote(match[0]);
        if (prevEnd !== -1 && /^\s*\+\s*$/.test(strippedCode.slice(prevEnd, match.index))) {
          joined += text;
          count += 1;
        } else {
          flushChain();
          joined = text;
          count = 1;
        }
        prevEnd = match.index + match[0].length;
      }
      flushChain();
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

      // Known accepted gap (reviewed 2026-09-06, not an oversight): this
      // only looks at the line the literal itself starts on, so a
      // Prettier-wrapped multi-line call (`fetch(\n  'https://...' + env\n)`)
      // or a URL built in a variable and passed to fetch() elsewhere never
      // matches here. The HIGH env-var-in-URL signal below is knowingly
      // lost in that shape - network-egress-scanner still independently
      // catches the bare URL at MEDIUM (network-egress-unknown), so the
      // finding is downgraded, not silently dropped. Left as-is: fixing it
      // needs real call-boundary tracking across lines, not a per-line regex.
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
