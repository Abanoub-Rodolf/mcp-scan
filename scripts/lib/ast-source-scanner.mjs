import ts from 'typescript';

/**
 * Source-aware sibling of ast-scanner.ts's scanAst(). scanAst's regexes were
 * tuned for a short CLI argument string; scripts/source-scan.mjs instead
 * stuffs an entire package source file into a single fake `args` entry
 * (toFileServer), which made those same regexes fire on almost anything
 * (316 of 378 HIGH/CRITICAL findings in the 2026-09-05 ecosystem sweep).
 * This runs the same checks one string/template/regex literal at a time.
 * scanAst itself is untouched and must stay byte-identical for real MCP
 * config scans - do not merge these two paths.
 *
 * Previous versions of this file hand-rolled a comment/string/regex-aware
 * tokenizer to split source into literals. Three cold reviews each found a
 * new bypass in that tokenizer's guessing (a `//` inside a regex read as a
 * line comment; a division after `}` swallowing a whole string as "regex
 * text"; an in-class quote exemption smuggling a payload past every rule).
 * The root cause was parsing a language without a parser. This version
 * uses the TypeScript compiler API (already a devDependency, handles .ts/
 * .tsx/.js/.mjs/.cjs natively) to get real StringLiteral,
 * NoSubstitutionTemplateLiteral, TemplateExpression and
 * RegularExpressionLiteral nodes with exact positions and zero ambiguity
 * about where one ends and the next begins.
 *
 * Lives under scripts/, not src/scanners/: its only real caller is
 * scripts/source-scan.mjs (internal ecosystem-campaign tooling), not the
 * real MCP-config scan path (src/commands/scan.ts only imports scanAst).
 * Keeping it here means `typescript` never needs to become a runtime
 * dependency of the published CLI package.
 */

const MAX_QUOTE_LEN = 120;
function quote(s) {
  return s.length > MAX_QUOTE_LEN ? s.slice(0, MAX_QUOTE_LEN) : s;
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
// Matches only when a call's first argument, once unquoted and trimmed, IS a
// shell name (optionally path-qualified, e.g. '/bin/bash', or Windows-style
// 'bash.exe') - i.e. argv[0] itself, not merely a token that appears
// somewhere in the argument list.
const SHELL_NAME_RE = /^(?:.*[\\/])?(?:bash|sh|zsh|fish|ksh|csh)(?:\.exe)?$/;
const SHELL_CALLEE_NAMES = new Set(['spawn', 'execFile', 'spawnSync', 'execFileSync']);

function isAllowedHost(host, allowedDomains) {
  const h = host.toLowerCase();
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1' || h.endsWith('.localhost')) return true;
  return allowedDomains.some((d) => {
    const dh = d.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    return h === dh || h.endsWith('.' + dh);
  });
}

function scriptKindFor(filePath) {
  const ext = (filePath || '').split('.').pop()?.toLowerCase();
  switch (ext) {
    case 'tsx': return ts.ScriptKind.TSX;
    case 'jsx': return ts.ScriptKind.JSX;
    case 'js': case 'mjs': case 'cjs': return ts.ScriptKind.JS;
    default: return ts.ScriptKind.TS; // TS is a syntactic superset of plain JS
  }
}

function isStringLikeLiteral(node) {
  return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isTemplateExpression(node);
}

// Raw slice of the delimiters' interior - not the parser's decoded `.text`.
// Keeps the same semantics the old tokenizer had (backslash escapes and
// `${...}` substitution syntax stay as literal characters, not evaluated),
// so a template's raw content ('${GITHUB_TOKEN}' as text, not the resolved
// value) is what the env-var-interpolation rule matches against.
function rawInterior(node, sourceFile) {
  return sourceFile.text.slice(node.getStart(sourceFile) + 1, node.getEnd() - 1);
}

// A RegularExpressionLiteral's raw text is "/body/flags" - flags are always
// a trailing run of lowercase letters right after the real closing `/`,
// which the parser has already located unambiguously (that's the whole
// point of using a real parser here). Greedy backtracking on `[\s\S]*`
// finds the rightmost `/` for which everything after it to end-of-string is
// letters-only, i.e. the true closing delimiter, without re-deriving where
// the literal ends ourselves.
function regexLiteralBody(node, sourceFile) {
  const raw = node.getText(sourceFile);
  const m = /^\/([\s\S]*)\/([a-z]*)$/.exec(raw);
  return m ? m[1] : raw;
}

function isImportOrRequireSpecifier(node) {
  const parent = node.parent;
  if (!parent) return false;
  if (ts.isImportDeclaration(parent) || ts.isExportDeclaration(parent)) return true;
  if (ts.isCallExpression(parent) && parent.arguments[0] === node) {
    if (parent.expression.kind === ts.SyntaxKind.ImportKeyword) return true;
    if (ts.isIdentifier(parent.expression) && parent.expression.text === 'require') return true;
  }
  return false;
}

// Every comment range in the file, collected from the real parse tree (not
// re-derived by scanning raw text) so a `/` or quote inside a string/regex
// literal is never mistaken for comment syntax - the exact class of bug
// this rewrite exists to eliminate. ts.getLeadingCommentRanges only ever
// looks at trivia strictly between two real tokens (a position the parser
// has already fixed), so it can't re-open the same ambiguity.
function collectCommentRanges(sourceFile) {
  const text = sourceFile.getFullText();
  const seen = new Set();
  const ranges = [];
  function record(pos) {
    if (seen.has(pos)) return;
    seen.add(pos);
    for (const r of ts.getLeadingCommentRanges(text, pos) || []) ranges.push(r);
  }
  function visit(node) {
    record(node.getFullStart());
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  record(sourceFile.endOfFileToken.getFullStart());
  return ranges;
}

// The one line of raw source containing `pos`, with any comment ranges on
// that line blanked out (kept the same width, so this stays purely a text
// helper for the same-line network-context check, not a general strip).
function commentFreeLine(sourceFile, commentRanges, lineNumber) {
  const text = sourceFile.getFullText();
  const lineStarts = sourceFile.getLineStarts();
  const start = lineStarts[lineNumber];
  const end = lineNumber + 1 < lineStarts.length ? lineStarts[lineNumber + 1] : text.length;
  let line = text.slice(start, end);
  for (const r of commentRanges) {
    const rs = Math.max(r.pos, start);
    const re = Math.min(r.end, end);
    if (rs < re) {
      const localStart = rs - start;
      const localEnd = re - start;
      line = line.slice(0, localStart) + ' '.repeat(localEnd - localStart) + line.slice(localEnd);
    }
  }
  return line;
}

function lineOf(sourceFile, node) {
  return sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line; // 0-based
}

const CALL_TEXT_LIMIT = 60;

export function scanAstSource(server, allowedDomains = []) {
  if (!server.command) return [];
  const argsArray = server.args ? (Array.isArray(server.args) ? server.args : Object.values(server.args)) : [];
  const findings = [];
  const scriptKind = scriptKindFor(server.configPath);

  for (const arg of argsArray) {
    if (typeof arg !== 'string') continue;

    let sourceFile;
    try {
      sourceFile = ts.createSourceFile('source.tsx', arg, ts.ScriptTarget.Latest, true, scriptKind);
    } catch (err) {
      findings.push({
        id: 'source-parse-failed', severity: 'MEDIUM',
        description: `Could not parse source as JS/TS (${err instanceof Error ? err.message : String(err)}). This file was not analyzed by ast-scanner - "no findings" below does not mean clean.`,
        fixRecommendation: 'Verify this is valid JavaScript/TypeScript source, not minified/obfuscated content the parser cannot handle.',
      });
      continue;
    }
    const parseDiagnostics = sourceFile.parseDiagnostics;
    if (parseDiagnostics && parseDiagnostics.length > 0) {
      findings.push({
        id: 'source-parse-failed', severity: 'MEDIUM',
        description: `Source has ${parseDiagnostics.length} syntax error(s) and could not be fully parsed. This file was not analyzed by ast-scanner - "no findings" below does not mean clean.`,
        fixRecommendation: 'Verify this is valid JavaScript/TypeScript source.',
      });
      continue;
    }

    const commentRanges = collectCommentRanges(sourceFile);
    // { text, line (0-based), shellShapedOnly } - shellShapedOnly literals
    // (regex bodies) only go through rules 2/6/7/8/9 below, not the
    // domain/IP network-exfiltration rules, to avoid a legitimate
    // URL-matching regex misreading as a real network call.
    const literals = [];

    function pushLiteral(node, shellShapedOnly) {
      literals.push({ node, text: rawInterior(node, sourceFile), line: lineOf(sourceFile, node), shellShapedOnly });
    }

    // --- 1/1b: structural call checks (eval/new Function/exec/execSync/spawn/execFile) ---
    function calleeName(expr) {
      if (ts.isIdentifier(expr)) return expr.text;
      return null; // property-access calls (page.$eval, someRegex.exec, cp.exec) deliberately excluded - see below
    }

    function isPlainLiteralArg(node) {
      return !!node && (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node));
    }

    function checkCall(node) {
      const name = calleeName(node.expression);
      if (name === 'eval') {
        findings.push({
          id: 'suspicious-execution', severity: 'HIGH',
          description: `Source calls eval(: '${quote(node.getText(sourceFile).slice(0, CALL_TEXT_LIMIT))}'.`,
          fixRecommendation: 'Avoid eval(). Use JSON.parse or an explicit parser instead.',
        });
      } else if (name === 'exec' || name === 'execSync') {
        const firstArg = node.arguments[0];
        const dynamic = !isPlainLiteralArg(firstArg);
        findings.push({
          id: 'suspicious-execution', severity: dynamic ? 'HIGH' : 'MEDIUM',
          description: `Command execution call ${dynamic ? 'with a dynamic/built argument' : 'on a hardcoded literal'}: '${quote(node.getText(sourceFile).slice(0, CALL_TEXT_LIMIT))}'.`,
          fixRecommendation: 'Avoid shell exec with dynamic input. Use execFile with an argument array instead.',
        });
      } else if (name && SHELL_CALLEE_NAMES.has(name)) {
        // spawn/execFile(Sync) invoking a shell with -c - a capability
        // scanAst covered on the whole joined command line and the
        // exec/execSync check above doesn't, since the shell name and the
        // -c flag are two separate array elements here.
        const firstArg = node.arguments[0];
        // Known accepted gap: only matches a shell name given as a literal
        // argv[0] string. `const shell = 'bash'; spawn(shell, ['-c', x])`
        // resolves `shell` to a variable and is invisible here - this is a
        // syntactic scanner, not data-flow analysis.
        const isShellLiteral = isPlainLiteralArg(firstArg) && SHELL_NAME_RE.test(rawInterior(firstArg, sourceFile).trim());
        if (isShellLiteral) {
          const secondArg = node.arguments[1];
          let hasDashC = false;
          if (secondArg && ts.isArrayLiteralExpression(secondArg)) {
            hasDashC = secondArg.elements.some((el) => isPlainLiteralArg(el) && rawInterior(el, sourceFile).trim() === '-c');
          } else if (secondArg) {
            hasDashC = /(['"`])-c\1/.test(secondArg.getText(sourceFile));
          }
          if (hasDashC) {
            findings.push({
              id: 'suspicious-execution', severity: 'HIGH',
              description: `Shell exec via ${name}( with a shell -c argument: '${quote(node.getText(sourceFile).slice(0, CALL_TEXT_LIMIT + 40))}'.`,
              fixRecommendation: 'Avoid spawning a shell with -c and untrusted input. Pass the command and its arguments directly instead of invoking a shell.',
            });
          }
        }
      }
    }

    // --- 9b: sensitive-glob evasion via `+`-concatenated adjacent literals ---
    function flattenPlusChain(node, out) {
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
        flattenPlusChain(node.left, out);
        flattenPlusChain(node.right, out);
      } else {
        out.push(node);
      }
    }
    function checkConcatGlob(node) {
      // Only handle the outermost `+` of a chain to avoid re-processing
      // the same chain once per nested BinaryExpression.
      if (node.parent && ts.isBinaryExpression(node.parent) && node.parent.operatorToken.kind === ts.SyntaxKind.PlusToken) return;
      const operands = [];
      flattenPlusChain(node, operands);
      // Longest run of adjacent string-literal-shaped operands.
      let run = [];
      const flush = () => {
        if (run.length >= 2) {
          const joined = run.map((n) => rawInterior(n, sourceFile)).join('');
          if (/\/\*\*/.test(joined) && SENSITIVE_PATH_RE.test(joined)) {
            findings.push({
              id: 'sensitive-glob-pattern', severity: 'HIGH',
              description: `Glob pattern assembled from concatenated string literals may expose a sensitive directory: '${quote(joined)}'.`,
              fixRecommendation: 'Avoid building sensitive glob patterns from concatenated string literals; write the path directly so it is reviewable.',
            });
          }
        }
        run = [];
      };
      for (const op of operands) {
        if (ts.isStringLiteral(op) || ts.isNoSubstitutionTemplateLiteral(op)) run.push(op);
        else flush();
      }
      flush();
    }

    // Regex literals need their own raw-text extraction (body between the
    // delimiters, flags excluded) - distinct from pushLiteral's quote-aware
    // slicing used for string/template literals.
    function pushRegexLiteral(node) {
      literals.push({ node, text: regexLiteralBody(node, sourceFile), line: lineOf(sourceFile, node), shellShapedOnly: true });
    }
    function walk(node) {
      if (ts.isCallExpression(node)) checkCall(node);
      if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'Function') {
        findings.push({
          id: 'suspicious-execution', severity: 'HIGH',
          description: `Source calls new Function(: '${quote(node.getText(sourceFile).slice(0, CALL_TEXT_LIMIT))}'.`,
          fixRecommendation: 'Avoid the Function constructor with dynamic bodies.',
        });
      }
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) checkConcatGlob(node);
      if (isStringLikeLiteral(node)) pushLiteral(node, false);
      else if (ts.isRegularExpressionLiteral(node)) pushRegexLiteral(node);
      ts.forEachChild(node, walk);
    }
    walk(sourceFile);

    // --- per-literal checks (rules 2,3,4,5,6,7,8,9) ---
    for (const lit of literals) {
      const text = lit.text;

      // 2. curl/wget piping to/from another tool.
      if (/\|\s*(?:curl|wget|nc|netcat|socat)\b/.test(text) || /\b(?:curl|wget)\b[^|]*\|(?!\|)/.test(text)) {
        findings.push({
          id: 'data-exfiltration-risk', severity: 'CRITICAL',
          description: `Command string pipes data to/from a network transfer tool: '${quote(text)}'.`,
          fixRecommendation: 'Never pipe sensitive data to network tools. Use authenticated HTTPS APIs instead.',
        });
      }

      // 6. Reverse shells.
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

      // 9. Sensitive glob - both signals in the same literal.
      if (/\/\*\*/.test(text) && SENSITIVE_PATH_RE.test(text)) {
        findings.push({
          id: 'sensitive-glob-pattern', severity: 'HIGH',
          description: `Glob pattern may expose a sensitive directory: '${quote(text)}'.`,
        });
      }

      if (lit.shellShapedOnly) continue; // regex-literal bodies stop here - see note at `literals` declaration

      // 3/4. Network endpoint + optional co-located env-var interpolation.
      const hasIp = IP_RE.test(text);
      const domainMatch = text.match(DOMAIN_RE);
      const matchStr = domainMatch ? domainMatch[0] : '';
      const isPathLike = text.startsWith('/') || text.startsWith('./') || text.startsWith('../') ||
        text.startsWith('~/') || text.startsWith('file://');
      const isFilePath = !!domainMatch && !/^https?:\/\//i.test(matchStr) &&
        FILE_EXTENSIONS.has(matchStr.split('.').pop().toLowerCase());
      const host = matchStr.replace(/^https?:\/\//i, '').split(/[/:]/)[0];
      const isDocHost = DOC_HOST_RE.test(host);
      const hasExternalDomain = !!domainMatch && !isPathLike && !isFilePath && !isDocHost && !isAllowedHost(host, allowedDomains);

      // Known accepted gap (unchanged from the tokenizer version): this only
      // looks at the line the literal itself starts on, so a Prettier-
      // wrapped multi-line call or a URL built in a variable and passed to
      // fetch() elsewhere never matches here. network-egress-scanner still
      // independently catches the bare URL at MEDIUM.
      const lineText = commentFreeLine(sourceFile, commentRanges, lit.line);
      const inNetworkContext = NETWORK_CALL_CTX_RE.test(lineText);
      const isModuleSpecifier = isImportOrRequireSpecifier(lit.node);

      if ((hasIp || hasExternalDomain) && inNetworkContext && !isModuleSpecifier) {
        findings.push({
          id: 'exfiltration-vector', severity: 'MEDIUM',
          description: `Network call targets a potential external endpoint: '${quote(text)}'.`,
          fixRecommendation: 'Review if this code should be making outbound network calls to this endpoint.',
        });

        if (/\$\{[A-Z0-9_]{3,}\}/.test(text)) {
          findings.push({
            id: 'exfiltration-vector', severity: 'HIGH',
            description: `Network call interpolates an env-var-style value into the request: '${quote(text)}'.`,
            fixRecommendation: 'This is a high-risk exfiltration vector. Avoid passing secrets to external endpoints.',
          });
        }
      }

      // 5. Filesystem access to a sensitive path, combined with a real
      // network endpoint elsewhere in the file.
      if (SENSITIVE_PATH_RE.test(text) && (isPathLike || /^[\w.-]+$/.test(text) === false)) {
        const hasNetworkElsewhere = literals.some((other) => {
          if (other.shellShapedOnly) return false;
          const otherLine = commentFreeLine(sourceFile, commentRanges, other.line);
          if (!NETWORK_CALL_CTX_RE.test(otherLine) || isImportOrRequireSpecifier(other.node)) return false;
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
