// Precision/recall benchmark: mcp-scan (static config scanners, --live) against
// Cisco mcp-scanner (YARA) and Snyk agent-scan, on a labeled corpus of real
// published poisoned servers and real benign servers.
//   node bench/run.mjs [--only ours,cisco,snyk] [--jobs 4]
// Needs `npm run build` first. Competitors need `bench/setup.sh`. Snyk needs
// SNYK_TOKEN; without it Snyk is reported as "not run", never as a score.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { scanLive, scanToolPoisoning, scanPromptInjection, snapshotOf, diffSnapshots } from '../dist/lib.js';

const run = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (n, d) => { const i = args.indexOf(n); return i === -1 ? d : args[i + 1]; };
const only = new Set(opt('--only', 'ours,cisco,snyk').split(','));
const jobs = Number(opt('--jobs', '4'));

const load = (dir) => fs.existsSync(path.join(here, 'corpus', dir))
  ? fs.readdirSync(path.join(here, 'corpus', dir)).filter(f => f.endsWith('.json')).sort().map(f => ({ file: path.join(here, 'corpus', dir, f), ...JSON.parse(fs.readFileSync(path.join(here, 'corpus', dir, f), 'utf8')) }))
  : [];
const samples = [...load('poisoned'), ...load('benign')];
const catalogOf = (s) => ({ tools: s.tools || [], prompts: s.prompts || [], resources: s.resources || [], resourceTemplates: [], instructions: s.instructions || undefined });
const RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const atLeast = (findings, sev) => findings.some(f => RANK[f.severity] >= RANK[sev]);

// Each scanner returns { flagged: boolean, detail } for one sample.
const scanners = {
  // The checks 2.3.0 ran on a server's tool text: config-time regexes over the
  // static schema blob. This is the "before" in the before/after.
  'mcp-scan static (2.3.0 checks)': async (s) => {
    const server = { name: s.id, toolName: 'bench', configPath: 'bench', command: 'node', description: s.instructions || undefined, schema: { tools: s.tools || [] } };
    const f = [...scanToolPoisoning(server), ...scanPromptInjection(server)];
    return { flagged: atLeast(f, 'HIGH'), flaggedMedium: atLeast(f, 'MEDIUM'), detail: f.map(x => x.id).join(',') };
  },
  'mcp-scan --live': async (s) => {
    const f = scanLive(catalogOf(s));
    return { flagged: atLeast(f, 'MEDIUM'), flaggedHigh: atLeast(f, 'HIGH'), detail: f.map(x => `${x.severity}:${x.id}`).join(',') };
  },
};

const cisco = path.join(here, '.venv-cisco/bin/mcp-scanner');
if (only.has('cisco') && fs.existsSync(cisco)) {
  scanners['cisco mcp-scanner 4.8.7 (yara)'] = async (s) => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-cisco-'));
    try {
      const w = (n, v) => { const p = path.join(tmp, n); fs.writeFileSync(p, JSON.stringify(v)); return p; };
      const a = ['--analyzers', 'yara', '--raw', 'static', '--tools', w('tools.json', { tools: s.tools || [] })];
      if (s.prompts?.length) a.push('--prompts', w('prompts.json', { prompts: s.prompts }));
      if (s.resources?.length) a.push('--resources', w('resources.json', { resources: s.resources }));
      const { stdout } = await run(cisco, a, { maxBuffer: 64 * 1024 * 1024, timeout: 120000, env: { PATH: process.env.PATH, HOME: process.env.HOME } });
      const out = JSON.parse(stdout.slice(stdout.indexOf('[')));
      const bad = out.filter(r => r.is_safe === false);
      return { flagged: bad.length > 0, detail: bad.map(r => `${r.item_type}:${r.tool_name || r.prompt_name || r.resource_name}:${(r.findings?.yara_analyzer?.threat_names || []).join('+')}`).join(',') };
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  };
}

const snyk = path.join(here, '.venv-snyk/bin/snyk-agent-scan');
const snykSkipped = !(only.has('snyk') && fs.existsSync(snyk) && process.env.SNYK_TOKEN);
if (!snykSkipped) {
  scanners['snyk agent-scan 0.6.11'] = async (s) => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-snyk-'));
    try {
      const cfg = path.join(tmp, 'mcp.json');
      fs.writeFileSync(cfg, JSON.stringify({ mcpServers: { [s.id]: { command: process.execPath, args: [path.join(here, 'replay-server.mjs'), s.file] } } }));
      const { stdout } = await run(snyk, ['scan', '--json', '--no-skills', '--dangerously-run-mcp-servers', cfg], { maxBuffer: 64 * 1024 * 1024, timeout: 180000 });
      const out = JSON.parse(stdout);
      const issues = JSON.stringify(out).match(/"code":\s*"([EW]\d+)"/g) || [];
      return { flagged: issues.length > 0, detail: [...new Set(issues)].join(',') };
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  };
}

async function pool(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: n }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k]); } }));
  return out;
}

const results = {};
for (const [name, fn] of Object.entries(scanners)) {
  const parallel = name.startsWith('mcp-scan') ? 1 : jobs;
  const rows = await pool(samples, parallel, async (s) => {
    try { return { id: s.id, label: s.label, category: s.category || 'benign', ...(await fn(s)) }; }
    catch (e) { return { id: s.id, label: s.label, category: s.category || 'benign', error: String(e.message || e).slice(0, 200) }; }
  });
  results[name] = rows;
  process.stderr.write(`${name}: ${rows.length} samples${rows.some(r => r.error) ? `, ${rows.filter(r => r.error).length} errors` : ''}\n`);
}

const pct = (n, d) => d === 0 ? 'n/a' : `${(100 * n / d).toFixed(1)}%`;
function score(rows, key = 'flagged') {
  const ok = rows.filter(r => !r.error);
  const tp = ok.filter(r => r.label === 'poisoned' && r[key]).length;
  const fn = ok.filter(r => r.label === 'poisoned' && !r[key]).length;
  const fp = ok.filter(r => r.label === 'benign' && r[key]).length;
  const tn = ok.filter(r => r.label === 'benign' && !r[key]).length;
  const p = tp + fp === 0 ? NaN : tp / (tp + fp), r = tp + fn === 0 ? NaN : tp / (tp + fn);
  return { tp, fp, fn, tn, precision: p, recall: r, f1: p + r === 0 || Number.isNaN(p + r) ? NaN : 2 * p * r / (p + r), errors: rows.length - ok.length };
}

const table = {};
for (const [name, rows] of Object.entries(results)) table[name] = score(rows);
const poisoned = samples.filter(s => s.label === 'poisoned'), benign = samples.filter(s => s.label === 'benign');
const categories = [...new Set(poisoned.map(s => s.category))].sort();

// Rug-pull detection: of the samples that carry a "before" catalog, how many
// does the snapshot diff report as changed.
const pulls = poisoned.filter(s => s.before);
const pullHits = pulls.filter(s => diffSnapshots(s.id, snapshotOf(catalogOf(s.before)), snapshotOf(catalogOf(s))).some(f => f.id === 'tool-definition-changed' || f.id === 'tool-added')).length;

const md = [];
md.push(`Corpus: ${poisoned.length} poisoned (published proofs of concept), ${benign.length} benign (real npm servers). Generated ${new Date().toISOString().slice(0, 10)}.`, '');
md.push('| Scanner | Precision | Recall | F1 | TP | FP | FN | TN |', '|---|---|---|---|---|---|---|---|');
for (const [name, s] of Object.entries(table)) md.push(`| ${name} | ${pct(s.tp, s.tp + s.fp)} | ${pct(s.tp, s.tp + s.fn)} | ${Number.isNaN(s.f1) ? 'n/a' : s.f1.toFixed(2)} | ${s.tp} | ${s.fp} | ${s.fn} | ${s.tn} |`);
if (snykSkipped) md.push('| snyk agent-scan 0.6.11 | not run | not run | | | | | |');
md.push('', 'Recall by category:', '', `| Category | n | ${Object.keys(table).join(' | ')} |`, `|---|---|${Object.keys(table).map(() => '---').join('|')}|`);
for (const c of categories) {
  const n = poisoned.filter(s => s.category === c).length;
  md.push(`| ${c} | ${n} | ${Object.keys(table).map(name => { const rows = results[name].filter(r => r.category === c && !r.error); return pct(rows.filter(r => r.flagged).length, rows.length); }).join(' | ')} |`);
}
md.push('', `Rug pulls (changed definition after approval): snapshot diff reported ${pullHits} of ${pulls.length}.`);
const fps = {};
for (const [name, rows] of Object.entries(results)) fps[name] = rows.filter(r => r.label === 'benign' && r.flagged).map(r => `${r.id} (${r.detail})`);
fs.mkdirSync(path.join(here, 'results'), { recursive: true });
fs.writeFileSync(path.join(here, 'results/latest.json'), JSON.stringify({ date: new Date().toISOString(), corpus: { poisoned: poisoned.length, benign: benign.length }, table, categories, rugPulls: { total: pulls.length, detected: pullHits }, falsePositives: fps, snykRun: !snykSkipped, rows: results }, null, 2) + '\n');
fs.writeFileSync(path.join(here, 'results/latest.md'), md.join('\n') + '\n');
console.log(md.join('\n'));
for (const [name, list] of Object.entries(fps)) if (list.length) console.log(`\nFalse positives, ${name}:\n  ${list.join('\n  ')}`);
