// Precision/recall benchmark: mcp-scan (static config scanners, --live) against
// Cisco mcp-scanner (YARA) and Snyk agent-scan, on a labeled corpus of real
// published poisoned servers and real benign servers.
//   node bench/run.mjs [--only ours,cisco,snyk] [--jobs 4]
// Needs `npm run build` first. Competitors need `bench/setup.sh`. Snyk needs
// SNYK_TOKEN; without it Snyk is reported as "not run", never as a score.
import fs from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { scanLive, scanToolPoisoning, scanPromptInjection, snapshotOf, diffSnapshots } from '../dist/lib.js';

const run = promisify(execFile);
// Nothing a child process echoes may carry the Snyk token or the home directory into results/.
const redact = (t) => [process.env.SNYK_TOKEN, os.homedir()].filter(Boolean).reduce((x, v) => x.split(v).join('***'), t);
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
  // Snyk's free tier stops at a daily cap. Verdicts that came back clean are kept, keyed by the sample's
  // content hash, so a run cut short by the cap can be finished the next day instead of restarted.
  const cacheFile = path.join(here, 'results/snyk-cache.json');
  let cache = {};
  try { cache = JSON.parse(fs.readFileSync(cacheFile, 'utf8')); } catch (_e) { /* first run */ }
  // The key covers everything the verdict depends on: the sample, the replay server, Snyk's version and the score threshold.
  const sampleKey = (s) => crypto.createHash('sha256').update(fs.readFileSync(s.file)).update(fs.readFileSync(path.join(here, 'replay-server.mjs'))).update('snyk-agent-scan 0.6.11 score>=300').digest('hex').slice(0, 16);
  scanners['snyk agent-scan 0.6.11'] = async (s) => {
    const hit = cache[s.id];
    if (hit && hit.key === sampleKey(s)) return { flagged: hit.flagged, detail: hit.detail };
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-snyk-'));
    try {
      const cfg = path.join(tmp, 'mcp.json');
      fs.writeFileSync(cfg, JSON.stringify({ mcpServers: { [s.id]: { command: process.execPath, args: [path.join(here, 'replay-server.mjs'), s.file] } } }));
      // A minimal env: the token is the one secret this process holds, and a failing child can echo its environment.
      const { stdout } = await run(snyk, ['scan', '--json', '--no-skills', '--dangerously-run-mcp-servers', cfg], { maxBuffer: 64 * 1024 * 1024, timeout: 180000, env: { PATH: process.env.PATH, HOME: process.env.HOME, SNYK_TOKEN: process.env.SNYK_TOKEN } });
      const out = JSON.parse(stdout);
      const risks = (out.scan_path_responses || []).flatMap(r => r.server_risks || []);
      const pathErr = (out.scan_path_responses || []).find(r => r.error);
      if (pathErr) throw new Error(`snyk scan failed: ${String(pathErr.error.message || '').slice(0, 100)}`);
      if (risks.length === 0) throw new Error('snyk returned no server_risks (the replay server may not have started)');
      const err = risks.find(r => r.error);
      if (err) throw new Error(`snyk reported an error: ${JSON.stringify(err.error).slice(0, 120)}`);
      // 0.6.11 reports risk scores, not issue codes. prompt_injection_tool_desc is the poisoning verdict;
      // private_data, untrusted_content and destructive_capabilities describe what a tool can do, so they are not counted.
      // Scores up to 299 are the lowest band in its own printer, so a flag needs 300 or more.
      const hits = risks.map(r => r.risk_indexes?.prompt_injection_tool_desc).filter(x => x && x.score >= 300);
      const verdict = { flagged: hits.length > 0, detail: hits.map(h => `prompt_injection_tool_desc:${h.score}`).join(',') };
      cache[s.id] = { key: sampleKey(s), ...verdict };
      fs.writeFileSync(cacheFile, JSON.stringify(cache, null, 1) + '\n');
      return verdict;
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
    try { return { id: s.id, label: s.label, set: s.set, category: s.category || 'benign', ...(await fn(s)) }; }
    catch (e) { return { id: s.id, label: s.label, category: s.category || 'benign', error: redact(String(e.message || e)).slice(0, 200) }; }
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
for (const [name, s] of Object.entries(table)) if (s.errors) md.push(`WARNING: ${name} errored on ${s.errors} samples; they are left out of its numbers.`, '');
md.push('| Scanner | Precision | Recall | F1 | TP | FP | FN | TN |', '|---|---|---|---|---|---|---|---|');
for (const [name, s] of Object.entries(table)) if (s.errors) md.push(`| ${name} | incomplete: ${s.errors} of ${results[name].length} samples errored, so no score is given | | | | | | |`); else md.push(`| ${name} | ${pct(s.tp, s.tp + s.fp)} | ${pct(s.tp, s.tp + s.fn)} | ${Number.isNaN(s.f1) ? 'n/a' : s.f1.toFixed(2)} | ${s.tp} | ${s.fp} | ${s.fn} | ${s.tn} |`);
if (snykSkipped) md.push('| snyk agent-scan 0.6.11 | not run | not run | | | | | |');
md.push('', 'Recall by category:', '', `| Category | n | ${Object.keys(table).join(' | ')} |`, `|---|---|${Object.keys(table).map(() => '---').join('|')}|`);
for (const c of categories) {
  const n = poisoned.filter(s => s.category === c).length;
  md.push(`| ${c} | ${n} | ${Object.keys(table).map(name => { const rows = results[name].filter(r => r.category === c && !r.error); return pct(rows.filter(r => r.flagged).length, rows.length); }).join(' | ')} |`);
}
const hold = (results['mcp-scan --live'] || []).filter(r => r.set === 'holdout' && !r.error);
if (hold.length) md.push('', `Holdout benign servers (recorded after the rules were written): ${hold.length}; mcp-scan --live flagged ${hold.filter(r => r.flagged).length}.`);
md.push('', `Rug pulls (changed definition after approval): snapshot diff reported ${pullHits} of ${pulls.length} (no benign control, so this shows the diff works, not its false-positive rate).`);
const fps = {};
for (const [name, rows] of Object.entries(results)) fps[name] = rows.filter(r => r.label === 'benign' && r.flagged).map(r => `${r.id} (${r.detail})`);
fs.mkdirSync(path.join(here, 'results'), { recursive: true });
// A partial run (--only, or a competitor not installed) must not replace the full committed results.
const complete = !snykSkipped && Object.keys(scanners).length === 4 && Object.values(table).every(t => !t.errors);
const outName = complete ? 'latest' : 'latest.partial';
fs.writeFileSync(path.join(here, `results/${outName}.json`), JSON.stringify({ date: new Date().toISOString(), corpus: { poisoned: poisoned.length, benign: benign.length }, table, categories, rugPulls: { total: pulls.length, detected: pullHits }, falsePositives: fps, snykRun: !snykSkipped, rows: results }, null, 2) + '\n');
fs.writeFileSync(path.join(here, `results/${outName}.md`), md.join('\n') + '\n');
console.log(md.join('\n'));
for (const [name, list] of Object.entries(fps)) if (list.length) console.log(`\nFalse positives, ${name}:\n  ${list.join('\n  ')}`);
