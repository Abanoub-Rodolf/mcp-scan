import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// `npm audit --audit-level=high` cannot be used as-is: braces has a high
// advisory with no published fix, so it would fail every run. This gate
// fails on any high or critical runtime advisory unless it is listed in
// scripts/audit-accepted.json, and an accepted entry stops counting once
// its reviewBy date passes, so an acceptance cannot go stale quietly.
const BLOCKING = new Set(['high', 'critical']);

export function evaluate(audit, accepted, now = new Date()) {
  const advisories = new Map();
  for (const vuln of Object.values(audit.vulnerabilities ?? {})) {
    for (const via of vuln.via ?? []) {
      // String entries only point at another package in the chain.
      if (typeof via !== 'object' || !BLOCKING.has(via.severity)) continue;
      const id = via.url?.split('/').pop() ?? String(via.source);
      advisories.set(id, { id, package: via.name, severity: via.severity, title: via.title });
    }
  }
  const failures = [];
  for (const adv of advisories.values()) {
    const ok = accepted.find((a) => a.id === adv.id);
    if (!ok) failures.push({ ...adv, why: 'not accepted' });
    else if (new Date(ok.reviewBy) < now) failures.push({ ...adv, why: `acceptance expired ${ok.reviewBy} (owner ${ok.owner})` });
  }
  return failures;
}

function main() {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  const accepted = JSON.parse(readFileSync(path.join(dir, 'audit-accepted.json'), 'utf8'));
  const run = spawnSync('npm', ['audit', '--omit=dev', '--json'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  let audit;
  try {
    audit = JSON.parse(run.stdout);
  } catch {
    console.error('audit-gate: could not parse npm audit output', run.stderr);
    process.exit(2);
  }
  if (audit.error) {
    console.error('audit-gate: npm audit failed:', audit.error.summary ?? audit.error);
    process.exit(2);
  }
  const failures = evaluate(audit, accepted);
  for (const f of failures) console.error(`${f.severity} ${f.package} ${f.id}: ${f.title} (${f.why})`);
  if (failures.length) process.exit(1);
  console.log('audit-gate: no unaccepted high or critical runtime advisories');
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) main();
