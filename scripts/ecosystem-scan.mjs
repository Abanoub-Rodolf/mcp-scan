#!/usr/bin/env node
// Runs mcp-scan's own supply-chain/package checks against a list of package
// names instead of locally detected tool configs. Registry lookups only
// (npm, OSV.dev, GitHub API) - never installs or executes package code.

import { mkdir, readFile, writeFile } from 'fs/promises';
import path from 'path';
import {
  scanRegistry,
  scanTyposquat,
  scanPackageDeep,
  scanSupplyChain,
  scanLicense,
} from '../dist/lib.js';
import { deepScanPackage } from './source-scan.mjs';
import { writeFindingsRanked } from './findings-ranked.mjs';

const OUT_DIR = path.resolve('out/ecosystem');
const TARGETS_PATH = path.join(OUT_DIR, 'targets.json');
const CONCURRENCY = 5;
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function safeName(pkg) {
  return pkg.replace(/[^a-zA-Z0-9.-]/g, '_');
}

async function runPool(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  async function runNext() {
    const i = next++;
    if (i >= items.length) return;
    results[i] = await worker(items[i]);
    await runNext();
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, runNext));
  return results;
}

// The per-package/version registry document, distinct from the package-wide
// doc scanSupplyChain/scanPackageDeep already fetch: this is the only place
// dist.tarball and the resolved `dependencies` map for that exact version
// live, which the source/dependency deep scan needs.
async function fetchVersionManifest(name, version) {
  if (!version) return null;
  try {
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}/${encodeURIComponent(version)}`);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function toResolvedServer(pkg) {
  return {
    name: pkg,
    toolName: 'ecosystem-scan',
    configPath: 'ecosystem-scan',
    command: 'npx',
    args: [pkg],
  };
}

// Tags each finding with the scanner that produced it - findings-ranked.md
// needs this and a couple of finding ids (unicode-injection, tool-name-shadow)
// are shared between scanners, so it can't be reconstructed from id alone.
function tag(scanner, findings) {
  return findings.map((f) => ({ ...f, scanner }));
}

async function scanNpmPackage({ name, weeklyDownloads, bounty }) {
  const server = toResolvedServer(name);
  const findings = [];
  const supplyChain = await scanSupplyChain(server, false);
  findings.push(...tag('supply-chain-scanner', supplyChain.findings));
  findings.push(...tag('registry-scanner', await scanRegistry(server, false)));
  findings.push(...tag('typosquat-scanner', scanTyposquat(server)));
  findings.push(...tag('package-scanner', await scanPackageDeep(server, false)));
  findings.push(...tag('license-scanner', scanLicense(supplyChain.metadata)));

  const manifest = await fetchVersionManifest(name, supplyChain.metadata?.version);
  const deep = await deepScanPackage(name, manifest);
  findings.push(...deep.findings);

  return {
    package: name,
    ecosystem: 'npm',
    weeklyDownloads,
    bounty: bounty ?? null,
    trustScore: supplyChain.trustScore,
    metadata: supplyChain.metadata ?? null,
    findings,
    sourceScan: deep.summary,
    scannedAt: new Date().toISOString(),
  };
}

// The scanners resolve packages by shelling out to npx/npm, so PyPI names
// have no reused check to run. Recorded for coverage tracking, not scanned.
function unsupportedPypiPackage(pkg) {
  return {
    package: pkg.name,
    ecosystem: 'pypi',
    weeklyDownloads: null,
    bounty: pkg.bounty ?? null,
    trustScore: null,
    metadata: { version: pkg.version, license: pkg.license },
    findings: [],
    unsupported: true,
    reason: 'mcp-scan has no PyPI supply-chain path; npm/npx-only scanners cannot resolve this package',
    scannedAt: new Date().toISOString(),
  };
}

function severityCounts(findings) {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity]++;
  }
  return counts;
}

function topFinding(findings) {
  for (const severity of SEVERITIES) {
    const hit = findings.find((f) => f.severity === severity);
    if (hit) return `${hit.id}: ${hit.description}`.slice(0, 140);
  }
  return 'none';
}

function csvField(value) {
  const str = String(value);
  return /[",\n]/.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
}

async function main() {
  await mkdir(OUT_DIR, { recursive: true });
  const targets = JSON.parse(await readFile(TARGETS_PATH, 'utf8'));

  const npmResults = await runPool(targets.npm ?? [], CONCURRENCY, scanNpmPackage);
  const pypiResults = (targets.pypi ?? []).map(unsupportedPypiPackage);
  const results = [...npmResults, ...pypiResults];

  for (const result of results) {
    const file = path.join(OUT_DIR, `${safeName(result.package)}.json`);
    await writeFile(file, JSON.stringify(result, null, 2));
  }

  const rows = ['package,weekly_downloads,bounty,vendor,critical,high,medium,low,info,top_finding'];
  for (const result of results) {
    const counts = severityCounts(result.findings);
    rows.push([
      csvField(result.package),
      result.weeklyDownloads ?? 'n/a',
      csvField(result.bounty?.bounty ?? 'unmapped'),
      csvField(result.bounty?.vendor ?? ''),
      counts.CRITICAL,
      counts.HIGH,
      counts.MEDIUM,
      counts.LOW,
      counts.INFO,
      csvField(result.unsupported ? 'not supported: no PyPI path in mcp-scan scanners' : topFinding(result.findings)),
    ].join(','));
  }
  await writeFile(path.join(OUT_DIR, 'summary.csv'), rows.join('\n') + '\n');

  const rankedFindings = await writeFindingsRanked(results, OUT_DIR);

  const totals = severityCounts(npmResults.flatMap((r) => r.findings));
  console.log(`scanned ${npmResults.length} npm + ${pypiResults.length} pypi packages`);
  console.log('severity totals (npm only):');
  console.table(totals);
  console.log(`${rankedFindings.length} finding(s) at HIGH/CRITICAL - see out/ecosystem/findings-ranked.md`);
  console.log('wrote out/ecosystem/summary.csv');
}

main();
