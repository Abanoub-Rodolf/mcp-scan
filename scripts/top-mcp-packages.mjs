#!/usr/bin/env node
// Builds the ecosystem-scan target list: the top npm MCP server packages by
// weekly downloads, plus PyPI packages named mcp-server-* for coverage
// tracking. Registry lookups only, no code execution.

import { mkdir, readFile, writeFile } from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const OUT_DIR = path.resolve('out/ecosystem');
const NPM_TARGET_COUNT = 150;
const NPM_SEARCH_QUERIES = ['mcp-server', 'modelcontextprotocol', 'scope:modelcontextprotocol'];

// Named vendor packages that the npm search-term pass above misses (wrong
// naming convention, low download count vs the 150-package cutoff, or just
// not surfaced by npm's ranking for these query terms). Added explicitly so
// the campaign's priority vendors (Vercel, Cloudflare first) are always
// scanned instead of depending on search luck. Verified to exist on the
// npm registry 2026-09-06; 'github-mcp-server' is intentionally included
// even though it is NOT GitHub's official package - see bounty-map.json.
const NAMED_TARGETS = [
  '@vercel/mcp-adapter',
  '@cloudflare/mcp-server-cloudflare',
  'mcp-server-cloudflare',
  'workers-mcp',
  '@neondatabase/mcp-server-neon',
  '@supabase/mcp-server-supabase',
  '@stripe/mcp',
  '@notionhq/notion-mcp-server',
  '@azure/mcp',
  '@azure-devops/mcp',
  '@sentry/mcp-server',
  'github-mcp-server',
];
const NPM_DOWNLOADS_CHUNK = 100;
const PYPI_PREFIX = 'mcp-server-';
const PYPI_TARGET_COUNT = 50;
const BOUNTY_MAP_PATH = path.resolve('scripts/bounty-map.json');

// Ranks each target by whether its vendor pays for reports, so the campaign
// can triage the highest-value packages first instead of scanning blind.
// Rules are a flat list, first substring match wins; see scripts/bounty-map.json.
async function loadBountyMap() {
  const raw = JSON.parse(await readFile(BOUNTY_MAP_PATH, 'utf8'));
  return { rules: raw.rules ?? [], fallback: raw.default };
}

function bountyFor({ rules, fallback }, name) {
  const lower = name.toLowerCase();
  const rule = rules.find((r) => lower.includes(r.match.toLowerCase()));
  const { match: _match, ...rest } = rule ?? fallback;
  return rest;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchJson(url, timeoutMs = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) return null;
    return await res.json();
  } catch (_err) {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function searchNpmPackages() {
  const names = new Set();
  for (const query of NPM_SEARCH_QUERIES) {
    const url = `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(query)}&size=250`;
    const data = await fetchJson(url);
    for (const obj of data?.objects ?? []) {
      const name = obj?.package?.name;
      if (name) names.add(name);
    }
    await sleep(200);
  }
  return [...names];
}

// npm's bulk downloads endpoint 400s the whole batch if one name in it is
// unpublished. Fall back to per-package lookups for that chunk so one bad
// name doesn't zero out the rest.
async function downloadsForChunk(chunk) {
  const bulk = await fetchJson(`https://api.npmjs.org/downloads/point/last-week/${chunk.join(',')}`);
  if (bulk) {
    return chunk.map((name) => [name, bulk[name]?.downloads ?? null]);
  }
  const results = [];
  for (const name of chunk) {
    const point = await fetchJson(`https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(name)}`);
    results.push([name, point?.downloads ?? null]);
    await sleep(150);
  }
  return results;
}

// Named priority-vendor targets must not fall out of the scan just because
// npm's downloads endpoint has nothing for them this run (new package, API
// hiccup, or a name pattern the bulk endpoint mishandles) - withDownloads'
// `downloads !== null` filter was silently dropping them (run2 campaign,
// 2026-09-05: 6 of 12 named targets never made it into targets.json). A
// named target only ends up excluded when it doesn't exist on the registry
// at all, and that gets recorded with a reason instead of vanishing.
export async function resolveNamedTargets(names) {
  const results = [];
  for (const name of names) {
    const point = await fetchJson(`https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(name)}`);
    if (point && typeof point.downloads === 'number') {
      results.push({ name, weeklyDownloads: point.downloads });
      await sleep(150);
      continue;
    }
    // No download figure - confirm the package actually exists before
    // scanning it with an unknown download count, or recording a real skip.
    const meta = await fetchJson(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
    if (meta) {
      results.push({ name, weeklyDownloads: null });
    } else {
      results.push({ name, weeklyDownloads: null, skipped: 'package not found on npm registry' });
    }
    await sleep(150);
  }
  return results;
}

async function withDownloads(names) {
  const ranked = [];
  for (let i = 0; i < names.length; i += NPM_DOWNLOADS_CHUNK) {
    const chunk = names.slice(i, i + NPM_DOWNLOADS_CHUNK);
    ranked.push(...await downloadsForChunk(chunk));
    await sleep(200);
  }
  return ranked
    .filter(([, downloads]) => downloads !== null)
    .sort((a, b) => b[1] - a[1])
    .map(([name, downloads]) => ({ name, weeklyDownloads: downloads }));
}

// PyPI has no search JSON API; the simple index (PEP 503) is the documented
// machine-readable listing of every project name, so we grep it for the
// mcp-server- prefix instead of scraping the HTML search page.
async function findPypiCandidates() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  let text;
  try {
    const res = await fetch('https://pypi.org/simple/', { signal: controller.signal });
    if (!res.ok) return [];
    text = await res.text();
  } catch (_err) {
    return [];
  } finally {
    clearTimeout(timer);
  }

  const names = [];
  const re = /<a[^>]*>([^<]+)<\/a>/g;
  let match;
  while ((match = re.exec(text))) {
    const name = match[1].trim();
    if (name.toLowerCase().startsWith(PYPI_PREFIX)) names.push(name);
  }
  return names;
}

async function fetchPypiMetadata(names) {
  const packages = [];
  for (const name of names.slice(0, PYPI_TARGET_COUNT)) {
    const data = await fetchJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
    if (data?.info) {
      packages.push({
        name,
        version: data.info.version ?? null,
        license: data.info.license || null,
        summary: data.info.summary || null,
      });
    }
    await sleep(150);
  }
  return packages;
}

async function main() {
  await mkdir(OUT_DIR, { recursive: true });

  const bountyMap = await loadBountyMap();

  const npmNames = await searchNpmPackages();
  const npmRanked = await withDownloads(npmNames);
  const topRanked = npmRanked.slice(0, NPM_TARGET_COUNT);

  // Named targets ride along outside the download-count cutoff so a
  // priority vendor package with modest download counts (or a name the
  // search terms don't match) still gets scanned every run.
  const alreadyRanked = new Set(topRanked.map((pkg) => pkg.name));
  const missingNamed = NAMED_TARGETS.filter((name) => !alreadyRanked.has(name));
  const namedResolved = missingNamed.length > 0 ? await resolveNamedTargets(missingNamed) : [];
  const namedRanked = namedResolved.filter((pkg) => !pkg.skipped);
  const namedSkipped = namedResolved.filter((pkg) => pkg.skipped);

  const npm = [...topRanked, ...namedRanked]
    .map((pkg) => ({ ...pkg, bounty: bountyFor(bountyMap, pkg.name) }));

  const pypiCandidates = await findPypiCandidates();
  const pypi = (await fetchPypiMetadata(pypiCandidates))
    .map((pkg) => ({ ...pkg, bounty: bountyFor(bountyMap, pkg.name) }));

  const targets = {
    generatedAt: new Date().toISOString(),
    npm,
    pypi,
    // Named priority-vendor targets that still didn't make it in even after
    // bypassing the download-count filter, with why - see resolveNamedTargets.
    skippedNamedTargets: namedSkipped.map(({ name, skipped }) => ({ name, reason: skipped })),
  };

  const outPath = path.join(OUT_DIR, 'targets.json');
  await writeFile(outPath, JSON.stringify(targets, null, 2));
  console.log(`wrote ${npm.length} npm + ${pypi.length} pypi targets to ${outPath}`);
  if (namedSkipped.length > 0) {
    console.log(`${namedSkipped.length} named target(s) skipped: ${namedSkipped.map((p) => `${p.name} (${p.skipped})`).join(', ')}`);
  }
}

// Plain-path comparison instead of a raw `file://${argv[1]}` string match -
// the string form breaks on spaces/unicode in the path (needs URL-encoding)
// and on a relative argv[1] (invoked as `node scripts/foo.mjs` rather than
// an absolute path), both of which make isMain false when this *is* the
// entrypoint and main() silently never runs.
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) main();
