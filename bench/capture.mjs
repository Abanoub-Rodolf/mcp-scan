// Records what a real published MCP server serves at tools/list (+ prompts,
// resources) into bench/corpus/benign/<name>.json. Run by hand when growing
// the corpus; the benchmark itself never starts a server.
//   node bench/capture.mjs <id> <npm-package@version> [extra args...]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { introspect } from '../dist/lib.js';

const [id, pkg, ...extra] = process.argv.slice(2);
if (!id || !pkg || !/^[a-z0-9-]+$/.test(id) || pkg.startsWith('-')) { console.error('usage: capture.mjs <id: [a-z0-9-]+> <pkg@version> [args...]  (runs third-party code via npx)'); process.exit(2); }
const out = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'corpus/benign', `${id}.json`);
const server = { name: id, toolName: 'bench', configPath: 'bench', command: 'npx', args: ['-y', pkg, ...extra] };
const c = await introspect(server, { timeoutMs: 180000 });
fs.writeFileSync(out, JSON.stringify({
  id, label: 'benign', source: `npm:${pkg}`, capturedAt: new Date().toISOString().slice(0, 10),
  serverInfo: c.serverInfo, instructions: c.instructions, tools: c.tools, prompts: c.prompts, resources: c.resources,
}, null, 2) + '\n');
console.log(`${id}: ${c.tools.length} tools, ${c.prompts.length} prompts, ${c.resources.length} resources`);
