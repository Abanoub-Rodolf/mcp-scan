// Serves a corpus sample over MCP stdio so scanners that only accept a running
// server (Snyk agent-scan, Cisco `config`) can be pointed at a recorded catalog.
//   node bench/replay-server.mjs <sample.json>
import fs from 'node:fs';
import readline from 'node:readline';

const s = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const send = (m) => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', ...m }) + '\n');
const caps = { tools: {}, ...(s.prompts?.length ? { prompts: {} } : {}), ...(s.resources?.length ? { resources: {} } : {}) };
readline.createInterface({ input: process.stdin }).on('line', (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === 'initialize') send({ id: m.id, result: { protocolVersion: '2025-06-18', capabilities: caps, serverInfo: { name: s.id, version: '1.0.0' }, ...(s.instructions ? { instructions: s.instructions } : {}) } });
  else if (m.method === 'tools/list') send({ id: m.id, result: { tools: s.tools || [] } });
  else if (m.method === 'prompts/list') send({ id: m.id, result: { prompts: s.prompts || [] } });
  else if (m.method === 'resources/list') send({ id: m.id, result: { resources: s.resources || [] } });
  else if (m.id !== undefined && m.method) send({ id: m.id, error: { code: -32601, message: 'method not found' } });
});
