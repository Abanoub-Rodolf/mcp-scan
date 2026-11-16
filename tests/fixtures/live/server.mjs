// Dependency-free MCP stdio server for --live tests. Tools come from the JSON
// file in FIXTURE_TOOLS_FILE, read at start, so a test can change them between
// scans. FIXTURE_BEHAVIOR: hang | crash | chatty | flood | pages | pidfile:<path>
import fs from 'node:fs';
import readline from 'node:readline';

const file = process.env.FIXTURE_TOOLS_FILE;
const cfg = file ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
const behavior = process.env.FIXTURE_BEHAVIOR || '';
const send = (m) => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', ...m }) + '\n');

if (behavior.startsWith('pidfile:')) fs.writeFileSync(behavior.slice(8), String(process.pid));
if (behavior === 'crash') { process.stderr.write('boom: missing API_KEY\n'); process.exit(3); }
if (behavior === 'chatty') process.stdout.write('starting server v1...\nnot json at all\n');

const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (line) => {
  let msg; try { msg = JSON.parse(line); } catch { return; }
  if (behavior === 'hang') return;
  if (msg.method === 'initialize') {
    send({ id: msg.id, result: {
      protocolVersion: '2025-06-18',
      capabilities: { tools: {}, ...(cfg.prompts ? { prompts: {} } : {}), ...(cfg.resources ? { resources: {} } : {}) },
      serverInfo: { name: 'fixture', version: '1.0.0' },
      ...(cfg.instructions ? { instructions: cfg.instructions } : {}),
    } });
    // a server may ask the client for something; the scanner must refuse
    send({ id: 'srv-1', method: 'sampling/createMessage', params: {} });
  } else if (msg.method === 'tools/list') {
    if (behavior === 'flood') { process.stdout.write('x'.repeat(5 * 1024 * 1024) + '\n'); return; }
    if (behavior === 'pages') {
      const n = Number(msg.params?.cursor || 0);
      send({ id: msg.id, result: { tools: [{ name: `t${n}`, description: 'page tool' }], nextCursor: String(n + 1) } });
      return;
    }
    send({ id: msg.id, result: { tools: cfg.tools || [] } });
  } else if (msg.method === 'prompts/list') send({ id: msg.id, result: { prompts: cfg.prompts || [] } });
  else if (msg.method === 'resources/list') send({ id: msg.id, result: { resources: cfg.resources || [] } });
  else if (msg.id !== undefined && msg.method) send({ id: msg.id, error: { code: -32601, message: 'method not found' } });
});
