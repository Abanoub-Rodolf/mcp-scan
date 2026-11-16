import { spawn, ChildProcess } from 'child_process';
import { StringDecoder } from 'string_decoder';
import { ResolvedServer } from '../types/config.js';
import { clean, oneLine } from '../scanners/live-scanner.js';

// Minimal MCP client for `scan --live`: connect, list what the server puts in
// front of the model, disconnect. No SDK dependency on purpose; the server
// under test is untrusted, so every read is capped and every wait is bounded.

export const PROTOCOL_VERSION = '2025-06-18';

export interface LiveCatalog {
  protocolVersion?: string;
  serverInfo?: { name?: string; version?: string };
  instructions?: string;
  tools: Record<string, unknown>[];
  prompts: Record<string, unknown>[];
  resources: Record<string, unknown>[];
  resourceTemplates: Record<string, unknown>[];
  // Set when a list hit MAX_ITEMS or MAX_PAGES: what was kept is still scanned.
  truncated?: boolean;
}

export interface IntrospectOptions {
  timeoutMs?: number;
  // Skip servers reached over the network (url-based) entirely.
  noNetwork?: boolean;
}

export class IntrospectError extends Error {
  constructor(message: string) {
    // Messages can carry server-controlled text (JSON-RPC errors, stderr): one clean line.
    super(oneLine(message));
    this.name = 'IntrospectError';
  }
}

const MAX_LINE = 4 * 1024 * 1024;
const MAX_TOTAL = 32 * 1024 * 1024;
const MAX_PAGES = 50;
const MAX_ITEMS = 2000;

// What the server process inherits from us. A config's own env is added on
// top. The rest of the scanning user's environment (tokens, cloud creds) is
// withheld: --live may be the first time this command ever runs.
const PASSTHROUGH_ENV = [
  'PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'LANG', 'LC_ALL', 'TERM', 'TMPDIR', 'TEMP', 'TMP',
  'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'SystemRoot', 'SYSTEMROOT', 'ComSpec', 'PATHEXT', 'HOMEDRIVE', 'HOMEPATH',
  'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'NVM_DIR', 'NODE_EXTRA_CA_CERTS',
  // npx/uvx must still reach their registry from behind a proxy or private CA.
  'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy',
  'SSL_CERT_FILE', 'SSL_CERT_DIR', 'npm_config_cache', 'npm_config_registry', 'npm_config_proxy', 'npm_config_https_proxy',
];

export function liveEnv(server: Pick<ResolvedServer, 'env'>, from: NodeJS.ProcessEnv = process.env): Record<string, string> {
  const env: Record<string, string> = {};
  for (const k of PASSTHROUGH_ENV) if (from[k] !== undefined) env[k] = from[k] as string;
  return { ...env, ...(server.env ?? {}) };
}

type Rpc = (method: string, params?: Record<string, unknown>) => Promise<any>;
type Notify = (method: string, params?: Record<string, unknown>) => Promise<void>;

async function listAll(rpc: Rpc, method: string, key: string, out: { truncated?: boolean }): Promise<Record<string, unknown>[]> {
  const items: Record<string, unknown>[] = [];
  const seen = new Set<string>();
  let cursor: string | undefined;
  for (let page = 0; ; page++) {
    if (page >= MAX_PAGES) { out.truncated = true; break; }
    const res = await rpc(method, cursor ? { cursor } : undefined);
    const list = res?.[key];
    if (!Array.isArray(list)) throw new IntrospectError(`${method} returned no ${key} array`);
    for (const item of list) {
      if (items.length >= MAX_ITEMS) { out.truncated = true; return items; }
      if (item && typeof item === 'object' && !Array.isArray(item)) items.push(item);
    }
    const next = res?.nextCursor;
    // A server that hands back the same cursor would page forever.
    if (typeof next !== 'string' || next === '' || seen.has(next)) break;
    seen.add(next);
    cursor = next;
  }
  return items;
}

async function catalog(rpc: Rpc, notify: Notify): Promise<LiveCatalog> {
  const init = await rpc('initialize', {
    protocolVersion: PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: 'mcp-scan', version: 'live' },
  });
  if (!init || typeof init !== 'object') throw new IntrospectError('initialize returned no result');
  await notify('notifications/initialized');
  const caps = (init.capabilities ?? {}) as Record<string, unknown>;
  const out: LiveCatalog = {
    protocolVersion: typeof init.protocolVersion === 'string' ? init.protocolVersion : undefined,
    serverInfo: init.serverInfo && typeof init.serverInfo === 'object' ? init.serverInfo : undefined,
    instructions: typeof init.instructions === 'string' ? init.instructions : undefined,
    tools: [], prompts: [], resources: [], resourceTemplates: [],
  };
  // Lists are asked for only when advertised: many servers answer an
  // unadvertised method with an error, which is not a finding.
  if (caps.tools) out.tools = await listAll(rpc, 'tools/list', 'tools', out);
  if (caps.prompts) out.prompts = await listAll(rpc, 'prompts/list', 'prompts', out);
  if (caps.resources) {
    out.resources = await listAll(rpc, 'resources/list', 'resources', out);
    try {
      out.resourceTemplates = await listAll(rpc, 'resources/templates/list', 'resourceTemplates', out);
    } catch (_e) { /* optional in the spec */ }
  }
  return out;
}

function withTimeout<T>(p: Promise<T>, ms: number, onTimeout: () => void): Promise<T> {
  let timer: NodeJS.Timeout;
  return Promise.race([
    p,
    new Promise<T>((_, reject) => {
      timer = setTimeout(() => { onTimeout(); reject(new IntrospectError(`no complete answer within ${ms}ms`)); }, ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

// Children still running. An interrupted scan (Ctrl-C, kill) must not leave
// servers behind: they are detached into their own process group, so the
// terminal's signal does not reach them.
const running = new Set<ChildProcess>();
let hooked = false;
function killTree(child: ChildProcess) {
  running.delete(child);
  try {
    // taskkill /T takes the whole tree on Windows, where there are no process groups
    if (process.platform === 'win32' && child.pid) spawn('taskkill', ['/T', '/F', '/PID', String(child.pid)], { stdio: 'ignore', windowsHide: true }).on('error', () => {});
    // detached gave it its own process group: take npx's grandchildren too,
    // even when the direct child has already exited
    if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, 'SIGKILL');
    else if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  } catch (_e) {
    try { child.kill('SIGKILL'); } catch (_e2) { /* already gone */ }
  }
}
function trackChild(child: ChildProcess) {
  running.add(child);
  if (hooked) return;
  hooked = true;
  process.on('exit', () => { for (const c of [...running]) killTree(c); });
  for (const sig of ['SIGINT', 'SIGTERM'] as const) {
    process.once(sig, () => {
      for (const c of [...running]) killTree(c);
      // the listener replaced the default: re-raise so the signal still ends us
      process.kill(process.pid, sig);
    });
  }
}

function introspectStdio(server: ResolvedServer, timeoutMs: number): Promise<LiveCatalog> {
  const args = Array.isArray(server.args) ? server.args.filter((a): a is string => typeof a === 'string') : [];
  const child = spawn(server.command as string, args, {
    env: liveEnv(server),
    stdio: ['pipe', 'pipe', 'pipe'],
    detached: process.platform !== 'win32',
    // npx and friends are .cmd shims on Windows
    shell: process.platform === 'win32',
    windowsHide: true,
  });

  trackChild(child);
  let nextId = 1;
  const pending = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void }>();
  let dead: Error | null = null;
  let stderrTail = '';
  const failAll = (err: Error) => {
    if (!dead) dead = err;
    for (const p of pending.values()) p.reject(dead);
    pending.clear();
  };

  const write = (msg: Record<string, unknown>) => {
    if (dead) throw dead;
    child.stdin!.write(JSON.stringify(msg) + '\n');
  };

  let buffer = '';
  let total = 0;
  const decoder = new StringDecoder('utf8');
  child.stdout!.on('data', (chunk: Buffer) => {
    total += chunk.length;
    if (total > MAX_TOTAL) { failAll(new IntrospectError(`server wrote more than ${MAX_TOTAL} bytes`)); killTree(child); return; }
    buffer += decoder.write(chunk);
    let nl: number;
    while ((nl = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (line.length > MAX_LINE) { failAll(new IntrospectError(`a single message exceeded ${MAX_LINE} bytes`)); killTree(child); return; }
      if (line) onLine(line);
    }
    if (buffer.length > MAX_LINE) { failAll(new IntrospectError(`a single message exceeded ${MAX_LINE} bytes`)); killTree(child); }
  });
  // Kept for the error message only; never forwarded to our stdout.
  child.stderr!.on('data', (c: Buffer) => { stderrTail = (stderrTail + c.toString('utf8')).slice(-400); });
  child.stdin!.on('error', () => {});
  child.on('error', (e) => failAll(new IntrospectError(`could not start '${server.command}': ${e.message}`)));
  child.on('exit', (code, signal) => {
    const tail = clean(stderrTail).trim().split('\n').slice(-2).join(' | ');
    failAll(new IntrospectError(`server exited (${signal ?? `code ${code}`}) before answering${tail ? `: ${tail}` : ''}`));
  });

  function onLine(line: string) {
    let msg: any;
    try { msg = JSON.parse(line); } catch (_e) { return; } // log noise on stdout is common
    if (!msg || typeof msg !== 'object') return;
    if (typeof msg.method === 'string') {
      // Server-to-client requests (sampling, roots, elicitation) are refused:
      // a scan grants the server nothing.
      if (msg.id !== undefined && msg.id !== null) {
        try { write({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'not supported by mcp-scan' } }); } catch (_e) {}
      }
      return;
    }
    const p = typeof msg.id === 'number' ? pending.get(msg.id) : undefined;
    if (!p) return;
    pending.delete(msg.id);
    if (msg.error) p.reject(new IntrospectError(`server error: ${String(msg.error.message ?? JSON.stringify(msg.error)).slice(0, 200)}`));
    else p.resolve(msg.result);
  }

  const rpc: Rpc = (method, params) => new Promise((resolve, reject) => {
    if (dead) return reject(dead);
    const id = nextId++;
    pending.set(id, { resolve, reject });
    try { write({ jsonrpc: '2.0', id, method, ...(params ? { params } : {}) }); } catch (e) { pending.delete(id); reject(e as Error); }
  });
  const notify: Notify = async (method, params) => { write({ jsonrpc: '2.0', method, ...(params ? { params } : {}) }); };

  return withTimeout(catalog(rpc, notify), timeoutMs, () => failAll(new IntrospectError('timed out')))
    .finally(() => {
      try { child.stdin!.end(); } catch (_e) {}
      killTree(child);
      child.stdout!.destroy();
      child.stderr!.destroy();
    });
}

// Streamable HTTP transport: one POST per message, the answer as JSON or as
// an SSE stream carrying it.
function introspectHttp(server: ResolvedServer, timeoutMs: number): Promise<LiveCatalog> {
  const url = server.url as string;
  const controller = new AbortController();
  const headers: Record<string, string> = {};
  const raw = (server as unknown as { headers?: unknown }).headers;
  if (raw && typeof raw === 'object') {
    for (const [k, v] of Object.entries(raw as Record<string, unknown>)) if (typeof v === 'string') headers[k] = v;
  }
  let session: string | undefined;
  let version: string | undefined;
  let nextId = 1;

  const post = async (body: Record<string, unknown>) => {
    const res = await fetch(url, {
      method: 'POST',
      signal: controller.signal,
      redirect: 'error',
      headers: {
        ...headers,
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        ...(session ? { 'mcp-session-id': session } : {}),
        ...(version ? { 'mcp-protocol-version': version } : {}),
      },
      body: JSON.stringify(body),
    });
    const sid = res.headers.get('mcp-session-id');
    if (sid) session = sid;
    return res;
  };

  const readCapped = async (res: Response): Promise<string> => {
    if (!res.body) return '';
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let text = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      text += decoder.decode(value, { stream: true });
      if (text.length > MAX_TOTAL) { await reader.cancel(); throw new IntrospectError(`response exceeded ${MAX_TOTAL} bytes`); }
    }
    return text;
  };

  const rpc: Rpc = async (method, params) => {
    const id = nextId++;
    const res = await post({ jsonrpc: '2.0', id, method, ...(params ? { params } : {}) });
    if (res.status === 401 || res.status === 403) throw new IntrospectError(`HTTP ${res.status}: the server needs credentials this config does not carry`);
    if (!res.ok) throw new IntrospectError(`HTTP ${res.status} for ${method}`);
    const type = res.headers.get('content-type') ?? '';
    const text = await readCapped(res);
    const messages: any[] = [];
    if (type.includes('text/event-stream')) {
      for (const event of text.split(/\r?\n\r?\n/)) {
        const data = event.split(/\r?\n/).filter(l => l.startsWith('data:')).map(l => l.slice(5).trimStart()).join('\n');
        if (!data) continue;
        try { messages.push(JSON.parse(data)); } catch (_e) {}
      }
    } else {
      try {
        const parsed = JSON.parse(text);
        messages.push(...(Array.isArray(parsed) ? parsed : [parsed]));
      } catch (_e) { throw new IntrospectError(`${method}: response was not JSON`); }
    }
    const msg = messages.find(m => m && m.id === id);
    if (!msg) throw new IntrospectError(`${method}: no response with id ${id}`);
    if (msg.error) throw new IntrospectError(`server error: ${String(msg.error.message ?? '').slice(0, 200)}`);
    if (method === 'initialize' && typeof msg.result?.protocolVersion === 'string') version = msg.result.protocolVersion;
    return msg.result;
  };
  const notify: Notify = async (method, params) => {
    const res = await post({ jsonrpc: '2.0', method, ...(params ? { params } : {}) });
    await res.body?.cancel();
  };

  return withTimeout(catalog(rpc, notify), timeoutMs, () => controller.abort())
    .finally(() => {
      controller.abort();
      // Ends the session server-side when it kept one. Best effort.
      if (session) fetch(url, { method: 'DELETE', redirect: 'error', signal: AbortSignal.timeout(3000), headers: { ...headers, 'mcp-session-id': session } }).catch(() => {});
    });
}

export async function introspect(server: ResolvedServer, opts: IntrospectOptions = {}): Promise<LiveCatalog> {
  const timeoutMs = opts.timeoutMs ?? 20000;
  if (server.url) {
    if (opts.noNetwork) throw new IntrospectError('remote server skipped (--offline)');
    if ((server.type ?? '').toLowerCase() === 'sse') throw new IntrospectError('the legacy SSE transport is not supported by --live yet');
    let parsed: URL;
    try { parsed = new URL(server.url); } catch (_e) { throw new IntrospectError(`invalid url '${server.url}'`); }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new IntrospectError(`unsupported url scheme '${parsed.protocol}'`);
    return introspectHttp(server, timeoutMs);
  }
  if (!server.command) throw new IntrospectError('no command or url to connect to');
  return introspectStdio(server, timeoutMs);
}
