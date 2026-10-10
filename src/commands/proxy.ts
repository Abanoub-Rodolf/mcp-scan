import { spawn } from 'child_process';
import { logger } from '../utils/logger.js';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { Transform, TransformCallback } from 'stream';
import { StringDecoder } from 'string_decoder';
import { loadPolicy } from '../config/parser.js';
import { PolicyError, policyFileExists } from '../utils/policy-file.js';
import { maskPii, maskString, PrivacyOptions } from '../utils/privacy-engine.js';
import { reportBlessedImportError } from '../utils/dashboard-deps-hint.js';

// The proxy's stdout is the protocol channel to the client, so its own
// warnings go to stderr. Quiet while the dashboard owns the terminal.
function warnStderr(msg: string) {
  if (!logger.isSilent) process.stderr.write(`mcp-scan proxy: ${msg}\n`);
}

// writableLength stays at the full size of an in-flight write until it
// completes, so it overstates what the client is still owed once the kernel
// has taken part of it. libuv's writeQueueSize counts only what the kernel has
// not taken yet, but only of that one in-flight write: writes Node has queued
// behind it are in writableLength alone. So with the in-flight write's size
// known, owed = libuv's unsent part + everything queued behind it. Without it
// (no handle, nothing in flight) libuv's figure wins when it is above 0,
// otherwise writableLength. A value that is not a finite number counts as 0,
// so a changed internal can never wedge the proxy.
const finite = (n: unknown): number => (typeof n === 'number' && Number.isFinite(n) && n > 0 ? n : 0);
export const queuedBytes = (writableLength: unknown, writeQueueSize: unknown, inFlight?: unknown): number => {
  const sent = finite(inFlight);
  if (sent > 0) return finite(writeQueueSize) + Math.max(0, finite(writableLength) - sent);
  return finite(writeQueueSize) || finite(writableLength);
};

// Bytes still owed to whoever reads this stream, read off Node's internals the
// same defensive way (the in-flight size only counts when libuv's queue is readable).
export const owedBytes = (s: any): number => {
  const q = s?._handle?.writeQueueSize;
  const st = s?._writableState;
  return queuedBytes(s?.writableLength, q, st?.writing && typeof q === 'number' ? st.writelen : undefined);
};

const isJson = (text: string) => { try { JSON.parse(text); return true; } catch (_e) { return false; } };

const UNREACHABLE = 'Internal error: server is no longer reachable';

export class JsonRpcInterceptor extends Transform {
  private buffer: string = '';
  // A multibyte character can straddle two chunks; decoding each chunk on
  // its own would turn the halves into U+FFFD.
  private decoder = new StringDecoder('utf8');
  private direction: string;
  private logStream: fs.WriteStream | null;
  private privacyOptions?: PrivacyOptions;
  private dashboardCallback?: (dir: string, msg: string, pii: boolean) => void;
  private replyToSender?: (line: string) => void;
  private refusing = false;
  private discarding = false;
  // One entry per line pushed, in order: the requests it carries, with their
  // ids as the sender wrote them (masking may have changed the pushed copy).
  // Kept only for a consumer that reports back through settled(), or it grows forever.
  private inFlight: { batch: boolean; requests: { id: string | number }[] }[] = [];
  private tracking = false;

  constructor(direction: string, logStream: fs.WriteStream | null, privacyOptions?: PrivacyOptions, dashboardCallback?: (dir: string, msg: string, pii: boolean) => void, replyToSender?: (line: string) => void) {
    super();
    this.direction = direction;
    this.logStream = logStream;
    this.privacyOptions = privacyOptions;
    this.dashboardCallback = dashboardCallback;
    this.replyToSender = replyToSender;
  }

  _transform(chunk: Buffer, encoding: BufferEncoding, callback: TransformCallback) {
    if (this.discarding) return callback(); // gave up: queued input is dropped
    this.buffer += typeof chunk === 'string' ? chunk : this.decoder.write(chunk);

    const lines = this.buffer.split('\n');
    this.buffer = lines.pop() || ''; // Keep the incomplete line in buffer

    for (const line of lines) this.handleLine(line);
    callback();
  }

  // The destination is gone: stop forwarding, and give each later request
  // an error for its id so its sender doesn't wait forever. Notifications and
  // responses have nobody to answer and are dropped.
  refuseFurther() {
    this.refusing = true;
    this.resume(); // nothing is pushed any more, but keep the buffers moving
  }

  // The consumer takes the entries for each chunk when it writes it, in push
  // order, and reports the write's outcome for exactly those. Every request in
  // a chunk that never reached the destination is answered like a refused one,
  // so a burst sent just before the pipe broke does not leave its senders
  // waiting. Binding at write time means the outcome callbacks may fire in any
  // order.
  trackDelivery() {
    this.tracking = true;
  }

  claim(chunk: Buffer) {
    // every pushed line ends in exactly one newline, and 0x0a never occurs inside a UTF-8 sequence
    let n = 0;
    for (let i = chunk.indexOf(10); i !== -1; i = chunk.indexOf(10, i + 1)) n++;
    return this.inFlight.splice(0, n);
  }

  settled(entries: { batch: boolean; requests: { id: string | number }[] }[], err?: Error | null) {
    if (!err || !this.replyToSender) return;
    for (const { batch, requests } of entries) {
      if (requests.length > 0) this.replyToSender(this.errorLines(requests, batch, UNREACHABLE));
    }
  }

  private send(line: string, ids = { batch: false, requests: [] as { id: string | number }[] }) {
    if (this.tracking) this.inFlight.push(ids);
    this.push(line + '\n');
  }

  // Called when we stop waiting. Whatever is in the line buffer, and any
  // input still queued behind it for a stalled consumer (`unread` adds bytes
  // the caller knows are waiting upstream), may be the front or back half of
  // a line cut short, so none of it is forwarded: delivering the back half
  // would send a fragment as if it were a message. One exception: nothing
  // queued and a buffer that is complete JSON (just no newline) is kept for
  // the flush. Returns what was dropped.
  abandon(unread = 0): { queued: number; fragment: boolean } {
    const queued = this.writableLength + unread;
    const tail = this.buffer.trim();
    if (queued === 0) {
      if (!tail) return { queued: 0, fragment: false };
      if (isJson(tail)) return { queued: 0, fragment: false };
    }
    if (queued > 0) this.discarding = true;
    this.buffer = '';
    this.decoder = new StringDecoder('utf8');
    return { queued, fragment: tail.length > 0 };
  }

  private handleLine(line: string) {
    if (!line.trim()) return;

    let json: unknown;
    try {
      json = JSON.parse(line);
    } catch (_e) {
      if (this.refusing) return; // nobody to answer, and nowhere to send it
      // Not JSON: forward it, but never put the raw line in the
      // log or dashboard. It may hold secrets the string detectors miss.
      const note = `<unparsed line, ${line.length} chars, not logged>`;
      if (this.logStream) this.logStream.write(`[${this.direction} RAW] ${note}\n`);
      if (this.dashboardCallback) this.dashboardCallback(this.direction + ' RAW', note, false);
      // With masking on, an unparsed line gets the string detectors too.
      this.send(this.privacyOptions ? maskString(line, this.privacyOptions) : line);
      return;
    }

    if (this.refusing) {
      const { batch, requests } = this.snapshotIds(json);
      if (requests.length > 0 && this.replyToSender) this.replyToSender(this.errorLines(requests, batch, UNREACHABLE));
      return;
    }

    // Masking off: the line goes through byte for byte. Re-serializing it
    // could change numbers or throw on extreme nesting, and there is nothing
    // to mask.
    if (!this.privacyOptions) {
      if (this.logStream) this.logStream.write(`[${this.direction}] ${line}\n`);
      if (this.dashboardCallback) this.dashboardCallback(this.direction, line, false);
      this.send(line, this.snapshotIds(json));
      return;
    }

    // Mask BEFORE anything is written to disk: with the privacy engine
    // enabled, the raw JSON-RPC payload (which can contain secrets and
    // PII) must never be logged or forwarded.
    let piiMasked = false;
    // maskPii edits in place and can throw halfway, so take the ids first:
    // the error reply must carry the id exactly as the sender wrote it.
    const ids = this.snapshotIds(json);
    if (this.privacyOptions) {
      const dropped = ids;
      try {
        const originalStr = JSON.stringify(json);
        json = maskPii(json, this.privacyOptions);
        piiMasked = originalStr !== JSON.stringify(json);
      } catch (_e) {
        // Fail closed: a message we could not mask is neither logged
        // nor forwarded.
        const note = '<message dropped, masking failed>';
        if (this.logStream) this.logStream.write(`[${this.direction}] ${note}\n`);
        if (this.dashboardCallback) this.dashboardCallback(this.direction, note, false);
        this.answerDropped(dropped);
        return;
      }
    }

    const finalMsg = JSON.stringify(json);
    if (this.logStream) this.logStream.write(`[${this.direction}] ${finalMsg}\n`);
    if (this.dashboardCallback) this.dashboardCallback(this.direction, finalMsg, piiMasked);

    this.send(finalMsg, ids);
  }

  private snapshotIds(json: unknown) {
    const batch = Array.isArray(json);
    const msgs: any[] = batch ? json : [json];
    const withId = msgs.filter(m => !!m && typeof m === 'object' && (typeof m.id === 'string' || typeof m.id === 'number'));
    return {
      batch,
      requests: withId.filter(m => typeof m.method === 'string').map(m => ({ id: m.id })),
      responses: withId.filter(m => typeof m.method !== 'string').map(m => ({ id: m.id })),
    };
  }

  private errorLines(list: { id: string | number }[], batch: boolean, message: string) {
    const out = list.map(m => ({ jsonrpc: '2.0', id: m.id, error: { code: -32603, message } }));
    return JSON.stringify(batch ? out : out[0]) + '\n';
  }

  // A dropped message must not leave the other side waiting on its id
  // forever. A dropped request is answered to its sender with a generic
  // JSON-RPC error; a dropped response is replaced downstream by an error
  // for the same id, so the request it answered settles. Only ids are
  // echoed, never content. Anything else is dropped with a warning.
  private answerDropped({ batch, requests, responses }: ReturnType<JsonRpcInterceptor['snapshotIds']>) {
    const errors = (list: { id: string | number }[]) => this.errorLines(list, batch, 'Internal error: message not forwarded');
    if (requests.length > 0 && this.replyToSender) this.replyToSender(errors(requests));
    if (responses.length > 0) this.send(errors(responses).slice(0, -1));
    if ((requests.length === 0 || !this.replyToSender) && responses.length === 0) {
      warnStderr(`dropped a ${this.direction} message: privacy masking failed`);
    }
  }

  _flush(callback: TransformCallback) {
    // An unterminated last line goes through the same mask/drop path as any
    // other; pushing it raw would skip masking and logging.
    if (this.discarding) return callback();
    this.buffer += this.decoder.end();
    const tail = this.buffer;
    this.buffer = '';
    // A last line that is not valid JSON is the front of a message cut off
    // by the stream ending: forwarding it would hand the other side a
    // fragment as if it were a message.
    if (tail.trim() && !isJson(tail)) {
      const note = `dropped an unfinished last line (${this.direction}): the stream ended without a newline in the middle of a message`;
      warnStderr(note);
      if (this.dashboardCallback) this.dashboardCallback('PROXY', note, false);
      return callback();
    }
    this.handleLine(tail);
    callback();
  }
}

/**
 * Splits a command-line string into arguments, respecting single and
 * double quotes and commas as separators. The old split-on-comma-or-space
 * broke multi-word values (e.g. -c 'echo hi') and quoted paths.
 */
export function splitArgs(input: string): string[] {
  const tokens: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|([^\s,"]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(input)) !== null) {
    tokens.push(m[1] ?? m[2] ?? m[3]);
  }
  return tokens;
}

export async function runProxy(options: { command?: string, args?: string, ui?: boolean }) {
  logger.toStderr = true;
  if (!options.command) {
    console.error('No command specified for proxy. Use --command <cmd>.');
    process.exitCode = 1;
    return;
  }

  const policyFile = path.join(process.cwd(), '.mcp-scan.json');
  let policy: ReturnType<typeof loadPolicy> = null;
  try {
    policy = loadPolicy();
  } catch (err) {
    if (!(err instanceof PolicyError)) throw err;
    logger.error(`Not starting: ${err.message}`);
    process.exitCode = 1;
    return;
  }
  // Belt and braces: loadPolicy throws for anything unreadable, but running
  // without masking because of a policy we could not use defeats its point.
  if (policyFileExists(policyFile) && (!policy || typeof policy !== 'object' || Array.isArray(policy))) {
    logger.error(`Not starting: ${policyFile} exists but is not a valid policy object, so privacy settings cannot be trusted. Fix or remove it.`);
    process.exitCode = 1;
    return;
  }

  let dashboardCallback: undefined | ((dir: string, msg: string, pii: boolean) => void);
  const args = options.args ? splitArgs(options.args) : [];
  if (options.ui) {
      let createDashboard;
      try {
        ({ createDashboard } = await import('../utils/dashboard-ui.js'));
      } catch (err) {
        reportBlessedImportError(err);
        return;
      }
      const dashboard = createDashboard();
      dashboard.switchView('PROXY');
      dashboardCallback = dashboard.appendProxyLog;
      logger.isSilent = true; // suppress normal logging if UI is active
  } else {
      logger.brand('MCP Guard Proxy Active');
      logger.info(`Proxying: ${options.command} ${args.join(' ')}`);
  }

  let privacyOpts: PrivacyOptions | undefined;
  
  if (policy?.privacy?.maskPii) {
    logger.info('Data Privacy Engine: Enabled');
    privacyOpts = {
      disabledPatterns: policy.privacy.excludePatterns
    };
  } else {
    logger.info('Data Privacy Engine: Disabled');
  }

  // Log dir is overridable so tests (and embedders) can redirect it away
  // from the real user home. A failure to open the log never kills the proxy.
  const logDir = process.env.MCP_SCAN_LOG_DIR || path.join(os.homedir(), '.mcp-scan', 'logs');
  let logStream: fs.WriteStream | null = null;
  try {
    // Logs hold raw tool traffic: owner-only, so other accounts on a shared
    // machine can't read them.
    fs.mkdirSync(logDir, { recursive: true, mode: 0o700 });
    // The default dir may predate this fix at 0755, with old 0644 logs in
    // it. Tighten that one; never chmod a dir the user pointed us at.
    // A dir we don't own can refuse the chmod; that must not cost the log.
    if (!process.env.MCP_SCAN_LOG_DIR) {
      try {
        fs.chmodSync(logDir, 0o700);
      } catch (err) {
        warnStderr(`could not restrict ${logDir} to owner-only (${err instanceof Error ? err.message : String(err)}); logging continues at its current mode`);
      }
    }
    const logFile = path.join(logDir, `proxy-${Date.now()}.log`);
    logStream = fs.createWriteStream(logFile, { flags: 'a', mode: 0o600 });
    logStream.on('error', (err) => logger.warn(`Proxy log write failed: ${err.message}`));
    logger.detail(`Audit log: ${logFile}`);
  } catch (err) {
    logger.warn(`Proxy logging disabled: ${err instanceof Error ? err.message : String(err)}`);
  }

  const child = spawn(options.command, args, {
    stdio: ['pipe', 'pipe', 'inherit']
  });

  const clientInterceptor = new JsonRpcInterceptor('CLIENT -> SERVER', logStream, privacyOpts, dashboardCallback, line => process.stdout.write(line));
  const serverInterceptor = new JsonRpcInterceptor('SERVER -> CLIENT', logStream, privacyOpts, dashboardCallback, line => child.stdin.write(line));

  // The server can close its stdin or die while the client is still talking.
  // An unhandled 'error' on either writable would crash the proxy with a
  // stack trace, so note it once per stream and drop further writes. Under
  // --ui stderr is silent, so the dashboard gets the note instead.
  const writeFailed = (what: string) => {
    let warned = false;
    return (err: NodeJS.ErrnoException) => {
      if (warned) return;
      warned = true;
      const note = `${what} is no longer writable (${err.code || err.message}); dropping further messages`;
      warnStderr(note);
      if (dashboardCallback) dashboardCallback('PROXY', note, false);
    };
  };
  const serverStdinFailed = writeFailed('server stdin');
  child.stdin.on('error', (err: NodeJS.ErrnoException) => {
    serverStdinFailed(err);
    clientInterceptor.refuseFurther();
  });

  // Nobody is reading our stdout any more (the client went away, e.g. a
  // closed pipe): same as being told to terminate, or the server would be
  // orphaned for as long as it cares to run.
  const clientGone = writeFailed('proxy stdout');
  let stopping = false;
  process.stdout.on('error', (err: NodeJS.ErrnoException) => {
    clientGone(err);
    serverInterceptor.resume(); // discard what can no longer be delivered
    if (stopping) return;
    stopping = true;
    child.kill('SIGTERM');
    if (!process.env.MCP_SCAN_NO_EXIT) {
      setTimeout(() => { child.kill('SIGKILL'); process.exit(process.exitCode || 0); }, 3000).unref();
    }
  });
  // A closed stderr must not turn the warning itself into a crash.
  process.stderr.on('error', () => {});

  // Not pipe(): each write's outcome is reported back, so requests that were
  // already on their way when the server closed its stdin still get answered.
  clientInterceptor.trackDelivery();
  process.stdin.pipe(clientInterceptor);
  clientInterceptor.on('data', (chunk: Buffer) => {
    const sent = clientInterceptor.claim(chunk);
    const ok = child.stdin.write(chunk, err => clientInterceptor.settled(sent, err));
    if (!ok && !child.stdin.destroyed) {
      clientInterceptor.pause();
      child.stdin.once('drain', () => clientInterceptor.resume());
    }
  });
  clientInterceptor.on('end', () => child.stdin.end());
  child.stdout.pipe(serverInterceptor).pipe(process.stdout);

  // The server's last output can still be in the pipe when 'exit' fires, so
  // normally wait for 'close'. But a descendant that inherited the server's
  // stdout keeps that pipe open long after the server is gone. So after
  // 'exit' we give up only when nothing has moved for 2s: no new bytes from
  // the server and nothing queued on the way to a (possibly slow) client.
  let settled = false;
  let exitPoll: NodeJS.Timeout | undefined;
  let lastActivity = Date.now();
  child.stdout.on('data', () => { lastActivity = Date.now(); });
  process.stdout.on('drain', () => { lastActivity = Date.now(); });
  // Bytes still on their way to the client. writableLength only drops when a
  // whole queued write finishes, so one huge line read slowly looks frozen;
  // the libuv write queue shrinks as the reader takes bytes, so count it too.
  const stdoutQueue = () => finite((process.stdout as any)._handle?.writeQueueSize);
  // Movement signal: either figure changing means bytes moved (the sum
  // changes whenever one does). Not a byte count; see queuedBytes for that.
  const stdoutPending = () => finite(process.stdout.writableLength) + stdoutQueue();
  const backlog = () => child.stdout.readableLength + serverInterceptor.readableLength + serverInterceptor.writableLength + stdoutPending();
  // How long a client with output queued may stay silent before we give up
  // on it. One deadline: the exit poll and the post-settle net share it.
  const stallMs = Number(process.env.MCP_SCAN_STALL_MS) || 60000;
  const settle = (code: number | null, forced = false) => {
    if (settled) return;
    settled = true;
    const idleMs = Date.now() - lastActivity;
    if (exitPoll) clearInterval(exitPoll);
    logger.info(`Server exited with code ${code}`);
    process.exitCode = code || 0;
    const note = (msg: string) => {
      warnStderr(msg);
      if (dashboardCallback) dashboardCallback('PROXY', msg, false);
    };
    if (forced) {
      const dropped = serverInterceptor.abandon(child.stdout.readableLength);
      if (dropped.queued > 0) {
        note(`gave up on a client that stopped reading: dropped ${dropped.queued} bytes of server output not yet processed`);
      } else if (dropped.fragment) {
        note('dropped an unfinished last line from the server: it exited without a newline and its output pipe never closed');
      }
    }
    // We cut the client off here too; its half-read line has nowhere to go.
    const cut = clientInterceptor.abandon();
    if (cut.queued > 0 || cut.fragment) warnStderr('dropped an unfinished last line from the client');
    // Stop reading both sides and run each interceptor's flush, so an
    // unterminated last line is masked, logged and answered like any other.
    // The log is closed only after both are done, or it would lose that tail.
    process.stdin.unpipe(clientInterceptor);
    child.stdout.unpipe(serverInterceptor);
    if (!clientInterceptor.writableEnded) clientInterceptor.end();
    if (!serverInterceptor.writableEnded) serverInterceptor.end();
    let pending = 2;
    const part = () => {
      if (--pending > 0) return;
      // Queued output must drain before exit or process.exit() drops it.
      process.stdout.write('', () => {
        logStream?.end();
        if (!process.env.MCP_SCAN_NO_EXIT) process.exit(code || 0);
      });
    };
    if (clientInterceptor.writableFinished) part(); else clientInterceptor.once('finish', part);
    if (serverInterceptor.readableEnded) part(); else serverInterceptor.once('end', part);
    if (!process.env.MCP_SCAN_NO_EXIT) {
      // Safety net for a stdout that never drains: counts time with no
      // movement, not total time, so a slow reader still gets it all.
      let last = stdoutPending();
      // Time already spent stalled counts: the whole wait is one deadline,
      // plus a last second to flush what is already queued on stdout.
      const ticks = Math.ceil(stallMs / 500);
      // The preload is a floor: a client that reads a little and stalls
      // again does not get a fresh deadline.
      const floor = last > 0 ? Math.max(0, Math.min(ticks, Math.floor(idleMs / 500)) - 2) : 0;
      let still = floor;
      setInterval(() => {
        const now = stdoutPending();
        still = now === last ? still + 1 : floor;
        last = now;
        const owed = owedBytes(process.stdout);
        // Nothing queued and still not done is stuck (5s). A reader that
        // simply stopped reading gets the full stall deadline.
        if (still >= (now === 0 ? 10 : ticks)) {
          if (owed > 0) note(`client stopped reading: dropped ${owed} bytes of queued output`);
          logStream?.end();
          process.exit(code || 0);
        }
      }, 500).unref();
    }
  };
  child.on('exit', (code) => {
    lastActivity = Date.now();
    let lastBacklog = backlog();
    exitPoll = setInterval(() => {
      const now = backlog();
      if (now !== lastBacklog) { lastBacklog = now; lastActivity = Date.now(); }
      // Nothing queued: 2s of quiet is enough. Something queued for a client
      // that has stopped reading: that client gets stallMs (60s), then we cut it off,
      // or a descendant plus a dead reader would keep us up forever.
      if (Date.now() - lastActivity >= (now > 0 ? stallMs : 2000)) settle(code, true);
    }, 200);
  });
  child.on('close', (code) => settle(code));

  child.on('error', (err) => {
    logger.error(`Failed to start server: ${err.message}`);
    logStream?.end();
    process.exitCode = 1;
    if (!process.env.MCP_SCAN_NO_EXIT) process.exit(1);
  });

  process.on('SIGINT', () => {
    logger.info('Shutting down proxy...');
    child.kill('SIGINT');
  });

  process.on('SIGTERM', () => {
    child.kill('SIGTERM');
  });
}
