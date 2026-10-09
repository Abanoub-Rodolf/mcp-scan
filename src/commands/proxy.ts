import { spawn } from 'child_process';
import { logger } from '../utils/logger.js';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { Transform, TransformCallback } from 'stream';
import { StringDecoder } from 'string_decoder';
import { loadPolicy } from '../config/parser.js';
import { maskPii, maskString, PrivacyOptions } from '../utils/privacy-engine.js';
import { reportBlessedImportError } from '../utils/dashboard-deps-hint.js';

// The proxy's stdout is the protocol channel to the client, so its own
// warnings go to stderr. Quiet while the dashboard owns the terminal.
function warnStderr(msg: string) {
  if (!logger.isSilent) process.stderr.write(`mcp-scan proxy: ${msg}\n`);
}

class JsonRpcInterceptor extends Transform {
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

  constructor(direction: string, logStream: fs.WriteStream | null, privacyOptions?: PrivacyOptions, dashboardCallback?: (dir: string, msg: string, pii: boolean) => void, replyToSender?: (line: string) => void) {
    super();
    this.direction = direction;
    this.logStream = logStream;
    this.privacyOptions = privacyOptions;
    this.dashboardCallback = dashboardCallback;
    this.replyToSender = replyToSender;
  }

  _transform(chunk: Buffer, encoding: BufferEncoding, callback: TransformCallback) {
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

  private handleLine(line: string) {
    if (!line.trim()) return;

    let json: unknown;
    try {
      json = JSON.parse(line);
    } catch (_e) {
      // Not JSON: forward it, but never put the raw line in the
      // log or dashboard. It may hold secrets the string detectors miss.
      const note = `<unparsed line, ${line.length} chars, not logged>`;
      if (this.logStream) this.logStream.write(`[${this.direction} RAW] ${note}\n`);
      if (this.dashboardCallback) this.dashboardCallback(this.direction + ' RAW', note, false);
      // With masking on, an unparsed line gets the string detectors too.
      this.push((this.privacyOptions ? maskString(line, this.privacyOptions) : line) + '\n');
      return;
    }

    if (this.refusing) {
      const { batch, requests } = this.snapshotIds(json);
      if (requests.length > 0 && this.replyToSender) this.replyToSender(this.errorLines(requests, batch, 'Internal error: server is no longer reachable'));
      return;
    }

    // Masking off: the line goes through byte for byte. Re-serializing it
    // could change numbers or throw on extreme nesting, and there is nothing
    // to mask.
    if (!this.privacyOptions) {
      if (this.logStream) this.logStream.write(`[${this.direction}] ${line}\n`);
      if (this.dashboardCallback) this.dashboardCallback(this.direction, line, false);
      this.push(line + '\n');
      return;
    }

    // Mask BEFORE anything is written to disk: with the privacy engine
    // enabled, the raw JSON-RPC payload (which can contain secrets and
    // PII) must never be logged or forwarded.
    let piiMasked = false;
    if (this.privacyOptions) {
      // maskPii edits in place and can throw halfway, so take the ids first:
      // the error reply must carry the id exactly as the sender wrote it.
      const dropped = this.snapshotIds(json);
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

    this.push(finalMsg + '\n');
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
    if (responses.length > 0) this.push(errors(responses));
    if ((requests.length === 0 || !this.replyToSender) && responses.length === 0) {
      warnStderr(`dropped a ${this.direction} message: privacy masking failed`);
    }
  }

  _flush(callback: TransformCallback) {
    // An unterminated last line goes through the same mask/drop path as any
    // other; pushing it raw would skip masking and logging.
    this.buffer += this.decoder.end();
    const tail = this.buffer;
    this.buffer = '';
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

  const policy = loadPolicy();
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

  process.stdin.pipe(clientInterceptor).pipe(child.stdin);
  child.stdout.pipe(serverInterceptor).pipe(process.stdout);

  // The server's last output can still be in the pipe when 'exit' fires, so
  // normally wait for 'close'. But a descendant that inherited the server's
  // stdout keeps that pipe open long after the server is gone, so 'exit'
  // starts a short grace period after which we stop waiting.
  let settled = false;
  let grace: NodeJS.Timeout | undefined;
  const settle = (code: number | null) => {
    if (settled) return;
    settled = true;
    if (grace) clearTimeout(grace);
    logger.info(`Server exited with code ${code}`);
    process.exitCode = code || 0;
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
    if (!process.env.MCP_SCAN_NO_EXIT) setTimeout(() => process.exit(code || 0), 5000).unref();
  };
  child.on('exit', (code) => { grace = setTimeout(() => settle(code), 2000); });
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
