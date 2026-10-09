import { spawn } from 'child_process';
import { logger } from '../utils/logger.js';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { Transform, TransformCallback } from 'stream';
import { loadPolicy } from '../config/parser.js';
import { maskPii, PrivacyOptions } from '../utils/privacy-engine.js';
import { reportBlessedImportError } from '../utils/dashboard-deps-hint.js';

// The proxy's stdout is the protocol channel to the client, so its own
// warnings go to stderr. Quiet while the dashboard owns the terminal.
function warnStderr(msg: string) {
  if (!logger.isSilent) process.stderr.write(`mcp-scan proxy: ${msg}\n`);
}

class JsonRpcInterceptor extends Transform {
  private buffer: string = '';
  private direction: string;
  private logStream: fs.WriteStream | null;
  private privacyOptions?: PrivacyOptions;
  private dashboardCallback?: (dir: string, msg: string, pii: boolean) => void;
  private replyToClient?: (line: string) => void;

  constructor(direction: string, logStream: fs.WriteStream | null, privacyOptions?: PrivacyOptions, dashboardCallback?: (dir: string, msg: string, pii: boolean) => void, replyToClient?: (line: string) => void) {
    super();
    this.direction = direction;
    this.logStream = logStream;
    this.privacyOptions = privacyOptions;
    this.dashboardCallback = dashboardCallback;
    this.replyToClient = replyToClient;
  }

  _transform(chunk: Buffer, encoding: BufferEncoding, callback: TransformCallback) {
    this.buffer += chunk.toString();
    
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop() || ''; // Keep the incomplete line in buffer

    for (const line of lines) {
      if (line.trim()) {
        let json: unknown;
        try {
          json = JSON.parse(line);
        } catch (_e) {
          // Not JSON: forward untouched, but never put the raw line in the
          // log or dashboard. It can't be masked, so it may hold secrets.
          const note = `<unparsed line, ${line.length} chars, not logged>`;
          if (this.logStream) this.logStream.write(`[${this.direction} RAW] ${note}\n`);
          if (this.dashboardCallback) this.dashboardCallback(this.direction + ' RAW', note, false);
          this.push(line + '\n');
          continue;
        }

        // Mask BEFORE anything is written to disk: with the privacy engine
        // enabled, the raw JSON-RPC payload (which can contain secrets and
        // PII) must never be logged or forwarded.
        let piiMasked = false;
        if (this.privacyOptions) {
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
            this.answerDropped(json);
            continue;
          }
        }

        const finalMsg = JSON.stringify(json);
        if (this.logStream) this.logStream.write(`[${this.direction}] ${finalMsg}\n`);
        if (this.dashboardCallback) this.dashboardCallback(this.direction, finalMsg, piiMasked);

        this.push(finalMsg + '\n');
      }
    }
    callback();
  }

  // A dropped client request would leave the client waiting on its id
  // forever, so it gets a generic JSON-RPC error back. Only the id is
  // echoed, never the content. Everything else is dropped with a warning.
  private answerDropped(json: unknown) {
    const batch = Array.isArray(json);
    const ids = (batch ? json : [json])
      .filter((m): m is { id: string | number } => !!m && typeof m === 'object' && typeof (m as any).method === 'string'
        && (typeof (m as any).id === 'string' || typeof (m as any).id === 'number'))
      .map(m => m.id);
    if (!this.replyToClient || ids.length === 0) {
      warnStderr(`dropped a ${this.direction} message: privacy masking failed`);
      return;
    }
    const errors = ids.map(id => ({ jsonrpc: '2.0', id, error: { code: -32603, message: 'Internal error: request not forwarded' } }));
    this.replyToClient(JSON.stringify(batch ? errors : errors[0]) + '\n');
  }

  _flush(callback: TransformCallback) {
    if (this.buffer.trim()) {
      this.push(this.buffer);
    }
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
  const serverInterceptor = new JsonRpcInterceptor('SERVER -> CLIENT', logStream, privacyOpts, dashboardCallback);

  process.stdin.pipe(clientInterceptor).pipe(child.stdin);
  child.stdout.pipe(serverInterceptor).pipe(process.stdout);

  child.on('exit', (code) => {
    logger.info(`Server exited with code ${code}`);
    logStream?.end();
    process.exitCode = code || 0;
    if (!process.env.MCP_SCAN_NO_EXIT) process.exit(code || 0);
  });

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
