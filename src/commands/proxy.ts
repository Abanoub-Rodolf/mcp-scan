import { spawn } from 'child_process';
import { logger } from '../utils/logger.js';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { Transform, TransformCallback } from 'stream';
import { loadPolicy } from '../config/parser.js';
import { maskPii, PrivacyOptions } from '../utils/privacy-engine.js';
import { reportBlessedImportError } from '../utils/dashboard-deps-hint.js';

class JsonRpcInterceptor extends Transform {
  private buffer: string = '';
  private direction: string;
  private logStream: fs.WriteStream | null;
  private privacyOptions?: PrivacyOptions;
  private dashboardCallback?: (dir: string, msg: string, pii: boolean) => void;

  constructor(direction: string, logStream: fs.WriteStream | null, privacyOptions?: PrivacyOptions, dashboardCallback?: (dir: string, msg: string, pii: boolean) => void) {
    super();
    this.direction = direction;
    this.logStream = logStream;
    this.privacyOptions = privacyOptions;
    this.dashboardCallback = dashboardCallback;
  }

  _transform(chunk: Buffer, encoding: BufferEncoding, callback: TransformCallback) {
    this.buffer += chunk.toString();
    
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop() || ''; // Keep the incomplete line in buffer

    for (const line of lines) {
      if (line.trim()) {
        try {
          let json = JSON.parse(line);

          // Mask BEFORE anything is written to disk: with the privacy engine
          // enabled, the raw JSON-RPC payload (which can contain secrets and
          // PII) must never be logged or forwarded.
          let piiMasked = false;
          if (this.privacyOptions) {
            const originalStr = JSON.stringify(json);
            json = maskPii(json, this.privacyOptions);
            piiMasked = originalStr !== JSON.stringify(json);
          }

          const finalMsg = JSON.stringify(json);
          if (this.logStream) this.logStream.write(`[${this.direction}] ${finalMsg}\n`);
          if (this.dashboardCallback) this.dashboardCallback(this.direction, finalMsg, piiMasked);
          
          this.push(finalMsg + '\n');
        } catch (_e) {
          // If not valid JSON, just pass through and log as raw
          if (this.logStream) this.logStream.write(`[${this.direction} RAW] ${line}\n`);
          if (this.dashboardCallback) this.dashboardCallback(this.direction + ' RAW', line, false);
          this.push(line + '\n');
        }
      }
    }
    callback();
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
    fs.mkdirSync(logDir, { recursive: true });
    const logFile = path.join(logDir, `proxy-${Date.now()}.log`);
    logStream = fs.createWriteStream(logFile, { flags: 'a' });
    logStream.on('error', (err) => logger.warn(`Proxy log write failed: ${err.message}`));
    logger.detail(`Audit log: ${logFile}`);
  } catch (err) {
    logger.warn(`Proxy logging disabled: ${err instanceof Error ? err.message : String(err)}`);
  }

  const child = spawn(options.command, args, {
    stdio: ['pipe', 'pipe', 'inherit']
  });

  const clientInterceptor = new JsonRpcInterceptor('CLIENT -> SERVER', logStream, privacyOpts, dashboardCallback);
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
