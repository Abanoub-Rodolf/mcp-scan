/**
 * Options accepted by runScan. Single source of truth: the CLI, the
 * library entry (src/lib.ts), and the runScan implementation all share
 * this type so the public API cannot drift from the implementation.
 */
export interface ScanOptions {
  silent?: boolean;
  json?: boolean;
  verbose?: boolean;
  severity?: string;
  config?: string;
  version?: string;
  ugig?: boolean;
  ci?: boolean;
  sbom?: string;
  sarif?: string;
  policy?: string;
  offline?: boolean;
  submit?: boolean;
  /** Start each stdio/HTTP server and scan the tools, prompts and resources it really serves. */
  live?: boolean;
  /** With live: accept changed tool definitions as the new baseline. */
  acceptToolChanges?: boolean;
  /** With live: per-server connect timeout in ms. */
  liveTimeout?: number;
}
