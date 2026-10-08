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
  // Skip the ~/.mcp-scan audit log and fingerprint writes. Used by the
  // MCP server, whose tools are advertised as read-only.
  readOnly?: boolean;
  // Contents of `config`, when the caller already read them safely.
  configContent?: string;
}
