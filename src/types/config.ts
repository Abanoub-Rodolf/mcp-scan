export interface McpServerEntry {
  command?: string;
  args?: string[];
  url?: string;
  type?: string;
  env?: Record<string, string>;
  disabled?: boolean;
  description?: string;
  schema?: any;
}

/**
 * What real-world config files actually contain before normalization:
 * args may be an object instead of an array and env values may be
 * numbers or booleans. parseConfig returns these; extractServers is the
 * documented boundary that turns them into strict McpServerEntries.
 */
export type RawMcpServerEntry = Omit<McpServerEntry, 'args' | 'env'> & {
  args?: string[] | Record<string, unknown>;
  env?: Record<string, unknown>;
};

export interface McpConfig {
  mcpServers: Record<string, RawMcpServerEntry>;
}

export interface DetectedTool {
  name: string;
  configPath: string;
  exists: boolean;
}

export interface ResolvedServer extends McpServerEntry {
  name: string;
  toolName: string;
  configPath: string;
}

export interface McpScanPolicy {
  allowedPackages?: string[];
  blockedPackages?: string[];
  allowedDomains?: string[];
  requiredEnvVarPrefix?: string;
  maxSeverity?: 'info' | 'low' | 'medium' | 'high' | 'critical';
  suppressRules?: string[];
  privacy?: {
    maskPii?: boolean;
    excludePatterns?: string[];
    customPatterns?: Record<string, string>;
  };
}
