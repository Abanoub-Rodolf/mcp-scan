import { ResolvedServer } from '../types/config.js';

/**
 * Builds the text surface a scanner should evaluate for a server.
 *
 * MCP's threat model (2026) treats the tool catalog as part of the prompt:
 * tool names, descriptions, and JSON schemas all land in the model's
 * context at tools/list time. Payloads therefore hide in nested schema
 * `description` and `enum` values, not just the top-level description.
 * Every scanner that looks for instruction injection must scan the union
 * of these surfaces, not just `server.description`.
 */
export function buildScanText(server: ResolvedServer): string {
  const parts: string[] = [server.name, server.description];

  const args = server.args
    ? (Array.isArray(server.args) ? server.args : Object.values(server.args))
    : [];
  for (const arg of args) {
    if (typeof arg === 'string') parts.push(arg);
  }

  const tools = server.schema?.tools;
  if (Array.isArray(tools)) {
    const visit = (value: unknown): void => {
      if (value == null) return;
      if (typeof value === 'string') {
        parts.push(value);
        return;
      }
      if (Array.isArray(value)) {
        for (const item of value) visit(item);
        return;
      }
      if (typeof value === 'object') {
        for (const key of Object.keys(value as Record<string, unknown>)) {
          // property names and descriptions are read by the model
          parts.push(key);
          visit((value as Record<string, unknown>)[key]);
        }
      }
    };

    for (const tool of tools) {
      if (typeof tool === 'object' && tool !== null) {
        visit(tool);
      }
    }
  }

  return parts.filter((p): p is string => typeof p === 'string' && p.length > 0).join('\n');
}
