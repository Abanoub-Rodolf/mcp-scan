// Variables the AI client expands itself before it launches a server, so a
// reference to one is neither a missing env var nor an injection vector.
// Claude Code sets CLAUDE_PLUGIN_ROOT for servers bundled in a plugin.
export const CLIENT_VARS = new Set(['CLAUDE_PLUGIN_ROOT']);

export const stripClientVars = (s: string) =>
  s.replace(/\$(?:\{([A-Za-z0-9_]+)\}|([A-Za-z0-9_]+))/g, (ref, braced, bare) => (CLIENT_VARS.has(braced ?? bare) ? '' : ref));
