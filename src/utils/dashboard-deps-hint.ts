// blessed and blessed-contrib are optionalDependencies (dashboard-ui.ts).
// A missing-module error there means the optional install was skipped
// (--omit=optional, a stripped-down CI image, etc). Any other error from
// that same import (a syntax error, a broken transitive dep) is unrelated
// and must not be swallowed into a misleading "go install blessed" hint.
const BLESSED_INSTALL_HINT =
  'The dashboard needs blessed and blessed-contrib. Install mcp-scan with its optional dependencies: npm i -g mcp-scan';

interface NodeImportError extends Error {
  code?: string;
}

function isMissingBlessedError(err: unknown): err is NodeImportError {
  if (!(err instanceof Error)) return false;
  const code = (err as NodeImportError).code;
  return (code === 'ERR_MODULE_NOT_FOUND' || code === 'MODULE_NOT_FOUND') && err.message.includes('blessed');
}

// Prints a hint for the known "optional dep not installed" case, or the
// real error message for anything else, and marks the process failed.
// Never throws: callers return right after calling this.
export function reportBlessedImportError(err: unknown): void {
  console.error(isMissingBlessedError(err) ? BLESSED_INSTALL_HINT : err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
}
