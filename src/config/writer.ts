import fs from 'fs';
import path from 'path';

/**
 * Atomically replaces a config file while preserving the original file's
 * permissions and symlink target.
 *
 * The naive temp-write + rename approach had three problems: a previously
 * 0600 secrets file became world-readable after the fix command rewrote it
 * (the temp file got default 0666 & umask); a symlinked config (common in
 * dotfiles setups) was replaced by a plain file; and formatting/comments
 * were silently lost. This version copies the mode from the existing file,
 * resolves symlinks before replacing, and keeps a timestamped backup.
 */
export function atomicWriteConfig(
  configPath: string,
  content: string,
  opts: { keepBackups?: number } = {},
): void {
  const dir = path.dirname(configPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  // Resolve symlinks so we replace the real file, not the link.
  const targetPath = fs.existsSync(configPath) ? fs.realpathSync(configPath) : configPath;

  let originalMode: number | undefined;
  try {
    originalMode = fs.statSync(targetPath).mode;
  } catch (_err) {
    // Target does not exist yet; nothing to preserve.
  }

  const tempPath = `${targetPath}.tmp-${Date.now()}`;
  const backupPath = `${targetPath}.backup-${Date.now()}`;

  // Create a timestamped backup if the target exists. A single fixed
  // .backup name was overwritten on every run; the timestamped name keeps
  // the pre-fix state around for recovery.
  if (fs.existsSync(targetPath)) {
    try {
      fs.copyFileSync(targetPath, backupPath);
    } catch (_err) {
      // Ignore backup failures (e.g. read-only)
    }
  }

  try {
    fs.writeFileSync(tempPath, content, 'utf8');
    if (originalMode !== undefined) {
      fs.chmodSync(tempPath, originalMode);
    }
    fs.renameSync(tempPath, targetPath);
  } catch (error) {
    // Cleanup temp if it failed
    if (fs.existsSync(tempPath)) {
      try { fs.unlinkSync(tempPath); } catch (_err) {}
    }
    throw error;
  }

  // Machine-written stores are rewritten on every scan, so their backups pile
  // up (one real ~/.mcp-scan held 1,191). User configs never pass this: there
  // the oldest backup is the pre-fix original.
  if (opts.keepBackups !== undefined) {
    try {
      pruneBackups(targetPath, backupPath, opts.keepBackups);
    } catch (_err) {
      // A failed prune must never fail the write.
    }
  }
}

function pruneBackups(targetPath: string, backupPath: string, keep: number): void {
  const dir = path.dirname(targetPath);
  const prefix = `${path.basename(targetPath)}.backup-`;
  const sorted = fs.readdirSync(dir)
    .filter(f => f.startsWith(prefix) && /^\d+$/.test(f.slice(prefix.length)))
    .sort((a, b) => Number(b.slice(prefix.length)) - Number(a.slice(prefix.length)));
  // A clock that stepped back leaves older backups with later stamps; the one
  // this write just made must never be the one cut.
  const own = sorted.indexOf(path.basename(backupPath));
  if (own > 0) sorted.unshift(...sorted.splice(own, 1));
  const stale = sorted.slice(Math.max(keep, 0));
  for (const f of stale) {
    try { fs.unlinkSync(path.join(dir, f)); } catch (_err) {}
  }
}
