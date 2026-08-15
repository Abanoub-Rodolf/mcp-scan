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
export function atomicWriteConfig(configPath: string, content: string): void {
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
}
