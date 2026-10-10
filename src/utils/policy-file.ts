import fs from 'fs';

// Thrown when a policy file is there but cannot be trusted (unreadable,
// unparseable, wrong shape) or when a policy the user named is missing.
// Scanning without it would silently drop enforcement, so callers stop.
export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PolicyError';
  }
}

// existsSync is false for a dangling symlink, but that is still a policy
// the user put there and we failed to read, not an absent one.
export function policyFileExists(p: string): boolean {
  if (fs.existsSync(p)) return true;
  try {
    return fs.lstatSync(p)?.isSymbolicLink() === true;
  } catch (_e) {
    return false;
  }
}

// A directory or a FIFO must error, not hang or be read as a policy.
export function assertRegularFile(p: string): void {
  const st = fs.statSync(p);
  if (st && !st.isFile()) throw new Error('not a regular file');
}
