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

// Opens once and checks the type of what was opened, so a FIFO swapped in
// after a separate stat cannot hang the read. O_NONBLOCK makes opening a FIFO
// return at once; the type check then rejects it before any read. A directory
// or device is rejected the same way.
export function readPolicyFile(p: string): string {
  const fd = fs.openSync(p, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0));
  try {
    if (!fs.fstatSync(fd).isFile()) throw new Error('not a regular file');
    return fs.readFileSync(fd, 'utf8');
  } finally {
    fs.closeSync(fd);
  }
}
