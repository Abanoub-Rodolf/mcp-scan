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

// existsSync is false for a dangling symlink or a file behind a directory we
// can't search, but those are still policies the user put there and we failed
// to read. Only a path that is really not there counts as absent.
export function policyFileExists(p: string): boolean {
  if (fs.existsSync(p)) return true;
  try {
    return fs.lstatSync(p, { throwIfNoEntry: false }) !== undefined;
  } catch (e: any) {
    // throwIfNoEntry only covers ENOENT; a parent that is a file still means absent.
    return e?.code !== 'ENOTDIR';
  }
}

// Opens once and checks the type of what was opened, so a FIFO swapped in
// after a separate stat cannot hang the read. O_NONBLOCK makes opening a FIFO
// return at once; the type check then rejects it before any read. A directory
// or device is rejected the same way.
export function readPolicyFile(p: string): string {
  let fd: number;
  try {
    fd = fs.openSync(p, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0));
  } catch (e: any) {
    // ENOENT on a path that lstat sees means a dangling link; say so, not "no such file".
    if (e.code === 'ENOENT') {
      let target: string | undefined;
      try { target = fs.readlinkSync(p); } catch (_e) { /* not a symlink */ }
      if (target !== undefined) throw new Error(`symlink target not found: ${target}`);
    }
    throw e;
  }
  try {
    if (!fs.fstatSync(fd).isFile()) throw new Error('not a regular file');
    return fs.readFileSync(fd, 'utf8');
  } finally {
    fs.closeSync(fd);
  }
}
