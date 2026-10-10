import fs from 'fs';

// Thrown for a path that exists but is a directory, FIFO, device or socket.
export class NotRegularFileError extends Error {
  readonly isDirectory: boolean;
  constructor(readonly path: string, isDirectory: boolean) {
    super(isDirectory ? 'is a directory' : 'not a regular file');
    this.name = 'NotRegularFileError';
    this.isDirectory = isDirectory;
  }
}

// Opens once and checks the type of what was opened, so a FIFO swapped in
// after a separate stat cannot hang the read. O_NONBLOCK makes opening a FIFO
// return at once; the type check then rejects it before any read.
export function readRegularFile(p: string): string {
  const fd = fs.openSync(p, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0));
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw new NotRegularFileError(p, st.isDirectory());
    return fs.readFileSync(fd, 'utf8');
  } finally {
    fs.closeSync(fd);
  }
}
