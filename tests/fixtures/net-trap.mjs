// Preloaded with NODE_OPTIONS=--import in serve.test.ts. Any outbound
// fetch or socket connect records itself in NET_TRAP_FILE and fails.
import fs from 'node:fs';
import net from 'node:net';

const mark = (what) => fs.appendFileSync(process.env.NET_TRAP_FILE, what + '\n');

globalThis.fetch = async (url) => {
  mark(`fetch ${url}`);
  throw new Error('network blocked by test trap');
};

const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  const target = typeof args[0] === 'object' && args[0] !== null ? args[0].host ?? args[0].path : args[0];
  // The stdio MCP transport uses no sockets, so any connect is a leak.
  mark(`connect ${target}`);
  return connect.apply(this, args);
};
