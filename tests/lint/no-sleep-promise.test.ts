import { describe, it, expect } from 'vitest';
import { ESLint } from 'eslint';
import path from 'path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const eslint = new ESLint({ cwd: REPO });

// Lints the snippet as a test file with the repo's real config and returns the
// ids of the sleep-ban rules that fired.
async function banned(code: string): Promise<string[]> {
  const [res] = await eslint.lintText(`async function t() {\n${code}\n}\nvoid t;\n`, { filePath: path.join(REPO, 'tests/snippet.test.ts') });
  const ids = ['local/no-sleep-promise', 'no-restricted-syntax', 'no-restricted-imports'];
  return res.messages.filter(m => m.ruleId && ids.includes(m.ruleId)).map(m => m.ruleId!);
}

const SLEEPS = [
  'await new Promise(r => setTimeout(r, 5));',
  'await new Promise((r, j) => setTimeout(r, 5));',
  'await new Promise((r, _j) => { setTimeout(() => { r(1); }, 5); });',
  'await new Promise(function (resolve) { setTimeout(resolve, 5); });',
  'await new Promise(r => globalThis.setTimeout(r, 5));',
  'await new Promise(r => globalThis.setTimeout(() => r(undefined), 5));',
  'await new Promise(r => setInterval(r, 5));',
  'const P = Promise; await new P(r => setTimeout(r, 5));',
  'await new Promise(r => setTimeout(r.bind(null), 5));',
  'await new Promise(r => { const t = setTimeout(r, 5); void t; });',
  // the resolver is only read, or sits in a callback nobody gets: still a pure sleep
  'await new Promise(r => { if (r) setTimeout(r, 5); });',
  'await new Promise(r => { void typeof r; setTimeout(r, 5); });',
  'await new Promise(r => { const unused = () => r(); setTimeout(r, 5); });',
  'await new Promise(r => { [1].forEach(r => console.log(r)); setTimeout(r, 5); });',
  'await new Promise(r => { r.length; setTimeout(r, 5); });',
  'await new Promise(r => { r(); setTimeout(r, 5); });',
  // an alias is a handoff only when the alias itself is given away
  'await new Promise(r => { const a = r; setTimeout(r, 5); });',
  'await new Promise(r => { const done = r; void done; setTimeout(r, 5); });',
  'await new Promise(r => { const f = r.bind(null); setTimeout(f, 5); });',
  'await new Promise(r => { let f; f = r.bind(null); setTimeout(f, 5); });',
  'await new Promise(r => { const a = r; setTimeout(a, 5); });',
  'await new Promise(r => { const a = r; const b = a; setTimeout(b, 5); });',
  'await new Promise(r => { const rec = { resolve: r }; setTimeout(r, 5); void rec; });',
  // a guard whose timer resolves is a sleep unless something else gets the resolver
  'await new Promise((r, j) => { setTimeout(() => r(1), 5); void j; });',
  'await new Promise((r, j) => { setTimeout(() => { if (x) j(new Error("d")); else r(1); }, 5); });',
  'await new Promise((r, j) => { const t = setTimeout(() => r("none"), 5); clearTimeout(t); void j; });',
  // the timer reaches the resolver through a helper or a branch
  'await new Promise(r => { setTimeout(() => process.nextTick(r), 5); });',
  'await new Promise(r => { setTimeout(() => done(r), 5); });',
  'await new Promise(r => { setTimeout(once(r), 5); });',
  'await new Promise(r => { setTimeout(c ? r : r, 5); });',
  'await new Promise(r => { const w = once(r); setTimeout(w, 5); });',
  // using it inside a function nobody gets, or logging it, hands nothing off
  'await new Promise(r => { console.log(r); setTimeout(r, 5); });',
  'await new Promise(r => { const u = () => { use(r); }; setTimeout(r, 5); });',
  'await new Promise(r => { const u = () => { saved = r; }; setTimeout(r, 5); });',
  'await new Promise(r => { const u = () => r; setTimeout(r, 5); void u; });',
  'await new Promise(r => { function u() { return r; } setTimeout(r, 5); });',
  // a shadowing binding is a different variable, whatever it is used for
  'await new Promise(r => { function h(r) { use(r); } h(1); setTimeout(r, 5); });',
  'await new Promise(r => { try { go(); } catch (r) { use(r); } setTimeout(r, 5); });',
  'await new Promise(r => { function keep(r) { return r; } keep(null); setTimeout(r, 5); });',
  'await new Promise(r => { { let r = 1; use(r); } setTimeout(r, 5); });',
];

const IMPORTS = [
  "await import('node:timers/promises');",
  "await import('timers/promises');",
  "const x = require('node:timers/promises'); void x;",
  "const s = promisify(setTimeout); void s;",
];

const ALLOWED = [
  // deadline guards: the timer throws or rejects
  "await new Promise(r => { server.on('x', r); setTimeout(() => { throw new Error('deadline'); }, 5000); });",
  "await new Promise((r, j) => { server.on('x', r); setTimeout(() => j(new Error('deadline')), 5000); });",
  "await new Promise(r => { setTimeout(() => { throw new Error('d'); }, 5); setTimeout(() => console.log('hi'), 5); r(1); });",
  // deadline guards on their own: the timer only throws or rejects, and nothing
  // else gets the resolver, so these cannot pass through a handoff
  "await new Promise(r => { setTimeout(() => { throw new Error('deadline'); }, 5000); void r; });",
  "await new Promise((r, j) => { setTimeout(() => j(new Error('deadline')), 5000); void r; });",
  "await new Promise((r, j) => { setTimeout(j, 5000); void r; });",
  "await new Promise((r, j) => { const t = setTimeout(() => j(new Error('deadline')), 5000); void t; void r; });",
  // resolve-style guard, resolver also handed to something else
  "await new Promise(resolve => { const t = setTimeout(() => resolve('none'), 5); onEvent(resolve); clearTimeout(t); });",
  "await new Promise(r => { server.on('x', r); setTimeout(r, 5000); });",
  "await new Promise(r => { server.on('x', () => r(1)); setTimeout(() => r(2), 5000); });",
  "let saved: unknown; await new Promise(r => { saved = r; setTimeout(() => r(1), 5); }); void saved;",
  "await new Promise(r => { const keep = r; onEvent(keep); setTimeout(r, 5); });",
  "await new Promise(r => { handlers.push(r); setTimeout(r, 5); });",
  "const fn = await new Promise(r => { setTimeout(r, 5); return r; });",
  // .bind is the resolver
  "await new Promise(r => { ee.once('x', r.bind(null)); setTimeout(r, 5); });",
  "await new Promise(r => { setTimeout(() => r(), 5); ee.once('x', r.bind(null, 1)); });",
  // a listener that calls it, given away
  "await new Promise(r => { ee.once('x', () => { r(); }); setTimeout(() => r(), 5); });",
  "await new Promise(r => { handlers.x = () => r(); setTimeout(r, 5); });",
  // aliases that are given away
  "await new Promise(r => { const a = r; ee.on('x', a); setTimeout(r, 5); });",
  "await new Promise(r => { const a = r.bind(null); ee.once('x', a); setTimeout(a, 5); });",
  "await new Promise(r => { const a = r; const b = a; handlers.push(b); setTimeout(r, 5); });",
  "await new Promise(r => { let f; f = r; ee.on('x', f); setTimeout(r, 5); });",
  // the resolver sits in an object that is given
  "await new Promise(r => { const t = setTimeout(() => r(), 5); pending.set(1, { resolve: r, timer: t }); });",
  "await new Promise(r => { const rec = { resolve: r }; pending.set(1, rec); setTimeout(r, 5); });",
  "await new Promise(r => { handlers.push([r]); setTimeout(r, 5); });",
  // a named handler given to a listener
  "await new Promise(r => { const h = () => r(); ee.on('x', h); setTimeout(r, 5); });",
  "await new Promise(r => { function h() { r(); } ee.on('x', h); setTimeout(r, 5); });",
  // ...unless the resolver is handed off some other way
  "await new Promise(r => { setTimeout(() => done(r), 5); ee.on('x', r); });",
  "await new Promise(r => { setTimeout(once(r), 5); ee.on('x', r); });",
  "await new Promise(r => { ee.on('x', once(r)); setTimeout(r, 5); });",
  // the same uses inside a function that is given away
  "await new Promise(r => { ee.on('x', () => { use(r); }); setTimeout(r, 5); });",
  "await new Promise(r => { const u = () => { saved = r; }; ee.on('x', u); setTimeout(r, 5); });",
  "await new Promise(r => { handlers.x = () => r; setTimeout(r, 5); });",
  // not a promise executor, or a plain timer
  "const t = setTimeout(() => {}, 5); clearTimeout(t);",
  "await new Promise(r => { r(1); });",
];

describe('local/no-sleep-promise and the timers/promises ban', () => {
  it.each(SLEEPS)('flags the sleep: %s', async code => {
    expect(await banned(code)).toContain('local/no-sleep-promise');
  });
  it.each(IMPORTS)('flags the import: %s', async code => {
    expect((await banned(code)).length).toBeGreaterThan(0);
  });
  it('flags a static timers/promises import', async () => {
    const [res] = await eslint.lintText("import { setTimeout as sleep } from 'node:timers/promises';\nvoid sleep;\n", { filePath: path.join(REPO, 'tests/snippet.test.ts') });
    expect(res.messages.map(m => m.ruleId)).toContain('no-restricted-imports');
  });
  it.each(ALLOWED)('allows: %s', async code => {
    expect(await banned(code)).toEqual([]);
  });
});
