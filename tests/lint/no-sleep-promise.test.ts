import { describe, it, expect } from 'vitest';
import { ESLint } from 'eslint';
import path from 'path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const eslint = new ESLint({ cwd: REPO });

// Lints the snippet as a test file with the repo's real config and returns the
// ids of the sleep-ban rules that fired.
async function bannedFile(source: string): Promise<string[]> {
  const [res] = await eslint.lintText(source, { filePath: path.join(REPO, 'tests/snippet.test.ts') });
  const ids = ['local/no-sleep-promise', 'no-restricted-syntax', 'no-restricted-imports'];
  return res.messages.filter(m => m.ruleId && ids.includes(m.ruleId)).map(m => m.ruleId!);
}
const banned = (code: string) => bannedFile(`async function t() {\n${code}\n}\nvoid t;\n`);

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
  // the resolver rides along as a later timer argument
  'await new Promise(r => { setTimeout((x) => x(), 5, r); });',
  'await new Promise(r => { setTimeout(go, 5, r); });',
  'await new Promise(r => { globalThis.setTimeout(go, 5, r); });',
  'await new Promise(r => { setInterval(go, 5, 1, r); });',
  'await new Promise(r => { const a = r; setTimeout(go, 5, a); });',
  // .call and .apply run the resolver, like r()
  'await new Promise(r => { setTimeout(() => r.call(null), 5); });',
  'await new Promise(r => { setTimeout(() => { r.call(null, 1); }, 5); });',
  'await new Promise(r => { setTimeout(() => { r.apply(null, []); }, 5); });',
  'await new Promise(r => { setTimeout(() => { r.apply(null, [1]); }, 5); });',
  'await new Promise(r => { const f = () => r.call(null); setTimeout(f, 5); });',
  // a comma expression is the last operand
  'await new Promise(r => { setTimeout((0, r), 5); });',
  // a named executor is followed like an inline one
  'function exec(r) { setTimeout(r, 5); } await new Promise(exec);',
  'function exec(resolve, _reject) { setTimeout(() => resolve(1), 5); } await new Promise(exec);',
  'const exec = (r) => { setTimeout(r, 5); }; await new Promise(exec);',
  'const exec = function (r) { setTimeout(r, 5); }; await new Promise(exec);',
  'function exec(r) { function later() { r(); } setTimeout(later, 5); } await new Promise(exec);',
  'await new Promise(function exec(r) { setTimeout(r, 5); });',
  // a defaulted resolver parameter is still the resolver
  'await new Promise((r = noop) => { setTimeout(r, 5); });',
  'await new Promise(function (resolve = noop, _j) { setTimeout(() => resolve(1), 5); });',
  'function exec(r = noop) { setTimeout(r, 5); } await new Promise(exec);',
  // a spread timer argument still carries the resolver
  'await new Promise(r => { setTimeout(go, 5, ...[r]); });',
  'await new Promise(r => { const args = [r]; setTimeout(go, 5, ...args); });',
  'await new Promise(r => { setTimeout(go, 5, ...[1, r]); });',
  // an alias of the timer is the timer
  'const t = setTimeout; await new Promise(r => { t(r, 5); });',
  'const t = setTimeout; await new Promise(r => t(() => r(), 5));',
  'const t = globalThis.setTimeout; await new Promise(r => t(r, 5));',
  'const a = setTimeout; const b = a; await new Promise(r => b(r, 5));',
  'const s = setInterval; await new Promise(r => s(r, 5));',
  'const { setTimeout: st } = globalThis; await new Promise(r => st(r, 5));',
  'const { setInterval: si, setTimeout: st } = window; await new Promise(r => si(r, 5)); void st;',
  'const { setTimeout: st = fallback } = globalThis; await new Promise(r => st(r, 5));',
  'const t = setTimeout; const { resolve } = Promise.withResolvers(); t(resolve, 5);',
  // Promise.withResolvers has no executor, the resolver is a destructured name or w.resolve
  'const { promise, resolve } = Promise.withResolvers<void>(); setTimeout(resolve, 5); await promise;',
  'const { resolve } = Promise.withResolvers(); setTimeout(() => resolve(), 5);',
  'const { resolve: done } = Promise.withResolvers(); setTimeout(done, 5);',
  'const { promise, reject, resolve } = Promise.withResolvers(); setTimeout(() => resolve(1), 5); void reject; void promise;',
  'const w = Promise.withResolvers(); setTimeout(w.resolve, 5); await w.promise;',
  'const w = Promise.withResolvers(); setTimeout(() => w.resolve(), 5);',
  'const w = Promise.withResolvers(); setTimeout(w["resolve"], 5);',
  'const w = Promise.withResolvers(); setTimeout(() => { w.resolve(); }, 5); void w.reject;',
  'const P = Promise; const { resolve } = P.withResolvers(); setInterval(resolve, 5);',
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
  // the timers module hands out the same sleep as timers.promises
  "await import('node:timers');",
  "await import('timers');",
  "const { promises } = require('node:timers'); void promises;",
  "const timers = require('timers'); void timers;",
  "const timers = process.getBuiltinModule('node:timers'); void timers;",
  "const timers = process.getBuiltinModule('timers/promises'); void timers;",
];

const STATIC_IMPORTS = [
  "import timers from 'node:timers';\nvoid timers;\n",
  "import timers from 'timers';\nvoid timers;\n",
  "import * as timers from 'node:timers';\nvoid timers;\n",
  "import { promises } from 'timers';\nvoid promises;\n",
  "import { promises as p } from 'node:timers';\nvoid p;\n",
  "import { setTimeout as sleep } from 'node:timers/promises';\nvoid sleep;\n",
  "import * as tp from 'timers/promises';\nvoid tp;\n",
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
  // extra timer arguments that are not the resolver
  "await new Promise(r => { setTimeout(log, 5, 'x'); r(1); });",
  "await new Promise((r, j) => { setTimeout((e) => j(e), 5000, new Error('deadline')); void r; });",
  "await new Promise(r => { ee.on('x', r); setTimeout((x) => x(), 5, r); });",
  "await new Promise(r => { ee.on('x', r); setTimeout(go, 5, r); });",
  // .call and .apply with the resolver given away elsewhere
  "await new Promise(r => { ee.on('x', r); setTimeout(() => r.call(null), 5); });",
  "await new Promise(r => { ee.on('x', () => { r.apply(null, []); }); setTimeout(() => r.call(null), 5); });",
  "await new Promise(r => { const h = () => r.call(null); ee.on('x', h); setTimeout(r, 5); });",
  // a comma expression whose last operand is not the resolver
  "await new Promise(r => { setTimeout((r, 0), 5); void r; });",
  "await new Promise(r => { ee.on('x', (0, r)); setTimeout((0, r), 5); });",
  // named executors: resolver given away, or no timer
  "function exec(r) { ee.on('x', r); setTimeout(r, 5); } await new Promise(exec);",
  "function exec(r) { r(1); } await new Promise(exec);",
  "const exec = (r) => { handlers.push(r); setTimeout(() => r(), 5); }; await new Promise(exec);",
  "await new Promise(unknownExecutor);",
  // defaulted resolver parameter, handed off
  "await new Promise((r = noop) => { ee.on('x', r); setTimeout(r, 5); });",
  "await new Promise((r = noop) => { setTimeout(() => { throw new Error('d'); }, 5); r(1); });",
  // not a plain parameter: no single resolver name to follow
  "await new Promise(({ a }) => { setTimeout(a, 5); });",
  "await new Promise((...args) => { setTimeout(args[0], 5); });",
  // spread arguments that are not the resolver, or a handed-off resolver
  "await new Promise(r => { setTimeout(go, 5, ...[1, 2]); r(1); });",
  "await new Promise(r => { setTimeout(go, 5, ...rest); r(1); });",
  "await new Promise(r => { ee.on('x', r); setTimeout(go, 5, ...[r]); });",
  // aliases that are not the timer, or whose resolver is handed off
  "const t = setTimeout; await new Promise(r => { ee.on('x', r); t(r, 5); });",
  "const t = foo; await new Promise(r => { t(r, 5); });",
  // a binding that can be reassigned is not known to be the timer
  "let t = setTimeout; t = fake; await new Promise(r => { t(r, 5); });",
  "const t = obj.setTimeout; await new Promise(r => { t(r, 5); });",
  "const { setTimeout: st } = obj; await new Promise(r => st(r, 5));",
  "const { other: st } = globalThis; await new Promise(r => st(r, 5));",
  "const st = other(setTimeout); await new Promise(r => st(r, 5));",
  "const t = setTimeout; await new Promise(r => { t(() => { throw new Error('d'); }, 5); r(1); });",
  // withResolvers: the resolver also handed off, or only reject on the timer
  "const { resolve } = Promise.withResolvers(); ee.on('x', resolve); setTimeout(resolve, 5);",
  "const { resolve } = Promise.withResolvers(); ee.on('x', () => resolve()); setTimeout(() => resolve(2), 5);",
  "const { promise, reject } = Promise.withResolvers(); setTimeout(() => reject(new Error('deadline')), 5000); await promise;",
  "const w = Promise.withResolvers(); pending.push(w); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); ee.on('x', w.resolve); setTimeout(() => w.resolve(), 5);",
  "const w = Promise.withResolvers(); setTimeout(() => w.reject(new Error('deadline')), 5000); ee.on('x', () => w.resolve());",
  "const w = Promise.withResolvers(); setTimeout(w.reject, 5000); w.resolve(1);",
  "const { resolve } = Promise.withResolvers(); resolve(1);",
  "Promise.withResolvers();",
  // not a promise executor, or a plain timer
  "const t = setTimeout(() => {}, 5); clearTimeout(t);",
  "await new Promise(r => { r(1); });",
];

// every spelling of the module against every way to load it
const MODULE_FORMS = [
  (m: string) => `await import('${m}');`,
  (m: string) => `const x = require('${m}'); void x;`,
  (m: string) => `const x = process.getBuiltinModule('${m}'); void x;`,
  (m: string) => `await import(\`${m}\`);`,
  (m: string) => `const x = require(\`${m}\`); void x;`,
  (m: string) => `const x = process['getBuiltinModule']('${m}'); void x;`,
  (m: string) => `const x = process["getBuiltinModule"](\`${m}\`); void x;`,
];
const MODULE_NAMES = ['timers', 'node:timers', 'timers/promises', 'node:timers/promises'];

describe('local/no-sleep-promise and the timers/promises ban', () => {
  it.each(MODULE_NAMES.flatMap(m => MODULE_FORMS.map(f => f(m))))('bans the module in every form: %s', async code => {
    expect((await banned(code)).length).toBeGreaterThan(0);
  });
  it.each(MODULE_NAMES)('bans the static import of %s', async m => {
    expect(await bannedFile(`import x from '${m}';\nvoid x;\n`)).toContain('no-restricted-imports');
  });
  it('lets an unrelated module through', async () => {
    expect(await banned("await import('node:path'); require('timersx'); require('xtimers');")).toEqual([]);
  });
  it.each(SLEEPS)('flags the sleep: %s', async code => {
    expect(await banned(code)).toContain('local/no-sleep-promise');
  });
  it.each(IMPORTS)('flags the import: %s', async code => {
    expect((await banned(code)).length).toBeGreaterThan(0);
  });
  it.each(STATIC_IMPORTS)('flags the static import: %s', async code => {
    expect(await bannedFile(code)).toContain('no-restricted-imports');
  });
  it.each(ALLOWED)('allows: %s', async code => {
    expect(await banned(code)).toEqual([]);
  });
});
