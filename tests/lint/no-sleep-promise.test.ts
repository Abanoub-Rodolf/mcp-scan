// Gaps the rule still has are listed in the 'Known gaps' comment above noSleepPromise in eslint.config.js.
// A shape is either in a table below or in that comment, never both.
import { describe, it, expect } from 'vitest';
import { ESLint } from 'eslint';
import path from 'path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { SPEC_CASES_ALLOWED, SPEC_CASES_BANNED } from './spec-cases';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const eslint = new ESLint({ cwd: REPO });

// Lints the snippet as a test file with the repo's real config and returns the
// ids of the sleep-ban rules that fired.
async function bannedFile(source: string): Promise<string[]> {
  const [res] = await eslint.lintText(source, { filePath: path.join(REPO, 'tests/snippet.test.ts') });
  // a snippet that does not parse reports nothing, so an allowed row would pass for the wrong reason
  expect(res.messages.filter(m => m.fatal), 'parse').toEqual([]);
  const ids = ['local/no-sleep-promise', 'local/no-fixed-wait', 'no-restricted-syntax', 'no-restricted-imports'];
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
  // the race fallback needs a real handoff: a subscription, or a container something else calls
  'await new Promise(r => { expect(r).toBeDefined(); setTimeout(r, 50); });',
  'await new Promise(r => { void String(r); setTimeout(r, 50); });',
  'await new Promise(r => { Object.freeze(r); setTimeout(r, 50); });',
  'await new Promise(r => { vi.fn()(r); setTimeout(r, 50); });',
  'await new Promise(r => { noop(r); setTimeout(r, 50); });',
  "await new Promise(r => { ee.off('x', r); setTimeout(r, 50); });",
  "await new Promise(r => { if (false) ee.on('x', r); setTimeout(r, 50); });",
  "await new Promise(r => { false && ee.on('x', r); setTimeout(r, 50); });",
  "await new Promise(r => { false ? ee.on('x', r) : 0; setTimeout(r, 50); });",
  'await new Promise(r => { setTimeout(r, 50); return r; });',
  'const fn = await new Promise(r => { setTimeout(r, 5); return r; });',
  // a store nobody calls, or only a timer calls
  'const sink: any[] = []; await new Promise(r => { sink.push(r); setTimeout(r, 50); });',
  'let saved: any; const p = new Promise(r => { saved = r; setTimeout(() => r(1), 5); }); void saved; await p;',
  "const handlers: any[] = []; const p = new Promise(r => { handlers.push(r); setTimeout(r, 5); }); setTimeout(() => handlers.forEach(f => f()), 5); await p;",
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
  // a direct .call is a call, not a handoff
  'await new Promise(r => { r.call(null); setTimeout(r, 5); });',
  'await new Promise(r => { r.apply(null, []); setTimeout(r, 5); });',
  // a comma expression is the last operand
  'await new Promise(r => { setTimeout((0, r), 5); });',
  // a named executor is followed like an inline one
  'function exec(r) { setTimeout(r, 5); } await new Promise(exec);',
  'function exec(resolve, _reject) { setTimeout(() => resolve(1), 5); } await new Promise(exec);',
  'const exec = (r) => { setTimeout(r, 5); }; await new Promise(exec);',
  'const exec = function (r) { setTimeout(r, 5); }; await new Promise(exec);',
  'function exec(r) { function later() { r(); } setTimeout(later, 5); } await new Promise(exec);',
  'await new Promise(function exec(r) { setTimeout(r, 5); });',
  // the executor is looked up through the outer scopes
  'function exec(r) { setTimeout(r, 5); } const go = () => new Promise(exec); await go();',
  'const exec = (r) => { setTimeout(r, 5); }; async function inner() { { await new Promise(exec); } } await inner();',
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
  'const { resolve = noop } = Promise.withResolvers(); setTimeout(resolve, 5);',
  'const { promise, reject, resolve } = Promise.withResolvers(); setTimeout(() => resolve(1), 5); void reject; void promise;',
  'const w = Promise.withResolvers(); setTimeout(w.resolve, 5); await w.promise;',
  'const w = Promise.withResolvers(); setTimeout(() => w.resolve(), 5);',
  'const w = Promise.withResolvers(); setTimeout(w["resolve"], 5);',
  'const w = Promise.withResolvers(); setTimeout(w[`resolve`], 5);',
  // optional chaining to resolve is still a read of resolve
  'const w = Promise.withResolvers(); setTimeout(w?.resolve, 5);',
  'const w = Promise.withResolvers(); setTimeout(() => w?.resolve(), 5);',
  'const w = Promise.withResolvers(); setTimeout(() => w.resolve?.(), 5);',
  // a destructure of w follows the variable bound to resolve; promise and reject are not it
  'const w = Promise.withResolvers(); const { promise } = w; setTimeout(w.resolve, 5); await promise;',
  'const w = Promise.withResolvers(); const { reject } = w; setTimeout(w.resolve, 5); void reject;',
  'const w = Promise.withResolvers(); const { promise, reject } = w; setTimeout(w.resolve, 5); void reject; await promise;',
  'const w = Promise.withResolvers(); const { resolve } = w; setTimeout(resolve, 5);',
  'const w = Promise.withResolvers(); const { resolve: done } = w; setTimeout(done, 5);',
  'const w = Promise.withResolvers(); const { resolve = noop } = w; setTimeout(resolve, 5);',
  "const w = Promise.withResolvers(); const { 'resolve': done } = w; setTimeout(done, 5);",
  'const w = Promise.withResolvers(); const { promise, resolve } = w; setTimeout(() => resolve(), 5); await promise;',
  // an alias of w is w, and an alias of w.resolve is the resolver
  'const w = Promise.withResolvers(); const v = w; setTimeout(v.resolve, 5);',
  'const w = Promise.withResolvers(); const { resolve } = w; const f = resolve.bind(null); setTimeout(f, 5);',
  'const w = Promise.withResolvers(); const f = w.resolve; setTimeout(f.bind(null), 5);',
  // a wrapped read of w is still w
  'const w = Promise.withResolvers(); const { resolve } = w as any; setTimeout(resolve, 5);',
  'const w = Promise.withResolvers(); const { resolve } = w!; setTimeout(resolve, 5);',
  'const w = Promise.withResolvers(); const { resolve } = (0, w); setTimeout(resolve, 5);',
  'const w = Promise.withResolvers(); setTimeout((w as any).resolve, 5);',
  'const w = Promise.withResolvers(); setTimeout(w!.resolve, 5);',
  'const w = Promise.withResolvers(); const v = w satisfies object; setTimeout(v.resolve, 5);',
  'const w = Promise.withResolvers(); const v = (0, w); setTimeout(v.resolve, 5);',
  // the test of a conditional only reads w
  'const w = Promise.withResolvers(); const x = w ? 1 : 2; setTimeout(w.resolve, 5); void x;',
  // an alias made by assignment is w
  'const w = Promise.withResolvers(); let v; v = w; setTimeout(v.resolve, 5);',
  // a function copied out of w is a function, not the object
  'const w = Promise.withResolvers(); const { resolve } = w; const f = resolve; f.length; setTimeout(f, 5);',
  // a cycle of aliases must not recurse forever
  'await new Promise(r => { let a = r; let b = a; a = b; setTimeout(a, 5); });',
  'const w = Promise.withResolvers(); setTimeout(() => { w.resolve(); }, 5); void w.reject;',
  'const P = Promise; const { resolve } = P.withResolvers(); setInterval(resolve, 5);',
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
  "await new Promise(resolve => { const t = setTimeout(() => resolve('none'), 5); ee.on('x', resolve); clearTimeout(t); });",
  "await new Promise(r => { server.on('x', r); setTimeout(r, 5000); });",
  "await new Promise(r => { server.on('x', () => r(1)); setTimeout(() => r(2), 5000); });",
  "let saved: any; const p = new Promise(r => { saved = r; setTimeout(() => r(1), 5); }); ee.on('x', () => saved(2)); await p;",
  "await new Promise(r => { const keep = r; ee.on('x', keep); setTimeout(r, 5); });",
  "const handlers: any[] = []; const p = new Promise(r => { handlers.push(r); setTimeout(r, 5); }); ee.on('x', () => handlers.forEach(f => f())); await p;",
  // .bind is the resolver
  "await new Promise(r => { ee.once('x', r.bind(null)); setTimeout(r, 5); });",
  "await new Promise(r => { setTimeout(() => r(), 5); ee.once('x', r.bind(null, 1)); });",
  // a listener that calls it, given away
  "await new Promise(r => { ee.once('x', () => { r(); }); setTimeout(() => r(), 5); });",
  "const handlers: any = {}; const p = new Promise(r => { handlers.x = () => r(); setTimeout(r, 5); }); ee.on('y', () => handlers.x()); await p;",
  // aliases that are given away
  "await new Promise(r => { const a = r; ee.on('x', a); setTimeout(r, 5); });",
  "await new Promise(r => { const a = r.bind(null); ee.once('x', a); setTimeout(a, 5); });",
  "const handlers: any[] = []; const p = new Promise(r => { const a = r; const b = a; handlers.push(b); setTimeout(r, 5); }); ee.on('x', () => handlers[0]()); await p;",
  "await new Promise(r => { let f; f = r; ee.on('x', f); setTimeout(r, 5); });",
  // the resolver sits in an object that is given
  "const pending = new Map(); const p = new Promise(r => { const t = setTimeout(() => r(), 5); pending.set(1, { resolve: r, timer: t }); }); ee.on('x', () => pending.get(1).resolve()); await p;",
  "const pending = new Map(); const p = new Promise(r => { const rec = { resolve: r }; pending.set(1, rec); setTimeout(r, 5); }); ee.on('x', () => pending.get(1).resolve()); await p;",
  "const handlers: any[] = []; const p = new Promise(r => { handlers.push([r]); setTimeout(r, 5); }); ee.on('x', () => handlers[0][0]()); await p;",
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
  "const handlers: any = {}; const p = new Promise(r => { handlers.x = () => r; setTimeout(r, 5); }); ee.on('y', () => handlers.x()); await p;",
  // extra timer arguments that are not the resolver
  "await new Promise(r => { setTimeout(log, 5, 'x'); r(1); });",
  "await new Promise((r, j) => { setTimeout((e) => j(e), 5000, new Error('deadline')); void r; });",
  "await new Promise(r => { ee.on('x', r); setTimeout((x) => x(), 5, r); });",
  "await new Promise(r => { ee.on('x', r); setTimeout(go, 5, r); });",
  // .call and .apply with the resolver given away elsewhere
  "await new Promise(r => { ee.on('x', r); setTimeout(() => r.call(null), 5); });",
  "await new Promise(r => { ee.on('x', () => { r.apply(null, []); }); setTimeout(() => r.call(null), 5); });",
  "await new Promise(r => { const h = () => r.call(null); ee.on('x', h); setTimeout(r, 5); });",
  // the resolver as the delay is not a callback or a later argument
  "await new Promise(r => { setTimeout(go, r); });",
  "await new Promise(r => { setInterval(go, r); r(1); });",
  // a comma expression whose last operand is not the resolver
  "await new Promise(r => { setTimeout((r, 0), 5); void r; });",
  "await new Promise(r => { ee.on('x', (0, r)); setTimeout((0, r), 5); });",
  // named executors: resolver given away, or no timer
  "function exec(r) { ee.on('x', r); setTimeout(r, 5); } await new Promise(exec);",
  "function exec(r) { r(1); } await new Promise(exec);",
  "const handlers: any[] = []; const exec = (r) => { handlers.push(r); setTimeout(() => r(), 5); }; const p = new Promise(exec); ee.on('x', () => handlers.forEach(f => f())); await p;",
  "await new Promise(unknownExecutor);",
  // two declarations of one name: which one runs is not knowable, so no verdict
  "function exec(r) { setTimeout(r, 5); } function exec(r) { r(); } await new Promise(exec);",
  // an inner executor shadows a sleeping outer one
  "function exec(r) { setTimeout(r, 5); } { function exec(r) { r(); } await new Promise(exec); }",
  "const exec = (r) => { setTimeout(r, 5); }; const go = (exec) => new Promise(exec); void go;",
  "function exec(r) { setTimeout(r, 5); } function wrap() { const exec = (r) => { r(1); }; return new Promise(exec); } void wrap;",
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
  // a cycle of aliases never reaches a timer, and must not recurse forever
  "const a = b; const b = a; await new Promise(r => { a(r, 5); });",
  "const a = a; await new Promise(r => { a(r, 5); });",
  // a computed key names the value of setTimeout, not the property
  "await new Promise(r => { globalThis[setTimeout](r, 5); });",
  "const { setTimeout: st } = obj; await new Promise(r => st(r, 5));",
  "const { other: st } = globalThis; await new Promise(r => st(r, 5));",
  "const st = other(setTimeout); await new Promise(r => st(r, 5));",
  // a rest element has no value: the pattern walk must skip it, not crash
  "const { ...rest } = globalThis; await new Promise(r => rest(r, 5));",
  "const { a, ...rest } = globalThis; await new Promise(r => rest(r, 5)); void a;",
  "const t = setTimeout; await new Promise(r => { t(() => { throw new Error('d'); }, 5); r(1); });",
  // withResolvers: the resolver also handed off, or only reject on the timer
  "const { resolve } = Promise.withResolvers(); ee.on('x', resolve); setTimeout(resolve, 5);",
  "const { resolve } = Promise.withResolvers(); ee.on('x', () => resolve()); setTimeout(() => resolve(2), 5);",
  "const { promise, reject } = Promise.withResolvers(); setTimeout(() => reject(new Error('deadline')), 5000); await promise;",
  "const pending: any[] = []; const w = Promise.withResolvers(); pending.push(w); setTimeout(w.resolve, 5); ee.on('x', () => pending[0].resolve());",
  "const w = Promise.withResolvers(); ee.on('x', w.resolve); setTimeout(() => w.resolve(), 5);",
  "const w = Promise.withResolvers(); setTimeout(() => w.reject(new Error('deadline')), 5000); ee.on('x', () => w.resolve());",
  "const w = Promise.withResolvers(); setTimeout(w.reject, 5000); w.resolve(1);",
  // any other read of the object hands the resolver off
  "const w = Promise.withResolvers(); const { resolve } = w; ee.on('x', resolve); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); const { ...rest } = w; setTimeout(w.resolve, 5); void rest;",
  "const w = Promise.withResolvers(); const { [k]: x } = w; setTimeout(w.resolve, 5); void x;",
  "const w = Promise.withResolvers(); const { resolve: { a } } = w; setTimeout(w.resolve, 5); void a;",
  "const w = Promise.withResolvers(); const [x] = w; setTimeout(w.resolve, 5); void x;",
  "const w = Promise.withResolvers(); const [x] = w as any; setTimeout(w.resolve, 5); void x;",
  "const w = Promise.withResolvers(); const { resolve: f } = w; ee.on('x', f.bind(null)); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); ee.on('x', w[`resolve`]); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); ee.on('x', w?.resolve); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); ee.on('x', w[k]); setTimeout(w.resolve, 5);",
  // a wrapped or contained alias of w that is given away
  "const w = Promise.withResolvers(); const v = w as any; ee.on('x', v.resolve); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); const v = w!; ee.on('x', v.resolve); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); const v = w satisfies object; ee.on('x', v.resolve); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); const v = (0, w); ee.on('x', v.resolve); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); const v = cond ? w : o; ee.on('x', v.resolve); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); const v = cond ? o : w; ee.on('x', v.resolve); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); const v = w || o; ee.on('x', v.resolve); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); const v = o && w; ee.on('x', v.resolve); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); const o = { w }; ee.on('x', o.w.resolve); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); const o = { k: w }; ee.on('x', o.k.resolve); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); const o = { ...w }; ee.on('x', o.resolve); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); const a = [w]; ee.on('x', a[0].resolve); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); const { resolve } = w as any; ee.on('x', resolve); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); ee.on('x', (w as any).resolve); setTimeout(w.resolve, 5);",
  // an alias made by assignment, given away
  "const w = Promise.withResolvers(); let v; v = w; ee.on('x', v); setTimeout(w.resolve, 5);",
  "const w = Promise.withResolvers(); ee.on('x', w.other); setTimeout(w.resolve, 5);",
  "const { resolve } = Promise.withResolvers(); resolve(1);",
  "Promise.withResolvers();",
  // not a promise executor, or a plain timer
  "const t = setTimeout(() => {}, 5); clearTimeout(t);",
  "await new Promise(r => { r(1); });",
];

// Third round: nine classes of bypass found by cold reviews of the sibling rules in
// two other repos. Keyed by class so a failing case names its class (c1 .. c9).
const BYPASS_BANNED: Record<string, string[]> = {
  // setInterval is a timer wherever setTimeout is
  c1: [
    'const s = promisify(setInterval); void s;',
    'const s = util.promisify(setInterval); void s;',
    'const t = setInterval; const s = promisify(t); void s;',
    'const s = promisify(globalThis.setTimeout); void s;',
    'const s = promisify(setInterval as any); void s;',
    'const si = setInterval; await new Promise(r => si(r, 5));',
    'await new Promise(r => globalThis.setInterval(r, 5));',
  ],
  // .call, .apply, .bind and the comma form run the same timer
  c2: [
    'await new Promise(r => setTimeout.call(null, r, 50));',
    'await new Promise(r => setTimeout.apply(null, [r, 50]));',
    'await new Promise(r => setTimeout.bind(null)(r, 50));',
    'await new Promise(r => setTimeout.bind(null, r, 50)());',
    'await new Promise(r => (0, setTimeout)(r, 50));',
    'await new Promise(r => (0, globalThis.setTimeout)(r, 50));',
    'await new Promise(r => globalThis.setTimeout.call(globalThis, () => r(), 50));',
    'await new Promise(r => setInterval.call(null, r, 50));',
    'await new Promise(r => { const args = [r, 50]; setTimeout.apply(null, args); });',
    'await new Promise(r => { const t = setTimeout.bind(null); t(r, 50); });',
    'await new Promise(r => (setTimeout as any)(r, 50));',
    'await new Promise(r => (globalThis as any).setTimeout(r, 50));',
    "await new Promise(r => globalThis['setTimeout'](r, 50));",
    'await new Promise(r => globalThis?.setTimeout(r, 50));',
  ],
  // the timers module in the forms the first rounds did not cover
  c3: [
    "const t = module.require('timers'); void t;",
    "const t = createRequire(import.meta.url)('node:timers/promises'); void t;",
    "const t = await import('node:timers/promises').then(m => m.scheduler.wait(5)); void t;",
  ],
  // the constructor reached some other way
  c4: [
    'const P = Promise; await new P(r => setTimeout(r, 50));',
    'await new globalThis.Promise(r => setTimeout(r, 50));',
    'await new (Promise as any)(r => setTimeout(r, 50));',
    'class P extends Promise<void> {} await new P(r => setTimeout(r, 50));',
    'class S extends Promise<void> { constructor() { super(r => setTimeout(r, 50)); } } await new S();',
    'class S extends Promise<void> { constructor(ms: number) { super((r) => { setTimeout(r, ms); }); } } await new S(5);',
    'await Reflect.construct(Promise, [(r: any) => setTimeout(r, 50)]);',
    'const P = globalThis.Promise; const { resolve } = P.withResolvers(); setTimeout(resolve, 50);',
    'const { resolve } = (Promise as any).withResolvers(); setTimeout(resolve, 5);',
    "const w = Promise['withResolvers'](); setTimeout(w.resolve, 5);",
    'const w = globalThis.Promise.withResolvers(); setTimeout(w.resolve, 5);',
  ],
  // the resolver goes to a helper declared in this file, and the helper owns the timer
  c5: [
    'const after = (f: () => void) => setTimeout(f, 50); await new Promise((r) => after(r));',
    'function after(f: () => void) { setTimeout(f, 50); } await new Promise((r) => { after(r); });',
    'const after = (f: () => void, ms: number) => { setTimeout(() => f(), ms); }; await new Promise((r) => after(r, 50));',
    'const after = (f: () => void) => setTimeout(f, 50); const again = (g: () => void) => after(g); await new Promise((r) => again(r));',
    'const after = (f: () => void) => { const g = f; setInterval(g, 50); }; await new Promise((r) => after(r));',
    'const after = (ms: number, f: () => void) => setTimeout(f, ms); await new Promise((r) => after(50, r));',
    'const after = (f: () => void) => setTimeout(f, 50); const { resolve } = Promise.withResolvers(); after(resolve);',
    'const after = (f: () => void) => setTimeout(f, 50); await new Promise((r) => { const ok = r; after(ok); });',
    // a helper that only hands the resolver back still wraps it for the timer
    'const same = (f: () => void) => f; await new Promise((r) => setTimeout(same(r), 50));',
    'await new Promise((r) => ((f: () => void) => setTimeout(f, 50))(r));',
  ],
  // the resolver aliased, reject only named, resolve defaulted
  c6: [
    'await new Promise((res, rej) => { const ok = res; setTimeout(() => ok(), 50); void rej; });',
    'await new Promise((res = undefined, rej) => { setTimeout(res, 50); void rej; });',
    'await new Promise((res, rej) => { const ok = res; setTimeout(ok, 50); void rej; });',
    'await new Promise((res, rej) => { let ok; ok = res; setTimeout(() => ok(), 50); void rej; });',
    'await new Promise((res, rej) => { const ok = res as () => void; setTimeout(() => ok(), 50); void rej; });',
    "await new Promise((res, rej) => { const ok = res; setTimeout(() => { rej(new Error('x')); ok(); }, 50); });",
    'await new Promise((res = undefined, rej = undefined) => { setTimeout(() => res(), 50); void rej; });',
  ],
  // the timer reached through destructuring, quoted or computed keys, objects, arrays, defaults
  c7: [
    'const { setTimeout } = globalThis; await new Promise(r => setTimeout(r, 50));',
    "const { 'setTimeout': wait } = globalThis; await new Promise(r => wait(r, 50));",
    "const { ['setInterval']: wait } = globalThis; await new Promise(r => wait(r, 50));",
    'const { setTimeout: wait } = self; await new Promise(r => wait(r, 50));',
    'const { window: { setTimeout: wait } } = globalThis; await new Promise(r => wait(r, 50));',
    'const { window: { self: { setInterval: wait } } } = global; await new Promise(r => wait(r, 50));',
    'const { window: w } = globalThis; await new Promise(r => w.setTimeout(r, 50));',
    'await new Promise(r => globalThis.globalThis.setTimeout(r, 50));',
    'await new Promise(r => window.self.setTimeout(r, 50));',
    'const { setTimeout: wait } = globalThis as any; await new Promise(r => wait(r, 50));',
    'const { setInterval: wait } = global; await new Promise(r => wait(r, 50));',
    'const o = { wait: setTimeout }; await new Promise(r => o.wait(r, 50));',
    'const { wait } = { wait: setTimeout }; await new Promise(r => wait(r, 50));',
    'const [w] = [setTimeout]; await new Promise(r => w(r, 50));',
    'const arr = [setTimeout]; await new Promise(r => arr[0](r, 50));',
    'const f = (w = setTimeout) => new Promise(r => w(r, 50)); void f;',
    'function f(w = setTimeout) { return new Promise(r => w(r, 50)); } void f;',
    'const f = ({ wait = setTimeout }) => new Promise(r => wait(r, 50)); void f;',
    'const { wait = setTimeout } = opts; await new Promise(r => wait(r, 50));',
    'const w = opts.timer ?? setTimeout; await new Promise(r => w(r, 50));',
    'const w = cond ? setTimeout : fake; await new Promise(r => w(r, 50));',
    'const g = globalThis; await new Promise(r => g.setTimeout(r, 50));',
    // two branches read one object under two keys: the second read is no cycle
    'const o = { a: fake, b: setTimeout }; const w = o.a ?? o.b; await new Promise(r => w(r, 50));',
    'const o = { a: fake, b: setTimeout }; const w = cond ? o.a : o.b; await new Promise(r => w(r, 50));',
    'const o = { a: fake, b: setTimeout }; const w = o.a || o.b || o.a; await new Promise(r => w(r, 50));',
  ],
  // withResolvers assigned later, and resolvers stored for a timer elsewhere
  c8: [
    'let d; d = Promise.withResolvers(); setTimeout(() => d.resolve(), 50); await d.promise;',
    'let d: any; d = Promise.withResolvers<void>(); setTimeout(d.resolve, 50);',
    'let resolve; ({ resolve } = Promise.withResolvers()); setTimeout(resolve, 50);',
    'let d; d = Promise.withResolvers(); setTimeout(() => (d).resolve(), 50);',
    'let d; d = Promise.withResolvers(); setTimeout(() => d?.resolve(), 50);',
    'let d; d = Promise.withResolvers(); setTimeout(() => d!.resolve(), 50);',
    'const rs: Array<() => void> = []; await new Promise(res => { rs[0] = res; setTimeout(() => rs.forEach(f => f()), 50); });',
    'const rs: Array<() => void> = []; const p = new Promise(res => { rs[0] = res; }); setTimeout(() => rs.forEach(f => f()), 50); await p;',
    'const rs: Array<() => void> = []; const p = new Promise(res => { rs.push(res); }); setTimeout(() => rs[0](), 50); await p;',
    'const pending = new Map(); const p = new Promise(res => { pending.set(1, res); }); setTimeout(() => pending.get(1)(), 50); await p;',
    'let saved: any; const p = new Promise(res => { saved = res; }); setTimeout(() => saved(), 50); await p;',
    'const rs: Array<() => void> = []; const w = Promise.withResolvers(); rs[0] = w.resolve; setTimeout(() => rs.forEach(f => f()), 50);',
    'const rs: Array<() => void> = []; const p = new Promise(res => { rs.push(res); }); setTimeout(rs.shift()!, 50); await p;',
    'const rs: Array<() => void> = []; const p = new Promise(res => { rs.push(res); }); function flush() { rs.forEach(f => f()); } setTimeout(flush, 50); await p;',
    'const rs: Array<() => void> = []; const p = new Promise(res => { rs.push(res); }); setTimeout(() => { for (const f of rs) f(); }, 50); await p;',
    'const d: any = {}; d.p = new Promise(res => { d.resolve = res; }); setTimeout(() => d.resolve(), 50);',
    'let d; d = Promise.withResolvers(); const { resolve } = d; setTimeout(resolve, 50);',
    // a stored { res, rej } is run through the key that holds the resolver
    'const pending = new Map(); const p = new Promise((res, rej) => { pending.set(1, { res, rej }); void rej; }); setTimeout(() => pending.get(1).res(), 50); await p;',
    'const pending = new Map(); const p = new Promise((res, rej) => { pending.set(1, { res, rej }); void rej; }); setTimeout(pending.get(1).res, 50); await p;',
    'const pending = new Map(); const p = new Promise((res, rej) => { pending.set(1, { res, rej }); void rej; }); setTimeout(() => pending.forEach((v: any) => v.res()), 50); await p;',
    'const pending = new Map(); const p = new Promise((res, rej) => { pending.set(1, { done: res, fail: rej }); void rej; }); setTimeout(() => pending.get(1).done(), 50); await p;',
    'const pending = new Map(); const d = Promise.withResolvers<void>(); pending.set(1, d); setTimeout(() => pending.get(1).resolve(), 50); await d.promise;',
    'const pending = new Map(); const d = Promise.withResolvers<void>(); pending.set(1, d); setTimeout(pending.get(1).resolve, 50); await d.promise;',
  ],
};

const BYPASS_ALLOWED: Record<string, string[]> = {
  c1: [
    'const s = promisify(fs.readFile); void s;',
    'const s = promisify(other.setTimeout); void s;',
  ],
  c2: [
    "await new Promise(r => { ee.on('x', r); setTimeout.call(null, r, 50); });",
    "await new Promise((r, j) => { setTimeout.call(null, () => j(new Error('deadline')), 5000); void r; });",
    'await new Promise((r, j) => { setTimeout.apply(null, [j, 5000]); void r; });',
    "await new Promise((r, j) => { (0, setTimeout)(() => j(new Error('d')), 5000); void r; });",
    'await new Promise(r => { setTimeout.call(null, go, r); r(1); });',
    'await new Promise(r => { setTimeout.bind(null)(go, r); r(1); });',
  ],
  c3: [
    "const t = foo.require('path'); void t;",
    "const t = createRequire(import.meta.url)('node:path'); void t;",
  ],
  c4: [
    "class S extends Promise<void> { constructor() { super((r, j) => { setTimeout(() => j(new Error('d')), 50); void r; }); } } void S;",
    "class S extends Promise<void> { constructor() { super((r) => { ee.on('x', r); setTimeout(r, 50); }); } } void S;",
  ],
  c5: [
    "const watch = (f: () => void) => { ee.on('x', f); setTimeout(f, 50); }; await new Promise((r) => watch(r));",
    "const fail = (f: () => void) => setTimeout(() => { throw new Error('d'); }, 50); await new Promise((r) => fail(r));",
    'const call = (f: () => void) => f(); await new Promise((r) => call(r));',
    'await new Promise((r) => importedHelper(r));',
    // mutual recursion between helpers must end
    'function a(f: () => void) { b(f); } function b(f: () => void) { a(f); } await new Promise((r) => a(r));',
    "const after = (f: () => void) => setTimeout(f, 50); await new Promise((r) => { ee.on('x', r); after(r); });",
    'const delay = (ms: number) => setTimeout(go, ms); await new Promise((r) => delay(r));',
  ],
  c6: [
    'await new Promise((res, rej) => { setTimeout(rej as never, 50); void res; });',
    'await new Promise((res, rej) => { const bad = rej; setTimeout(bad, 50); void res; });',
    "await new Promise((res, rej) => { const ok = res; ee.on('x', ok); setTimeout(() => rej(new Error('d')), 5000); });",
    'await new Promise((res = undefined, rej) => { setTimeout(rej, 50); void res; });',
  ],
  c7: [
    'const o = { wait: fake }; await new Promise(r => o.wait(r, 50));',
    'const f = (w = fake) => new Promise(r => w(r, 50)); void f;',
    "const o = { wait: setTimeout }; await new Promise(r => { ee.on('x', r); o.wait(r, 50); });",
    'const [w] = [fake, setTimeout]; await new Promise(r => w(r, 50));',
    "const { setTimeout: st } = globalThis; await new Promise((r, j) => { st(() => j(new Error('d')), 5000); void r; });",
    'const g = other; await new Promise(r => g.setTimeout(r, 50));',
    'const arr = [setTimeout]; await new Promise(r => arr[1](r, 50));',
  ],
  c8: [
    "let d; d = Promise.withResolvers(); ee.on('x', d.resolve); setTimeout(() => d.resolve(), 50);",
    "let d; d = Promise.withResolvers(); setTimeout(() => d.reject(new Error('d')), 5000); ee.on('x', () => d.resolve());",
    "const rs: Array<() => void> = []; const p = new Promise(res => { rs.push(res); }); ee.on('x', () => rs.forEach(f => f())); await p;",
    "const rs: Array<() => void> = []; const p = new Promise(res => { rs.push(res); }); setTimeout(() => console.log('tick'), 50); await p;",
    "const rs: Array<() => void> = []; const p = new Promise(res => { rs.push(res); }); setTimeout(() => { rs.length = 0; }, 50); await p;",
    "let saved: any; const p = new Promise(res => { saved = res; }); setTimeout(() => { throw new Error('d'); }, 50); void saved; await p;",
    // a stored { res, rej } or withResolvers object, and the timer rejects it: a deadline guard
    "const pending = new Map(); const p = new Promise((res, rej) => { pending.set(1, { res, rej }); }); setTimeout(() => pending.get(1).rej(new Error('timeout')), 5000); await p;",
    "const pending = new Map(); const p = new Promise((res, rej) => { pending.set(1, { res, rej }); }); setTimeout(pending.get(1).rej, 5000); await p;",
    "const pending = new Map(); const p = new Promise((res, rej) => { pending.set(1, { done: res, fail: rej }); }); setTimeout(() => pending.get(1).fail(new Error('timeout')), 5000); await p;",
    "const pending = new Map(); const d = Promise.withResolvers<void>(); pending.set(1, d); setTimeout(() => pending.get(1).reject(new Error('timeout')), 5000); ee.on('x', () => pending.get(1).resolve()); await d.promise;",
    "const pending = new Map(); const d = Promise.withResolvers<void>(); pending.set(1, d); setTimeout(() => void pending.get(1).promise, 5000); await d.promise;",
  ],
  // a property or a value that merely has the timer's name is not the timer
  c9: [
    'const ms = opts.setTimeout; expect(ms).toBe(5);',
    'const { setTimeout: ms } = opts; expect(ms).toBe(5);',
    'const o = { setTimeout: 5 }; expect(o.setTimeout).toBe(5);',
    'await new Promise((res, rej) => { setTimeout(rej as never, 50); res(1); });',
    'await new Promise((res, rej) => { setTimeout(rej as never, 50); void res; });',
    'const ms = cfg.setInterval; expect(ms).toBeGreaterThan(0);',
  ],
};

// waits that never build a promise are reported by their own rule, and the tables above see it too
BYPASS_BANNED.c10 = [
  'await page.waitForTimeout(500);',
  'const end = Date.now() + 500; while (Date.now() < end) {}',
];
BYPASS_ALLOWED.c10 = [
  "await page.waitForSelector('#x');",
  'const end = Date.now() + 500; while (Date.now() < end) { await check(); }',
];

// One row per name in the rule's own lists, so dropping a name from BENIGN, TAKES or INERT, or an
// alternative from the busy-loop test, fails here instead of passing quietly.
BYPASS_BANNED.c11 = [
  // TAKES: an element taken out of a container is the resolver
  'await new Promise(r => { const q = [r]; setTimeout(q.shift()!, 5); });',
  'await new Promise(r => { const q = [r]; setTimeout(q.pop()!, 5); });',
  'await new Promise(r => { const q = [r]; setTimeout(q.at(0)!, 5); });',
  // INERT: reading a member of the resolver that is not the resolver hands nothing off
  "await new Promise(r => { ee.on('x', r.length); setTimeout(r, 5); });",
  "await new Promise(r => { ee.on('x', r.name); setTimeout(r, 5); });",
  "await new Promise(r => { ee.on('x', r.toString); setTimeout(r, 5); });",
  "await new Promise(r => { ee.on('x', r.call); setTimeout(r, 5); });",
  "await new Promise(r => { ee.on('x', r.apply); setTimeout(r, 5); });",
  "await new Promise(r => { ee.on('x', r.bind); setTimeout(r, 5); });",
  // the second argument of a script runner is the script
  "await page.$eval('#x', '(el) => new Promise((r) => setTimeout(r, 5))');",
  // an optional call to withResolvers is still withResolvers
  'const d = Promise.withResolvers?.(); setTimeout(d.resolve, 50); await d.promise;',
];
BYPASS_ALLOWED.c11 = [
  // BENIGN: a timer that empties or asks about the container does not run what is in it
  'const rs = new Set<() => void>(); const p = new Promise<void>(res => { rs.add(res); }); setTimeout(() => { rs.clear(); }, 50); await p;',
  'const rs = new Map(); const p = new Promise(res => { rs.set(1, res); }); setTimeout(() => { rs.delete(1); }, 50); await p;',
  'const rs = new Map(); const p = new Promise(res => { rs.set(1, res); }); setTimeout(() => { if (rs.has(1)) log(); }, 50); await p;',
  // a loop whose body awaits, yields, calls or builds something is a poll, whichever one it is
  'const end = Date.now() + 500; while (Date.now() < end) { await pending; }',
  'const end = Date.now() + 500; function* g() { while (Date.now() < end) { yield 1; } } void g;',
  'const end = Date.now() + 500; while (Date.now() < end) { check(); }',
  'const end = Date.now() + 500; while (Date.now() < end) { new Foo(); }',
  'const end = Date.now() + 500; while (Date.now() < end) { tag`x`; }',
  "const end = Date.now() + 500; while (Date.now() < end) { import('x'); }",
  // the update clause runs on every pass too
  'const end = Date.now() + 500; for (; Date.now() < end; check()) {}',
];

// Atomics.wait and scheduler.wait are found by name wherever the file keeps them
BYPASS_BANNED.c12 = [
  'Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);',
  'globalThis.Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);',
  "Atomics['wait'](new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);",
  'const { wait } = Atomics; wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);',
  'const A = Atomics; A.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);',
  '(0, Atomics.wait)(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);',
  'Atomics.wait.call(Atomics, new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);',
  'Atomics.wait.apply(Atomics, [new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50]);',
  'Atomics.wait.bind(Atomics, new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50)();',
  'await Atomics.waitAsync(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50).value;',
  "await scheduler['wait'](50);",
  'const { wait } = scheduler; await wait(50);',
  'const s = scheduler; await s.wait(50);',
  'await globalThis.scheduler.wait(50);',
  'await (0, scheduler.wait)(50);',
  'await scheduler.wait.call(scheduler, 50);',
  'const { wait: w } = globalThis.scheduler; await w(50);',
];
BYPASS_ALLOWED.c12 = [
  // somebody else's scheduler, and a scheduler the file builds itself
  'await app.scheduler.wait(job);',
  'const scheduler = makeSched(); await scheduler.wait(job);',
  'function run(scheduler: any) { return scheduler.wait(job); } void run;',
  'const Atomics = fake(); Atomics.wait(1);',
  'Atomics.notify(new Int32Array(new SharedArrayBuffer(4)), 0, 1);',
];

// A busy loop is found by the clock read, not by one spelling of it
BYPASS_BANNED.c13 = [
  'const end = Date.now() + 500; for (;;) { if (Date.now() >= end) break; }',
  'const end = Date.now() + 500; while (true) { if (Date.now() >= end) break; }',
  'const end = Date.now() + 500; while (1) { if (Date.now() >= end) break; }',
  'const end = Date.now() + 500; do { if (Date.now() >= end) break; } while (true);',
  'const end = Date.now() + 500; do {} while (Date.now() < end);',
  "const end = Date['now']() + 500; while (Date['now']() < end) {}",
  'const end = performance.now() + 500; while (globalThis.performance.now() < end) {}',
  'const end = Date.now() + 500; while (globalThis.Date.now() < end) {}',
  'const end = Date.now() + 500; while (Date?.now() < end) {}',
  'const end = Date.now() + 500; while ((0, Date.now)() < end) {}',
  'const now = Date.now; const end = now() + 500; while (now() < end) {}',
  'const { now } = Date; const end = now() + 500; while (now() < end) {}',
  'const end = Date.now() + 500; while (Date.now.call(Date) < end) {}',
  'const end = +new Date() + 500; while (+new Date() < end) {}',
  'const end = +new Date() + 500; for (;;) { if (+new Date() >= end) break; }',
  'const end = new Date().getTime() + 500; while (new Date().getTime() < end) {}',
  'const end = new Date().getTime() + 500; for (;;) { if (new Date().getTime() >= end) break; }',
];
BYPASS_ALLOWED.c13 = [
  // the loop does something else on each pass, or reads no clock, or the clock is the file's own
  'const end = Date.now() + 500; while (true) { if (Date.now() >= end) break; await tick(); }',
  'const end = Date.now() + 500; for (;;) { if (Date.now() >= end) break; check(); }',
  'while (true) { if (done()) break; }',
  'const Date = fake(); while (Date.now() < 5) {}',
  'const end = new Date(0).getTime(); while (new Date(1).getTime() < end) {}',
];

// The timer reached through Reflect.apply, a helper called with .call/.apply/.bind, a resolver wrapped
// in a literal or walked by an array method, the timers module through a comma or a cast, and a
// script held in a const, a raw template or a concatenation
BYPASS_BANNED.c14 = [
  'await new Promise(r => Reflect.apply(setTimeout, globalThis, [r, 50]));',
  'await new Promise(r => { const list = [r, 50]; Reflect.apply(setTimeout, globalThis, list); });',
  'await new Promise(r => { const list = [r, 50]; setTimeout.apply(null, list); });',
  "const t = (0, require)('timers'); void t;",
  "const t = (require as any)('timers/promises'); void t;",
  "const t = (0, process.getBuiltinModule)('node:timers'); void t;",
  "const t = (module.require as any)('timers'); void t;",
  "const t = (0, module.require)('timers'); void t;",
  'function after(r: () => void) { setTimeout(r, 50); } await new Promise(r => after.call(null, r));',
  'function after(r: () => void) { setTimeout(r, 50); } await new Promise(r => after.apply(null, [r]));',
  'function after(r: () => void) { setTimeout(r, 50); } await new Promise(r => { after.bind(null, r)(); });',
  'function after(r: () => void) { setTimeout(r, 50); } await new Promise(r => Reflect.apply(after, null, [r]));',
  'function after(o: any) { setTimeout(o.f, 50); } await new Promise(r => after({ f: r }));',
  'function after({ f }: any) { setTimeout(f, 50); } await new Promise(r => after({ f: r }));',
  'function after({ n: { f } }: any) { setTimeout(f, 50); } await new Promise(r => after({ n: { f: r } }));',
  'function after([f]: any) { setTimeout(f, 50); } await new Promise(r => after([r]));',
  'const after = ({ f }: any) => setTimeout(f, 50); await new Promise(r => after({ f: r }));',
  'await new Promise(r => { [r].forEach((f) => setTimeout(f, 50)); });',
  'await new Promise(r => { [r].map((f) => setTimeout(f, 50)); });',
  'await new Promise(r => { const rs = [r]; rs.forEach((f) => setTimeout(f, 50)); });',
  'function go(f: () => void) { setTimeout(f, 50); } await new Promise(r => { [r].forEach(go); });',
  "const js = 'setTimeout(() => {}, 50)'; await page.evaluate(js);",
  "await page.evaluate(String.raw`new Promise((r) => setTimeout(r, 50))`);",
  "await page.evaluate('new Promise((r) => set' + 'Timeout(r, 50))');",
  "const head = 'new Promise((r) => '; await page.evaluate(`${head}setTimeout(r, 50))`);",
  "await page.evaluate(['new Promise(r => ', 'setTimeout(r, 50))'].join(''));",
  "await page.evaluate('new Promise(r => '.concat('setInterval(r, 50))'));",
];
BYPASS_ALLOWED.c14 = [
  // the key the helper reads is not the one that holds the resolver
  'function after({ f }: any) { setTimeout(f, 50); } await new Promise(r => { after({ g: r }); });',
  // a real handoff inside the helper or the callback
  "function after({ f }: any) { ee.on('x', f); setTimeout(f, 50); } await new Promise(r => after({ f: r }));",
  "await new Promise(r => { [r].forEach((f) => ee.on('x', f)); setTimeout(r, 50); });",
  "function after(r: () => void) { ee.once('x', r); } await new Promise(r => { Reflect.apply(after, null, [r]); setTimeout(r, 50); });",
  "function after(r: () => void) { ee.once('x', r); } await new Promise(r => { after.call(null, r); setTimeout(r, 50); });",
  // scripts that name no timer, or join an unknown into the middle of one
  "const js = 'return 1'; await page.evaluate(js);",
  "await page.evaluate('set' + name + 'Timeout');",
  "await page.evaluate(String.raw`document.title`);",
];

const BYPASS_STATIC: string[] = [
  "import timers = require('node:timers');\nvoid timers;\n",
  "import timers = require('timers/promises');\nvoid timers;\n",
  "export { setTimeout } from 'node:timers/promises';\n",
  "export * from 'timers';\n",
  "import { scheduler } from 'node:timers/promises';\nvoid scheduler;\n",
  "import * as t from 'node:timers';\nvoid t.promises.setInterval;\n",
  "import { setInterval as every } from 'timers/promises';\nvoid every;\n",
];

const flat = (rec: Record<string, string[]>) => Object.entries(rec).flatMap(([c, xs]) => xs.map(x => [c, x] as const));

// The rule follows the reads of a variable and skips its writes with
// `ref.isWriteOnly()` alone, no `ref.init` check. That is only right while every
// initializing write (`let a = 1`, a default value, a loop binding) is write-only.
// This probes the real scope manager for exactly that.
type Ref = { name: string; init: boolean; writeOnly: boolean; write: boolean };
async function refsOf(source: string): Promise<Ref[]> {
  const seen: Ref[] = [];
  const probe = new ESLint({
    cwd: REPO,
    overrideConfig: [{
      files: ['tests/**/*.ts'],
      plugins: { probe: { rules: { refs: { create: (ctx: any) => ({
        'Program:exit'() {
          for (const scope of ctx.sourceCode.scopeManager.scopes) {
            for (const r of scope.references) seen.push({ name: r.identifier.name, init: !!r.init, writeOnly: r.isWriteOnly(), write: r.isWrite() });
          }
        },
      }) } } } },
      rules: { 'probe/refs': 'error' },
    }],
  });
  await probe.lintText(source, { filePath: path.join(REPO, 'tests/snippet.test.ts') });
  return seen;
}

describe('ref.init is redundant next to isWriteOnly', () => {
  const SRC = [
    'let a = 1;', // initializing write
    'a = 2;', // plain write
    'a += 1;', // read and write
    'a++;', // read and write
    'use(a);', // read
    'const { b = 5 } = obj;', // default value inside a pattern
    'function f(c = 1) { return c; }', // parameter default
    'for (const d of list) use(d);', // loop binding
    'void f;',
  ].join('\n') + '\n';

  it('every initializing write is write-only', async () => {
    const refs = await refsOf(SRC);
    const inits = refs.filter(r => r.init);
    // the probe must see an initializer for each name, or the check below proves nothing
    for (const name of ['a', 'b', 'c', 'd']) expect(inits.some(r => r.name === name), name).toBe(true);
    expect(inits.every(r => r.writeOnly)).toBe(true);
  });
});

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
  it('explains the ban and points at the global setImmediate', async () => {
    const [res] = await eslint.lintText("import { setImmediate } from 'node:timers';\nvoid setImmediate;\n", { filePath: path.join(REPO, 'tests/snippet.test.ts') });
    const msg = res.messages.find(m => m.ruleId === 'no-restricted-imports')?.message ?? '';
    expect(msg).toMatch(/global .*setImmediate/);
  });
  it('refuses a snippet that does not parse', async () => {
    await expect(banned('const = ;')).rejects.toThrow('parse');
  });
  it('lets an unrelated module through', async () => {
    expect(await banned("await import('node:path'); require('timersx'); require('xtimers');")).toEqual([]);
  });
  it('bans a template that starts with the module name, hole or not', async () => {
    const codes = [
      'await import(`timers${x}`);',
      'await import(`node:timers${x}`);',
      'const m = require(`timers${x}`); void m;',
      'const m = process.getBuiltinModule(`timers/promises${x}`); void m;',
    ];
    for (const code of codes) expect((await banned(code)).length, code).toBeGreaterThan(0);
  });
  it('lets a template through when the hole comes before or inside the name', async () => {
    const codes = [
      'await import(`${x}timers`);',
      'await import(`timers-${x}`);',
      'const m = require(`${x}`); void m;',
      'const m = process.getBuiltinModule(`node:${x}`); void m;',
    ];
    for (const code of codes) expect(await banned(code), code).toEqual([]);
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
  it.each(flat(BYPASS_BANNED))('[%s] flags the bypass: %s', async (_c, code) => {
    expect((await banned(code)).length).toBeGreaterThan(0);
  });
  it.each(BYPASS_STATIC)('[c3] flags the static form: %s', async code => {
    expect((await bannedFile(code)).length).toBeGreaterThan(0);
  });
  it.each(flat(BYPASS_ALLOWED))('[%s] allows: %s', async (_c, code) => {
    expect(await banned(code)).toEqual([]);
  });
});

// Spec table (~/.claude/reference/no-sleep-rule-spec.md): one row per bypass, linted at the top level of a
// tests/*.ts file with the repo's real config. Columns: class, the rule id that must report it, a fragment
// of its message, the snippet. Classes 1 to 14 each need a row, and each rule id is muted once below to
// prove its rows depend on it.
const SPEC_BANNED: Array<[number, string, string, string]> = [
  [1, "local/no-sleep-promise", "sleep promises", "await new Promise<void>((r) => { const id = setInterval(() => { clearInterval(id); r(); }, 50); });"],
  [2, "local/no-sleep-promise", "sleep promises", "await new Promise((r) => setTimeout.call(globalThis, r, 50));"],
  [2, "local/no-sleep-promise", "sleep promises", "await new Promise((r) => setTimeout.apply(globalThis, [r, 50]));"],
  [2, "local/no-sleep-promise", "sleep promises", "await new Promise((r) => setTimeout.bind(globalThis)(r, 50));"],
  [2, "local/no-sleep-promise", "sleep promises", "await new Promise((r) => (0, setTimeout)(r, 50));"],
  [3, "no-restricted-imports", "imports of the timers module", "import { setTimeout as wait } from 'node:timers/promises'; await wait(50);"],
  [3, "no-restricted-imports", "imports of the timers module", "import timers from 'timers'; void timers;"],
  [3, "no-restricted-imports", "imports of the timers module", "import { setTimeout as st } from 'node:timers'; st(() => undefined, 50);"],
  [3, "no-restricted-syntax", "imports of the timers module", "const t = require('node:timers'); void t;"],
  [3, "no-restricted-syntax", "imports of the timers module", "const t = await import('timers/promises'); void t;"],
  [3, "no-restricted-syntax", "imports of the timers module", "const t = process.getBuiltinModule('node:timers'); void t;"],
  [3, "no-restricted-imports", "imports of the timers module", "import { scheduler } from 'node:timers/promises'; await scheduler.wait(50);"],
  [3, "local/no-fixed-wait", "scheduler.wait", "await (globalThis as any).scheduler.wait(50);"],
  [3, "local/no-fixed-wait", "scheduler.wait", "await scheduler.wait(50);"],
  [3, "local/no-sleep-promise", "promisified timers", "import { promisify } from 'node:util'; await promisify(setTimeout)(50);"],
  [4, "local/no-sleep-promise", "sleep promises", "const P = Promise; await new P((r) => setTimeout(r, 50));"],
  [4, "local/no-sleep-promise", "sleep promises", "await new globalThis.Promise((r) => setTimeout(r, 50));"],
  [4, "local/no-sleep-promise", "sleep promises", "await new (Promise as any)((r: () => void) => setTimeout(r, 50));"],
  [4, "local/no-sleep-promise", "sleep promises", "class P extends Promise<void> {} await new P((r) => setTimeout(r, 50));"],
  [4, "local/no-sleep-promise", "sleep promises", "const { Promise: P } = globalThis; await new P((r) => setTimeout(r, 50));"],
  [5, "local/no-sleep-promise", "sleep promises", "const after = (f: () => void) => setTimeout(f, 50); await new Promise<void>((r) => after(r));"],
  [5, "local/no-sleep-promise", "sleep promises", "function after(f: () => void) { setTimeout(f, 50); } await new Promise<void>((r) => { after(r); });"],
  [6, "local/no-sleep-promise", "sleep promises", "await new Promise((r, rej) => { const ok = r; setTimeout(() => { ok(); void rej; }, 50); });"],
  [7, "local/no-sleep-promise", "sleep promises", "await new Promise((r = () => undefined) => setTimeout(r, 50));"],
  [7, "local/no-sleep-promise", "sleep promises", "await new Promise((r = () => undefined, rej) => setTimeout(() => { r(); void rej; }, 50));"],
  [7, "local/no-sleep-promise", "sleep promises", "function ex(r = () => undefined) { setTimeout(r, 50); } await new Promise(ex);"],
  [6, "local/no-sleep-promise", "sleep promises", "await new Promise((r, rej) => { const o = { r }; setTimeout(() => { o.r(); void rej; }, 50); });"],
  [6, "local/no-sleep-promise", "sleep promises", "await new Promise((r, rej) => { const a = [r]; setTimeout(() => { a[0](); void rej; }, 50); });"],
  [6, "local/no-sleep-promise", "sleep promises", "await new Promise((r) => { const o = { a: { done: r } }; setTimeout(() => o.a.done(), 50); });"],
  [6, "local/no-sleep-promise", "sleep promises", "await new Promise((r) => { const o = { done: r }; const go = () => o.done(); setTimeout(go, 50); });"],
  [6, "local/no-sleep-promise", "sleep promises", "await new Promise((r) => { const a = [[r]]; setTimeout(() => a[0][0](), 50); });"],
  [6, "local/no-sleep-promise", "sleep promises", "let ok = () => undefined; const late = (j: (e: Error) => void) => { ok(); void j; }; await new Promise((r, rej) => { ok = r; setTimeout(() => late(rej), 50); });"],
  [6, "local/no-sleep-promise", "sleep promises", "let ok = () => undefined; function a() { b(); } function b() { ok(); } await new Promise((r) => { ok = r; setTimeout(a, 50); });"],
  [9, "local/no-sleep-promise", "sleep promises", "async function run(wait = setTimeout) { await new Promise((r) => wait(r, 50)); } await run(fake); await run();"],
  [9, "local/no-sleep-promise", "sleep promises", "const run = async (wait = setTimeout) => new Promise((r) => wait(r, 50)); await run(undefined);"],
  [9, "local/no-sleep-promise", "sleep promises", "export async function run(wait = setTimeout) { await new Promise((r) => wait(r, 50)); } await run(fake);"],
  [9, "local/no-sleep-promise", "sleep promises", "async function run(wait = setTimeout) { await new Promise((r) => wait(r, 50)); } use(run); await run(fake);"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "async function run(s = 'setTimeout(() => 0, 5)') { await tab.evaluate(s); } await run('document.title'); await run();"],
  [8, "local/no-sleep-promise", "sleep promises", "const { setTimeout: wait } = globalThis; await new Promise((r) => wait(r, 50));"],
  [8, "local/no-sleep-promise", "sleep promises", "let k = 'setTimeout'; k = 'setTimeout'; await new Promise((r) => (globalThis as any)[k](r, 50));"],
  [8, "local/no-sleep-promise", "sleep promises", "let k = 'title'; k = 'setInterval'; await new Promise((r) => (globalThis as any)[k](r, 50));"],
  [8, "local/no-sleep-promise", "sleep promises", "let k = 'setTimeout'; k = 'title'; const { [k]: wait } = globalThis; await new Promise((r) => wait(r, 50));"],
  [8, "local/no-sleep-promise", "sleep promises", "const { 'setTimeout': wait } = window; await new Promise((r) => wait(r, 50));"],
  [8, "local/no-sleep-promise", "sleep promises", "const { ['setTimeout']: wait } = self; await new Promise((r) => wait(r, 50));"],
  [8, "local/no-sleep-promise", "sleep promises", "const k = 'setTimeout'; const { [k]: wait } = globalThis; await new Promise((r) => wait(r, 50));"],
  [8, "local/no-sleep-promise", "sleep promises", "const { setTimeout: wait = fallback } = globalThis; await new Promise((r) => wait(r, 50));"],
  [8, "local/no-sleep-promise", "sleep promises", "const { setInterval: wait } = global; await new Promise((r) => wait(r, 50));"],
  [9, "local/no-sleep-promise", "sleep promises", "const box = { wait: setTimeout }; await new Promise((r) => box.wait(r, 50));"],
  [9, "local/no-sleep-promise", "sleep promises", "const box = { setTimeout }; await new Promise((r) => box.setTimeout(r, 50));"],
  [9, "local/no-sleep-promise", "sleep promises", "const fns = [setTimeout]; await new Promise((r) => fns[0](r, 50));"],
  [9, "local/no-sleep-promise", "sleep promises", "const [wait] = [setTimeout]; await new Promise((r) => wait(r, 50));"],
  [9, "local/no-sleep-promise", "sleep promises", "async function run(wait = setTimeout) { await new Promise((r) => wait(r, 50)); } await run();"],
  [9, "local/no-fixed-wait", "passed on as a value", "run(setTimeout as never);"],
  [9, "local/no-fixed-wait", "passed on as a value", "run(<any>setTimeout);"],
  [9, "local/no-fixed-wait", "passed on as a value", "run(setTimeout satisfies any);"],
  [9, "local/no-fixed-wait", "passed on as a value", "const o = setTimeout; run(o as never);"],
  [9, "local/no-fixed-wait", "passed on as a value", "run(globalThis.setInterval as never);"],
  [9, "local/no-sleep-promise", "sleep promises", "const run = async (wait = globalThis.setTimeout) => new Promise((r) => wait(r, 50)); await run();"],
  [9, "local/no-sleep-promise", "sleep promises", "async function run({ wait = setTimeout } = {}) { await new Promise((r) => wait(r, 50)); } await run();"],
  [9, "local/no-sleep-promise", "sleep promises", "const w = setTimeout; await new Promise((r) => w(r, 50));"],
  [9, "local/no-sleep-promise", "sleep promises", "const o = { a: fake, b: setTimeout }; const w = o.a ?? o.b; await new Promise((r) => w(r, 50));"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers<void>(); setTimeout(() => d.resolve(), 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const { promise, resolve } = Promise.withResolvers<void>(); setTimeout(resolve, 50); await promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "let d; d = Promise.withResolvers<void>(); setTimeout(d.resolve, 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "let resolve: () => void; ({ resolve } = Promise.withResolvers<void>()); setTimeout(resolve, 50);"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = globalThis.Promise.withResolvers<void>(); setTimeout(d.resolve, 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = (Promise as any).withResolvers(); setTimeout(() => d.resolve(), 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers<void>(); setTimeout((0, d.resolve), 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers<void>(); setTimeout((d as any).resolve, 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers<void>(); setTimeout(() => d?.resolve(), 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers<void>(); setTimeout(d?.resolve, 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers<void>(); setTimeout(() => d.resolve?.(), 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers<void>(); setTimeout(d['resolve'], 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers<void>(); setTimeout(d[`resolve`], 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const q: Array<() => void> = []; const d = Promise.withResolvers<void>(); q.push(d.resolve); setTimeout(() => q[0](), 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers<void>(); const q = [d.resolve]; setTimeout(q[0], 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers<void>(); const { resolve } = d; setTimeout(resolve, 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers<void>(); const e = d; setTimeout(e.resolve, 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const pending = new Map(); const d = Promise.withResolvers<void>(); pending.set(1, d); setTimeout(() => pending.get(1).resolve(), 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const m = new Map(); const p = new Promise(r => { m.set(1, r); }); setTimeout(() => m.get(1)(), 50); expect(m.get(1)).toBeDefined(); await p;"],
  [10, "local/no-sleep-promise", "sleep promises", "const m = new Map(); const p = new Promise(r => { m.set(1, r); }); setTimeout(() => m.get(1)(), 50); const ks = [...m.keys()]; await p;"],
  [10, "local/no-sleep-promise", "sleep promises", "const rs: any[] = []; const p = new Promise(r => { rs.push(r); }); setTimeout(() => rs[0](), 50); log(rs.indexOf(1)); await p;"],
  [10, "local/no-sleep-promise", "sleep promises", "const rs: any[] = []; const p = new Promise(r => { rs.push(r); }); setTimeout(() => rs[0](), 50); rs.forEach(f => log(f)); await p;"],
  [14, "local/no-sleep-promise", "sleep promises", "await new Promise(r => { [r].filter((f) => setTimeout(f, 50)); });"],
  [14, "local/no-sleep-promise", "sleep promises", "await new Promise(r => { [r].some((f) => setTimeout(f, 50)); });"],
  [14, "local/no-sleep-promise", "sleep promises", "await new Promise(r => { [r].every((f) => setTimeout(f, 50)); });"],
  [14, "local/no-sleep-promise", "sleep promises", "await new Promise(r => { [r].find((f) => setTimeout(f, 50)); });"],
  [14, "local/no-sleep-promise", "sleep promises", "await new Promise(r => { [r].findLast((f) => setTimeout(f, 50)); });"],
  [14, "local/no-sleep-promise", "sleep promises", "await new Promise(r => { [r].findIndex((f) => setTimeout(f, 50)); });"],
  [14, "local/no-sleep-promise", "sleep promises", "await new Promise(r => { [r].flatMap((f) => setTimeout(f, 50)); });"],
  [10, "local/no-sleep-promise", "sleep promises", "const rs: any[] = []; const p = new Promise(r => { rs.push(r); }); setTimeout(() => rs[0](), 50); rs.some(f => f === 1); await p;"],
  [10, "local/no-sleep-promise", "sleep promises", "const rs: any[] = []; const p = new Promise(r => { rs.push(r); }); setTimeout(() => rs[0](), 50); for (const f of rs) log(f); await p;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers<void>(); const e = { d }; setTimeout(() => e.d.resolve(), 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers<void>(); const e = { x: d }; setTimeout(() => e.x.resolve(), 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers<void>(); const q = [d]; setTimeout(() => q[0].resolve(), 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers<void>(); const e = { a: { b: [d] } }; setTimeout(() => e.a.b[0].resolve(), 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers<void>(); const e = { d }; const { resolve } = e.d; setTimeout(resolve, 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const e = { d: Promise.withResolvers<void>() }; setTimeout(() => e.d.resolve(), 50); await e.d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers.call(Promise); setTimeout(d.resolve, 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers.apply(Promise, []); setTimeout(d.resolve, 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers.bind(Promise)(); setTimeout(d.resolve, 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const mk = Promise.withResolvers.bind(Promise); const d = mk(); setTimeout(d.resolve, 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const { withResolvers: mk } = Promise; const d = mk.call(Promise); setTimeout(d.resolve, 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const { withResolvers: mk } = Promise; const { resolve } = mk.call(Promise); setTimeout(resolve, 50);"],
  [3, "local/no-fixed-wait", "imports of the timers module", "const m = 'node:timers'; const t = require(m); void t;"],
  [3, "local/no-fixed-wait", "imports of the timers module", "let m = 'timers'; const t = await import(m); void t;"],
  [3, "local/no-fixed-wait", "imports of the timers module", "const m = 'timers'; const t = process.getBuiltinModule(m); void t;"],
  [3, "local/no-fixed-wait", "imports of the timers module", "const a = 'timers'; const b = a; const t = require(b); void t;"],
  [3, "local/no-fixed-wait", "imports of the timers module", "const m = 'timers'; const t = createRequire(import.meta.url)(m); void t;"],
  [8, "local/no-sleep-promise", "sleep promises", "let k = 'setTimeout'; const { [k]: wait } = globalThis; await new Promise((r) => wait(r, 50));"],
  [8, "local/no-sleep-promise", "sleep promises", "let k = 'setTimeout'; await new Promise((r) => (globalThis as any)[k](r, 50));"],
  [9, "local/no-sleep-promise", "sleep promises", "let t = setTimeout; await new Promise((r) => t(r, 50));"],
  [9, "local/no-sleep-promise", "sleep promises", "let t: any; t = setTimeout; await new Promise((r) => t(r, 50));"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "let s = 'new Promise((r) => setTimeout(r, 500))'; await tab.evaluate(s);"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "let s = 'setTimeout'; s = 'x'; await page.evaluate(s);"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "let s = 'x'; s = 'setTimeout(() => 0, 5)'; await page.evaluate(s);"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "let s = 'setTimeout(() => 0, 5)'; s += ''; await page.evaluate(s);"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "let s: string; s = 'setTimeout(() => 0, 5)'; await page.evaluate(s);"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "let s = `new Promise((r) => setInterval(r, 5))`; await page.waitForFunction(s);"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "let s = 'setTimeout(() => undefined, 5)'; await context.addInitScript(s);"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "let s = 'setTimeout(() => undefined, 5)'; await page.addInitScript({ content: s });"],
  [8, "local/no-sleep-promise", "sleep promises", "let wait; ({ setTimeout: wait } = globalThis); await new Promise((r) => wait(r, 50));"],
  [8, "local/no-sleep-promise", "sleep promises", "let wait: any; [wait] = [setTimeout]; await new Promise((r) => wait(r, 50));"],
  [9, "local/no-sleep-promise", "sleep promises", "function mk() { return setTimeout; } const w = mk(); await new Promise((r) => w(r, 50));"],
  [4, "local/no-sleep-promise", "Reflect.construct(Promise", "await Reflect.construct(Promise, args);"],
  [4, "local/no-sleep-promise", "Reflect.construct(Promise", "class P extends Promise<void> {} await Reflect.construct(P, args);"],
  [4, "local/no-sleep-promise", "sleep promises", "const args = [(r: () => void) => setTimeout(r, 50)]; await Reflect.construct(Promise, args);"],
  [4, "local/no-sleep-promise", "sleep promises", "let args: any; args = [(r: () => void) => setTimeout(r, 50)]; await Reflect.construct(Promise, args);"],
  [4, "local/no-sleep-promise", "sleep promises", "void new (class extends Promise<void> {})((r) => { setTimeout(r, 5); });"],
  [4, "local/no-sleep-promise", "sleep promises", "class Q extends Promise<void> { constructor() { super((r) => setTimeout(r, 50)); } } await new Q();"],
  [9, "local/no-sleep-promise", "sleep promises", "const w = (() => setTimeout)(); await new Promise((r) => w(r, 50));"],
  [9, "local/no-sleep-promise", "sleep promises", "const mk = () => { if (c) return other; return globalThis.setInterval; }; const w = mk(); await new Promise((r) => w(r, 50));"],
  [9, "local/no-fixed-wait", "timers turned into text", "const t = `${setTimeout}`; void t;"],
  [8, "local/no-sleep-promise", "sleep promises", "async function run({ setTimeout: wait } = globalThis) { await new Promise((r) => wait(r, 50)); } await run();"],
  [8, "local/no-sleep-promise", "sleep promises", "const run = async ({ setInterval: wait } = window) => new Promise((r) => wait(r, 50)); await run();"],
  [10, "local/no-sleep-promise", "sleep promises", "class A { d = Promise.withResolvers<void>(); go() { setTimeout(() => this.d.resolve(), 5); return this.d.promise; } }"],
  [10, "local/no-sleep-promise", "sleep promises", "class A { #d = Promise.withResolvers<void>(); go() { setTimeout(() => this.#d.resolve(), 5); return this.#d.promise; } }"],
  [10, "local/no-sleep-promise", "sleep promises", "class A { static d = Promise.withResolvers<void>(); } setTimeout(() => A.d.resolve(), 5); await A.d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "class A { d: any; constructor() { this.d = Promise.withResolvers<void>(); } go() { setTimeout(() => this.d.resolve(), 5); } }"],
  [10, "local/no-sleep-promise", "sleep promises", "const o: any = {}; o.d = Promise.withResolvers<void>(); setTimeout(() => o.d.resolve(), 5); await o.d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "class A { d = Promise.withResolvers<void>(); go() { const { resolve } = this.d; setTimeout(resolve, 5); } }"],
  [10, "local/no-sleep-promise", "sleep promises", "const q = [Promise.withResolvers<void>()]; setTimeout(() => q[0].resolve(), 50); await q[0].promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers<void>(); const x = d || other; setTimeout(() => x.resolve(), 50); await d.promise;"],
  [10, "local/no-sleep-promise", "sleep promises", "const d = Promise.withResolvers<void>(); const x = c ? d : other; setTimeout(x.resolve, 50); await d.promise;"],
  [11, "local/no-fixed-wait", "fixed waitForTimeout (a call", "await page.waitForTimeout(500);"],
  [11, "local/no-fixed-wait", "fixed waitForTimeout (a call", "let k = 'waitForTimeout'; k = 'title'; await (page as any)[k]();"],
  [11, "local/no-fixed-wait", "fixed waitForTimeout (a call", "let k = 'title'; k = 'waitForTimeout'; await (page as any)[k](500);"],
  [11, "local/no-fixed-wait", "fixed waitForTimeout (a call", "await tab.waitForTimeout(500);"],
  [11, "local/no-fixed-wait", "fixed waitForTimeout (a call", "await getTab().waitForTimeout(500);"],
  [11, "local/no-fixed-wait", "fixed waitForTimeout (a call", "await page['waitForTimeout'](500);"],
  [11, "local/no-fixed-wait", "fixed waitForTimeout (a call", "const k = 'waitForTimeout'; await (page as any)[k](500);"],
  [11, "local/no-fixed-wait", "fixed waitForTimeout (a call", "await page.waitForTimeout.call(page, 500);"],
  [11, "local/no-fixed-wait", "fixed waitForTimeout (a call", "await page.waitForTimeout.apply(page, [500]);"],
  [11, "local/no-fixed-wait", "fixed waitForTimeout (a call", "const w = page.waitForTimeout.bind(page); await w(500);"],
  [11, "local/no-fixed-wait", "fixed waitForTimeout (a call", "const { waitForTimeout } = page; await waitForTimeout(500);"],
  [11, "local/no-fixed-wait", "fixed waitForTimeout (a call", "const { waitForTimeout: w } = page; await w(500);"],
  [11, "local/no-fixed-wait", "fixed waitForTimeout (a call", "run(page.waitForTimeout);"],
  [11, "local/no-fixed-wait", "fixed waitForTimeout (a call", "const w = page.waitForTimeout; await w.call(page, 500);"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "await page.evaluate('new Promise((r) => setTimeout(r, 500))');"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "await page.waitForFunction(`new Promise((r) => setInterval(r, 5))`);"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "await context.addInitScript('setTimeout(() => undefined, 5)');"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "await tab.evaluate('new Promise((r) => setTimeout(r, 500))');"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "await page.evaluate('(ms) => new Promise((r) => setTimeout(r, ms))', 500);"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "await page.addInitScript({ content: 'setTimeout(() => undefined, 5)' });"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "await page.evaluate(`new Promise((r) => setTimeout(r, ${ms}))`);"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "await page.$eval('#x', 'setTimeout(() => 0, 5)');"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "await page.evaluate('setTimeout(() => 0, 5)', 1);"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "await page.evaluate('set' + 'Timeout' + '(' + 'f' + ', ' + '5' + ')' + ';' + ' ' + 'x');"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "const s0 = 'setTimeout(() => 0, 5)'; const s1 = s0 + ' '; const s2 = s1 + ' '; const s3 = s2 + ' '; const s4 = s3 + ' '; const s5 = s4 + ' '; const s6 = s5 + ' '; const s7 = s6 + ' '; const s8 = s7 + ' '; const s9 = s8 + ' '; const s10 = s9 + ' '; await page.evaluate(s10);"],
  [12, "local/no-fixed-wait", "timers in a script string (", "async function run(s = 'new Promise((r) => setTimeout(r, 500))') { await tab.evaluate(s); } await run();"],
  [12, "local/no-fixed-wait", "timers in a function sent to the page", "await page.addInitScript(() => { setTimeout(() => undefined, 5); });"],
  [12, "local/no-fixed-wait", "timers in a function sent to the page", "const fn = () => { setTimeout(() => undefined, 5); }; await page.evaluate(fn);"],
  [12, "local/no-fixed-wait", "timers in a function sent to the page", "function fn() { setTimeout(() => undefined, 5); } await page.addInitScript(fn);"],
  [12, "local/no-fixed-wait", "timers in a function sent to the page", "await page.$eval('#x', (el) => { setInterval(() => undefined, 5); });"],
  [12, "local/no-fixed-wait", "timers in a function sent to the page", "await page.evaluate(function () { window.setTimeout(() => 0, 5); });"],
  [12, "local/no-fixed-wait", "timers in a script string (i", "const s0 = 'setTimeout(() => 0, 5)'; const s1 = s0 + s0; const s2 = s1 + s1; const s3 = s2 + s2; const s4 = s3 + s3; const s5 = s4 + s4; const s6 = s5 + s5; const s7 = s6 + s6; const s8 = s7 + s7; const s9 = s8 + s8; const s10 = s9 + s9; const s11 = s10 + s10; const s12 = s11 + s11; const s13 = s12 + s12; const s14 = s13 + s13; const s15 = s14 + s14; const s16 = s15 + s15; const s17 = s16 + s16; const s18 = s17 + s17; const s19 = s18 + s18; const s20 = s19 + s19; const s21 = s20 + s20; const s22 = s21 + s21; const s23 = s22 + s22; const s24 = s23 + s23; const s25 = s24 + s24; const s26 = s25 + s25; const s27 = s26 + s26; const s28 = s27 + s27; const s29 = s28 + s28; const s30 = s29 + s29; await page.evaluate(s30);"],
  [13, "local/no-fixed-wait", "Atomics.wait (it blocks for ", "Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);"],
  [13, "local/no-fixed-wait", "Atomics.wait (it blocks for ", "await Atomics.waitAsync(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500).value;"],
  [13, "local/no-fixed-wait", "Atomics.wait (it blocks for ", "Reflect.apply(Atomics.wait, null, [new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500]);"],
  [13, "local/no-fixed-wait", "Atomics.wait (it blocks for ", "const w = Atomics.wait; Reflect.apply(w, null, [new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500]);"],
  [13, "local/no-fixed-wait", "Atomics.wait (it blocks for ", "Reflect.apply(Atomics.wait.bind(null), null, [new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500]);"],
  [3, "local/no-fixed-wait", "scheduler.wait", "await Reflect.apply(scheduler.wait, scheduler, [50]);"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const end = Date.now() + 500; while (Date.now() < end) {}"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const end = Date.now() + 500; do {} while (Date.now() < end);"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const end = performance.now() + 500; for (; performance.now() < end; );"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const end = process.hrtime.bigint() + 5000000n; while (process.hrtime.bigint() < end) {}"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const { hrtime } = process; const end = hrtime.bigint() + 5n; while (hrtime.bigint() < end) {}"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const end = new Date().valueOf() + 500; while (new Date().valueOf() < end) {}"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const end = new Date().valueOf() + 500; for (;;) { if (new Date().valueOf() >= end) break; }"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const end = Date.now() + 500; let n = 0; while (Date.now() < end) { n++; }"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const end = Date.now() + 500; while (end > Date.now());"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "let done = false; const end = Date.now() + 500; while (!done) { if (Date.now() > end) break; }"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const end = Date.now() + 500; while (1) { if (Date.now() > end) break; }"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const end = Date.now() + 500; for (let i = 0; i < 10; i++) { if (Date.now() > end) break; }"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const end = Date.now() + 500; while (true) { const t = Date.now(); if (t > end) break; }"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const end = Date.now() + 500; let t = 0; for (;;) { t = performance.now(); if (t > end) { break; } }"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const end = Date.now() + 500; (() => { while (true) { if (Date.now() > end) return; } })();"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "for (let t = Date.now(); t < end; t = Date.now()) {}"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "let n = 0; while (n < 3) { const t = Date.now(); if (t > end) { break; } n++; }"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const end = Date.now() + 500; let t = Date.now(); while (t < end) { t = Date.now(); }"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const end = Date.now() + 500; let t = 0; do { t = Date.now(); } while (t < end);"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const end = Date.now() + 500; let ok = true; while (ok) { ok = Date.now() < end; }"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const end = performance.now() + 500; let t = 0; for (; t < end; ) { t = performance.now(); }"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "let done = false; const end = Date.now() + 500; while (!done) { if (Date.now() > end) done = true; }"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const end = Date.now() + 500; while (true) { if (Date.now() > end) throw new Error('late'); }"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const start = Date.now(); const elapsed = () => Date.now() - start; while (elapsed() < 500) {}"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "function now() { return performance.now(); } const end = now() + 500; while (now() < end) {}"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const now = function () { return Date.now(); }; const end = now() + 500; for (;;) { if (now() > end) break; }"],
  [14, "local/no-fixed-wait", "busy-waits on the clock", "const now = () => Date.now(); const read = () => now(); const end = read() + 500; do {} while (read() < end);"],
];

const SPEC_ALLOWED: string[] = [
  "await new Promise((r, rej) => { setTimeout(() => rej(new Error('late')), 50); });",
  "await new Promise((r, rej) => setTimeout(rej, 50));",
  "await page.evaluate(() => document.title);",
  "async function run(s = 'document.title') { await tab.evaluate(s); } await run();",
  "async function run(s = 'setTimeout(0)') { s = 'document.title'; await tab.evaluate(s); } await run();",
  "await page.evaluate(({ a }) => a + 1, { a: 1 });",
  "const orig = setTimeout; vi.stubGlobal('setTimeout', orig as never);",
  "const orig = globalThis.setInterval; vi.stubGlobal('setInterval', orig as never);",
  "expect(setTimeout as any).toBeDefined();",
  "vi.mocked(setTimeout as any).mockClear();",
  "run(other as never);",
  "Reflect.apply(Atomics.notify, null, [new Int32Array(new SharedArrayBuffer(4)), 0, 1]);",
  "const Reflect = { apply(f: any) { return f; } }; Reflect.apply(Atomics.wait, null, []);",
  "const h = process.hrtime.bigint(); log(h);",
  "const end = new Date(0).valueOf(); while (new Date(1).valueOf() < end) {}",
  "const rs: any[] = []; const p = new Promise(r => { rs.push(r); }); setTimeout(() => rs[0](), 50); rs.filter((f: any) => f()); await p;",
  "const rs: any[] = []; const p = new Promise(r => { rs.push(r); }); setTimeout(() => rs[0](), 50); rs.some((f: any) => f()); await p;",
  "const rs: any[] = []; const p = new Promise(r => { rs.push(r); }); setTimeout(() => rs[0](), 50); rs.every((f: any) => f()); await p;",
  "const rs: any[] = []; const p = new Promise(r => { rs.push(r); }); setTimeout(() => rs[0](), 50); rs.find((f: any) => f()); await p;",
  "const rs: any[] = []; const p = new Promise(r => { rs.push(r); }); setTimeout(() => rs[0](), 50); rs.findLast((f: any) => f()); await p;",
  "const rs: any[] = []; const p = new Promise(r => { rs.push(r); }); setTimeout(() => rs[0](), 50); rs.findIndex((f: any) => f()); await p;",
  "const rs: any[] = []; const p = new Promise(r => { rs.push(r); }); setTimeout(() => rs[0](), 50); rs.flatMap((f: any) => f()); await p;",
  "await new Promise(r => { src.addListener('x', r); setTimeout(r, 5); });",
  "await new Promise(r => { src.prependListener('x', r); setTimeout(r, 5); });",
  "await new Promise(r => { src.prependOnceListener('x', r); setTimeout(r, 5); });",
  "await new Promise(r => { src.addEventListener('x', r); setTimeout(r, 5); });",
  "await new Promise(r => { src.then('x', r); setTimeout(r, 5); });",
  "await new Promise(r => { src.finally('x', r); setTimeout(r, 5); });",
  "await new Promise(r => { src.subscribe('x', r); setTimeout(r, 5); });",
  "const rs: any[] = []; const p = new Promise(r => { rs.push(r); }); setTimeout(() => rs[0](), 50); rs.forEach(f => f()); await p;",
  "const rs: any[] = []; const p = new Promise(r => { rs.push(r); }); setTimeout(() => rs[0](), 50); for (const f of rs) f(); await p;",
  "const rs: any[] = []; const p = new Promise(r => { rs.push(r); }); setTimeout(() => rs[0](), 50); rs.shift()(); await p;",
  "function fail(j: (e: Error) => void) { j(new Error('late')); } await new Promise((r, rej) => setTimeout(() => fail(rej), 50));",
  "await new Promise((r, rej) => { const fail = rej; setTimeout(() => fail(new Error('late')), 50); });",
  "await new Promise((r, rej) => { setInterval(() => rej(new Error('late')), 50); });",
  "const orig = globalThis.setTimeout; globalThis.setTimeout = (() => 0) as never; globalThis.setTimeout = orig;",
  "const orig = setTimeout; setTimeout = (() => 0) as never; setTimeout = orig;",
  "const orig = setInterval; setInterval = (() => 0) as never; setInterval = orig;",
  "const orig = setTimeout; vi.stubGlobal('setTimeout', () => 0); vi.stubGlobal('setTimeout', orig);",
  "vi.useFakeTimers({ toFake: ['setTimeout'] }); vi.advanceTimersByTime(50); vi.useRealTimers();",
  "const ms = opts.setTimeout ?? 5000; if (ms) use(ms);",
  "const t = opts.setTimeout; use(t);",
  "const t = opts['setTimeout']; use(t);",
  "expect(opts.setTimeout).toBe(5000);",
  "server.setTimeout(5000);",
  "await new Promise((r) => { server.setTimeout(r, 50); });",
  "await new Promise((r, rej) => setTimeout(rej as never, 50));",
  "await new Promise((r, rej) => setTimeout((() => rej(new Error('late'))) as never, 50));",
  "const P = lib.Promise; use(P);",
  "const all = Promise.all([]); await all;",
  "const id = setTimeout(() => undefined, 50); clearTimeout(id);",
  "expect(setTimeout).toBeDefined(); expect(globalThis.setTimeout).toBeTypeOf('function');",
  "vi.mocked(setTimeout).mockClear();",
  "await expect(page.locator('#x')).toBeVisible();",
  "await page.evaluate('document.title');",
  "await page.evaluate(() => document.title);",
  "const end = Date.now() + 500; while (Date.now() < end) { await check(); }",
  "const d = Promise.withResolvers<void>(); setTimeout(() => d.reject(new Error('late')), 50); await d.promise.catch(() => undefined);",
  "const d = Promise.withResolvers<void>(); queueMicrotask(() => d.resolve()); await d.promise;",
  "await new Promise((r) => { globalThis['queueMicrotask'](r); });",
  "const stamps: number[] = []; for (let i = 0; i < 3; i++) stamps[i] = Date.now(); use(stamps);",
  "let last = 0; for (let i = 0; i < 3; i++) { last = Date.now(); } use(last);",
  "let late = 0; for (let i = 0; i < 3; i++) { if (Date.now() > deadline) late++; } use(late);",
  "let n = 0; let t = 0; while (n < 3) { t = performance.now(); n++; } use(t);",
  "let t = Date.now(); while (t < end) { t = Date.now(); await check(); }",
  "let ok = true; while (ok) { ok = next(); }",
  "while (!stopped) { if (Date.now() > end) missing = 1; }",
  "let done = false; let other = 0; while (!done) { if (Date.now() > end) other = 1; done = ok(); }",
  "const end = Date.now() + 500; while (true) { if (Date.now() > end) throw new Error('late'); work(); }",
  "let t = 0; let n = 0; while (t < end) { n++; t = n * 2; }",
  "function now() { return Date.now(); } const stamps: number[] = []; for (let i = 0; i < 3; i++) stamps[i] = now(); use(stamps);",
  "const mk = () => () => Date.now(); const end = 5; while (mk() < end) {}",
  "const now = () => now(); const end = 5; while (now() < end) {}",
  "function a() { return b(); } function b() { return a(); } while (a() < 5) {}",
  "const t0 = Date.now(); const check = () => { void fetch('x'); return Date.now() - t0; }; while (check() < 500) {}",
  "let n = 0; const tick = () => { n++; return n; }; while (tick() < 5) {}",
  "const stamp = () => Date.now(); const s: number[] = []; for (let i = 0; i < 3; i++) s[i] = stamp(); use(s);",
  "const t0 = Date.now(); const dt = () => Date.now() - t0; const a = dt(); use(a);",
  "for (let i = 0; i < 10; i++) { for (const x of xs) { if (Date.now() > end) break; } }",
  "for (let i = 0; i < 10; i++) { if (Date.now() > end) break; work(i); }",
  "await page.evaluate((s: string) => s, 'setTimeout');",
  "await page.$eval('setTimeout', (el) => el.id);",
  "await page.$$eval('#x', (els, s) => els, 'setTimeout');",
  "const a = b + 'x'; const b = a + 'y'; await page.evaluate(a);",
  "const s0 = 'document.title'; const s1 = s0 + s0; const s2 = s1 + s1; const s3 = s2 + s2; const s4 = s3 + s3; const s5 = s4 + s4; const s6 = s5 + s5; const s7 = s6 + s6; const s8 = s7 + s7; const s9 = s8 + s8; const s10 = s9 + s9; const s11 = s10 + s10; const s12 = s11 + s11; const s13 = s12 + s12; const s14 = s13 + s13; const s15 = s14 + s14; const s16 = s15 + s15; const s17 = s16 + s16; const s18 = s17 + s17; const s19 = s18 + s18; const s20 = s19 + s19; const s21 = s20 + s20; const s22 = s21 + s21; const s23 = s22 + s22; const s24 = s23 + s23; const s25 = s24 + s24; const s26 = s25 + s25; const s27 = s26 + s26; const s28 = s27 + s27; const s29 = s28 + s28; const s30 = s29 + s29; await page.evaluate(s30);",
  "await mySched.wait(50);",
  "const pending = new Map(); const p = new Promise((res, rej) => { pending.set(1, { res, rej }); }); setTimeout(() => pending.get(1).rej(new Error('timeout')), 5000); await p;",
  "const pending = new Map(); const d = Promise.withResolvers<void>(); pending.set(1, d); setTimeout(() => pending.get(1).reject(new Error('timeout')), 5000); ee.on('x', () => pending.get(1).resolve()); await d.promise;",
  "const d = Promise.withResolvers<void>(); const e = { d }; setTimeout(() => e.d.reject(new Error('late')), 50); await d.promise.catch(() => undefined);",
  "const d = Promise.withResolvers<void>(); const e = { d }; run(e); setTimeout(() => d.resolve(), 50); await d.promise;",
  "const d = Promise.withResolvers<void>(); const e = { d }; ee.on('x', () => e.d.resolve()); setTimeout(() => e.d.resolve(), 50); await d.promise;",
  "const d = Promise.withResolvers<void>(); const e = { d, n: 1 }; setTimeout(() => e.n++, 50); ee.on('x', () => e.d.resolve()); await d.promise;",
  "const d = Promise.withResolvers.call(Promise); setTimeout(() => d.reject(new Error('late')), 50); await d.promise.catch(() => undefined);",
  "const mk = lib.make.bind(lib); const d = mk(); setTimeout(d.resolve, 50);",
  "class A { d = Promise.withResolvers<void>(); go() { setTimeout(() => this.d.reject(new Error('late')), 5); return this.d.promise.catch(() => undefined); } }",
  "class A { n = 1; go() { setTimeout(() => this.n++, 5); } }",
  "class A { d = Promise.withResolvers<void>(); go() { setTimeout(() => this.d.resolve(), 5); ee.on('x', () => this.d.resolve()); return this.d.promise; } }",
  "class A { static d = Promise.withResolvers<void>(); } ee.on('x', () => A.d.resolve()); setTimeout(() => A.d.resolve(), 5);",
  "const o: any = {}; o.d = Promise.withResolvers<void>(); setTimeout(() => o.d.reject(new Error('late')), 5); await o.d.promise.catch(() => undefined);",
  "let m = 'timers'; m = './local'; const t = require(m); void t;",
  "let m = 'timers'; m = './local'; const t = await import(m); void t;",
  "const m = 'fs'; const t = require(m); void t;",
  "let t = setTimeout; t = other; await new Promise((r) => t(r, 50));",
  "let k = 'setTimeout'; k = 'other'; const { [k]: wait } = globalThis; use(wait);",
  "let k = 'title'; k = 'url'; await (page as any)[k]();",
  "async function run(wait = setTimeout) { await new Promise((r) => wait(r, 50)); } await run(fake);",
  "const run = async (s = 'setTimeout(() => 0, 5)') => { await tab.evaluate(s); }; await run('document.title'); await run(other);",
  "let ok = () => undefined; const late = () => { ok(); }; await new Promise((r) => { ok = r; ee.on('x', () => late()); setTimeout(() => late(), 50); });",
  "let ok = () => undefined; const late = () => { ok(); }; await new Promise((r) => { ok = r; ee.on('x', late); setTimeout(() => other(), 50); });",
  "let ok = () => undefined; const never = () => { ok(); }; await new Promise((r) => { ok = r; ee.on('x', () => never()); setTimeout(() => other(), 50); });",
  "await new Promise((r, rej) => { const o = { r, rej }; ee.on('x', o.r); setTimeout(() => o.rej(new Error('late')), 50); });",
  "let s = 'document.title'; s += '.length'; await page.evaluate(s);",
  "let wait; ({ setTimeout: wait } = opts); use(wait);",
  "function f({ setTimeout: ms } = opts) { use(ms); } f();",
  "let wait; ({ setTimeout: wait } = globalThis); wait = other; await new Promise((r) => wait(r, 50));",
  "function mk() { return setTimeoutLike; } mk();",
  "function mk() { return () => setTimeout; } const w = mk(); await new Promise((r) => w(r, 50));",
  "function mk() { return mk(); } const w = mk(); await new Promise((r) => w(r, 50));",
  "const t = `${other} and ${name}`; void t;",
  "await Reflect.construct(Foo, args);",
  "const args = [(r: () => void) => r()]; await Reflect.construct(Promise, args);",
  "void new (class extends Base {})((r) => { setTimeout(r, 5); });",
  "void new Foo((r) => { setTimeout(r, 5); });",
  "class Q extends Base { constructor() { super((r) => setTimeout(r, 50)); } } void new Q();",
  "void Reflect.construct(Foo, [(r: () => void) => setTimeout(r, 50)]);",
  // a bind that names itself never reaches a timer, and must end the walk instead of overflowing the stack
  "const t = t.bind(null); t(1);",
  "function f(a = b.bind(null), b = a.bind(null)) { a(1); } f();",
];


const SPEC_IDS = ['local/no-sleep-promise', 'local/no-fixed-wait', 'no-restricted-syntax', 'no-restricted-imports'];
async function specLint(code: string, opts: { file?: string; off?: string } = {}) {
  const lint = opts.off
    ? new ESLint({ cwd: REPO, overrideConfig: [{ files: ['tests/**/*.ts'], rules: { [opts.off]: 'off' } }] })
    : eslint;
  const [res] = await lint.lintText(code, { filePath: path.join(REPO, opts.file ?? 'tests/snippet.test.ts') });
  // a snippet that does not parse reports nothing, so an allowed row would pass for the wrong reason
  expect(res.messages.filter(m => m.fatal), 'parse').toEqual([]);
  return res.messages.filter(m => m.ruleId && SPEC_IDS.includes(m.ruleId));
}

// Fastest of up to three runs: a loaded runner stalls one run, a slow walk slows all of them. `done` ends
// the loop early once the best time is good enough, so a failing walk is not run three times over.
async function fastest(code: string, done: (best: number) => boolean = () => false): Promise<number> {
  let best = Infinity;
  for (let i = 0; i < 3 && !done(best); i++) {
    const t0 = performance.now();
    await specLint(code);
    best = Math.min(best, performance.now() - t0);
  }
  return best;
}

describe('sleep rule spec table', () => {
  it.each(SPEC_BANNED)('class %i is reported by %s (%s): %s', async (_c, id, frag, code) => {
    const hits = await specLint(code);
    expect(hits.map(m => m.ruleId)).toContain(id);
    expect(hits.find(m => m.ruleId === id)!.message).toContain(frag);
  });
  it.each(SPEC_ALLOWED)('allows: %s', async code => {
    expect((await specLint(code)).map(m => `${m.ruleId}: ${m.message}`)).toEqual([]);
  });
  // One report per promise, however the walk got to its answer: a memoized answer that was cut short by a
  // cycle must not be reused for the next promise that reaches the same alias or helper.
  it.each([
    "const a: any = b ?? setTimeout; const b: any = a; await new Promise((r) => a(r, 50)); await new Promise((r) => b(r, 50));",
    "function a(f: () => void) { if (c) b(f); setTimeout(f, 50); } function b(f: () => void) { a(f); } await new Promise((r) => a(r)); await new Promise((r) => b(r));",
  ])('reports each of two promises on a cyclic alias or helper: %s', async code => {
    const hits = await specLint(code);
    expect(hits.map(m => m.ruleId)).toEqual(['local/no-sleep-promise', 'local/no-sleep-promise']);
  });
  it('has a row for every class 1 to 14', () => {
    const have = new Set(SPEC_BANNED.map(r => r[0]));
    for (let c = 1; c <= 14; c++) expect(have.has(c), `class ${c}`).toBe(true);
  });
  it('reports a plain sleep in a test file at any depth and none outside the glob', async () => {
    const sleep = 'await new Promise((r) => setTimeout(r, 50));';
    for (const file of ['tests/a.test.ts', 'tests/a/b/c.ts']) {
      expect((await specLint(sleep, { file })).length, file).toBeGreaterThan(0);
    }
    for (const file of ['src/lib/wait.ts', 'scripts/wait.ts']) expect(await specLint(sleep, { file }), file).toEqual([]);
  });
  // The planted violation: a row whose only report is one rule id goes quiet when that rule is off, so
  // deleting the rule from the config fails the suite instead of passing quietly.
  it.each(SPEC_IDS)('muting %s silences a row only it reports', async id => {
    const rows: string[] = [];
    for (const r of SPEC_BANNED) {
      if (r[1] === id && (await specLint(r[3])).every(m => m.ruleId === id)) rows.push(r[3]);
    }
    expect(rows.length, 'a row that only this rule reports').toBeGreaterThan(0);
    expect(await specLint(rows[0], { off: id })).toEqual([]);
  });
  // Cost: the end-of-file judgment is promises x timers x callback size, and a helper that calls
  // another helper twice is 2^n, unless each is computed once. Each test times two sizes and compares them,
  // so a slow runner moves both and a walk that grows too fast moves one.
  it('lints stored resolvers against timers in time that grows with the file, not its square', async () => {
    const stored = (n: number) => {
      const lines = ['const rs: Array<() => void> = [];'];
      for (let i = 0; i < n; i++) lines.push(`const p${i} = new Promise<void>((res) => { rs.push(res); });`);
      for (let i = 0; i < n; i++) lines.push(`setTimeout(() => { ${Array.from({ length: 25 }, (_, j) => `step${j}(${i}, log);`).join(' ')} }, 50);`);
      lines.push('await Promise.all([p0, p1]);');
      return lines.join('\n');
    };
    expect(await specLint(stored(100))).toEqual([]);
    const t100 = await fastest(stored(100));
    const t400 = await fastest(stored(400), ms => ms < 8 * t100);
    expect(t400 / t100).toBeLessThan(8);
    // and the same file does report once a timer runs the container
    expect((await specLint(stored(100) + '\nsetTimeout(() => rs.forEach((f) => f()), 50);')).length).toBeGreaterThan(0);
  });
  // every promise is reported here, and each report asks who else runs the container: that answer is built once
  it('judges every stored resolver of a container a timer runs without rebuilding the answer', async () => {
    const run = (n: number) => {
      const lines = ['const rs: Array<() => void> = [];'];
      for (let i = 0; i < n; i++) lines.push(`const p${i} = new Promise<void>((res) => { rs.push(res); });`);
      for (let i = 0; i < n; i++) lines.push(`setTimeout(() => { ${Array.from({ length: 25 }, (_, j) => `step${j}(${i}, log);`).join(' ')} }, 50);`);
      lines.push('setTimeout(() => rs.forEach((f) => f()), 50);', 'await Promise.all([p0, p1]);');
      return lines.join('\n');
    };
    expect((await specLint(run(100))).length).toBe(100);
    const t100 = await fastest(run(100));
    const t400 = await fastest(run(400), ms => ms < 8 * t100);
    expect(t400 / t100).toBeLessThan(8);
  });
  it('analyzes a helper that calls the next helper twice once per helper', async () => {
    const helpers = (n: number) => {
      const lines = ['function h0(f: () => void) { setTimeout(f, 5); }'];
      for (let i = 1; i <= n; i++) lines.push(`function h${i}(f: () => void) { h${i - 1}(f); h${i - 1}(f); }`);
      lines.push(`await new Promise<void>((r) => h${n}(r));`);
      return lines.join('\n');
    };
    const t16 = await fastest(helpers(16));
    const t20 = await fastest(helpers(20), ms => ms < 4 * t16 + 50);
    expect(t20).toBeLessThan(4 * t16 + 50);
    expect((await specLint(helpers(200))).length).toBeGreaterThan(0);
  });
  // each level of a nest is judged once, so the count does not depend on how deep it goes
  it('judges 100 nested promise executors, one report', async () => {
    let code = 'setTimeout(r99, 50);';
    for (let i = 99; i >= 0; i--) code = `new Promise<void>((r${i}) => { ${code} });`;
    expect((await specLint(`await ${code}`)).length).toBe(1);
  });
  // A resolver called under N nested callbacks is judged once per callback, not once per path to it: without
  // the memo on a function's flow the cost doubles with every level.
  it('judges a resolver under nested callbacks once per callback', async () => {
    const nest = (n: number) => {
      let body = 'r();';
      for (let i = 0; i < n; i++) body = `a0(() => { ${body} });`;
      return `declare function a0(f: () => void): void;\nawait new Promise<void>((r) => { ${body} setTimeout(r, 50); });`;
    };
    expect((await specLint(nest(12))).length).toBe(1);
    const t12 = await fastest(nest(12));
    const t24 = await fastest(nest(24), ms => ms < 4 * t12 + 50);
    expect(t24).toBeLessThan(4 * t12 + 50);
  });
  // Per-branch walking must not turn a chain of `a1 = a0 ?? a0` into 2^n steps
  it('walks a doubling chain of aliases once', async () => {
    const chain = (n: number, head: string) => `const a0 = ${head}; ${Array.from({ length: n }, (_, i) => `const a${i + 1} = a${i} ?? a${i};`).join(' ')} await new Promise((r) => a${n}(r, 50));`;
    const t16 = await fastest(chain(16, 'other'));
    const t20 = await fastest(chain(20, 'other'), ms => ms < 4 * t16 + 50);
    expect(t20).toBeLessThan(4 * t16 + 50);
    expect(await specLint(chain(200, 'other'))).toEqual([]);
    expect(await specLint(chain(200, 'setTimeout'))).not.toEqual([]);
  });
  // The text of a script held in a name is read once per name: `s1 = s0 + s0` doubles the walk at every level
  it('reads a doubling chain of script texts once', async () => {
    const chain = (n: number, head: string) => `const s0 = '${head}'; ${Array.from({ length: n }, (_, i) => `const s${i + 1} = s${i} + s${i};`).join(' ')} await page.evaluate(s${n});`;
    const t16 = await fastest(chain(16, 'document.title'));
    const t20 = await fastest(chain(20, 'document.title'), ms => ms < 4 * t16 + 50);
    expect(t20).toBeLessThan(4 * t16 + 50);
    expect(await specLint(chain(200, 'document.title'))).toEqual([]);
    expect(await specLint(chain(200, 'setTimeout(() => 0, 5)'))).not.toEqual([]);
  });
  // 200 reverse assignments and 200 calls into a 200-line helper (spec 5.9)
  it('lints a 200-step reverse assignment chain and 200 calls into a long helper in under a second', async () => {
    const decl = Array.from({ length: 200 }, (_, i) => `let c${i}: any;`).join(' ');
    const asg = Array.from({ length: 199 }, (_, i) => `c${198 - i} = c${199 - i};`).join(' ');
    const helper = `function long(f: () => void) { ${Array.from({ length: 200 }, (_, i) => `log(${i}, f);`).join(' ')} }`;
    const calls = Array.from({ length: 200 }, () => 'long(() => undefined);').join(' ');
    const code = `${decl} c199 = Promise.withResolvers<void>(); ${asg} setTimeout(c0.resolve, 5); ${helper} ${calls}`;
    expect((await specLint(code)).length).toBeGreaterThan(0);
    expect(await fastest(code, ms => ms < 1000)).toBeLessThan(1000);
  });
  // A crash inside a rule aborts the lint for every file, so the exit code is what matters here
  it.each([
    'const t = t.bind(null); t(1);\n',
    'function f(a = b.bind(null), b = a.bind(null)) { a(1); }\nf();\n',
    'const [a] = [b.bind(null)], b = a.bind(null);\na(1);\n',
  ])('exits 0 on a bind that names itself: %s', code => {
    const run = spawnSync(process.execPath, [path.join(REPO, 'node_modules/eslint/bin/eslint.js'), '--stdin', '--stdin-filename', 'tests/snippet.test.ts'], { cwd: REPO, input: code, encoding: 'utf8' });
    expect(run.stdout + run.stderr).toBe('');
    expect(run.status).toBe(0);
  });
  // The race fallback is the one exemption: the resolver is also handed to something else.
  // A subscription (on, once, then...) or a container something other than a timer calls is the handoff;
  // `noop(r)` is not.
  it('keeps the race-fallback exemption and names its edge', async () => {
    expect((await specLint('new Promise((r) => { noop(r); setTimeout(r, 50); });')).length).toBeGreaterThan(0);
    expect(await specLint("new Promise((r) => { server.on('x', r); setTimeout(r, 5000); });")).toEqual([]);
    expect((await specLint('new Promise((r) => { setTimeout(r, 50); });')).length).toBeGreaterThan(0);
  });
});

// The shared spec table, every row: a shape the rule must report (by the rule id and message it names) or must
// leave alone.
describe('shared spec table', () => {
  it.each(SPEC_CASES_BANNED)('%s (class %i) is reported by %s (%s)', async (_id, _cls, rule, frag, code) => {
    const hits = await specLint(code);
    expect(hits.map(m => m.ruleId)).toContain(rule);
    expect(hits.find(m => m.ruleId === rule)!.message).toContain(frag);
  });
  it.each(SPEC_CASES_ALLOWED)('%s is not reported', async (_id, code) => {
    expect((await specLint(code)).map(m => `${m.ruleId}: ${m.message}`)).toEqual([]);
  });
  it('has a banned row for every class 1 to 14 and no row twice', () => {
    const have = new Set(SPEC_CASES_BANNED.map(r => r[1]));
    for (let c = 1; c <= 14; c++) expect(have.has(c), `class ${c}`).toBe(true);
    const ids = [...SPEC_CASES_BANNED.map(r => r[0]), ...SPEC_CASES_ALLOWED.map(r => r[0])];
    expect(new Set(ids).size).toBe(ids.length);
  });
});
