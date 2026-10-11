// @vitest-environment node
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ESLint, type Linter } from 'eslint';
import { describe, it, expect } from 'vitest';
import tsParser from '@typescript-eslint/parser';
import { SIGNALS, withNoSleep } from '../../eslint/no-sleep.js';
import { harnessAllowed, harnessBanned } from './no-sleep-harness-shapes.js';
import { ALIAS, API, PROMISE, SYNTAX, acceptedFalsePositives, allowedCases, bannedCases, gapCases } from './no-sleep-cases.js';

// The sleep ban lives in eslint/no-sleep.js, which eslint.config.js wraps its blocks in, so these run that config on snippets:
// every banned spec row must report, and the allowed rows (deadline guards and other lookalikes) must not.
// What it still misses, and the false positives it accepts, are the Known gaps comment above noSleepPromise in that file.
const eslint = new ESLint({ overrideConfigFile: 'eslint.config.js' });

const BAN_RULES = new Set([PROMISE, SYNTAX, ALIAS, API]);

async function sleepMessages(code: string, filePath = 'tests/lint/snippet.ts', linter = eslint): Promise<Linter.LintMessage[]> {
  const messages = (await linter.lintText(code, { filePath }))[0]?.messages ?? [];
  // A snippet that does not parse reports no rule at all, so an "allowed" case would pass
  // and a "banned" one would only fail with a confusing empty list.
  expect(messages.filter((m) => m.fatal), `snippet does not parse: ${code}`).toEqual([]);
  // Only the sleep-ban rules count: an unused-variable report must not pass for a ban.
  return messages.filter((m) => BAN_RULES.has(m.ruleId ?? ''));
}

const ruleIds = async (code: string, filePath?: string) => (await sleepMessages(code, filePath)).map((m) => m.ruleId ?? '');

// [code, the rule that must report it]. Asserting the rule keeps a shape from
// passing because some other ban happened to catch it.
const banned: Record<string, [string, string]> = {
  'bare setTimeout in an arrow executor': ['await new Promise((r) => setTimeout(r, 50));', PROMISE],
  'bare setTimeout in a block executor': ['await new Promise((r) => { setTimeout(r, 50); });', PROMISE],
  'globalThis.setTimeout': ['await new Promise((r) => globalThis.setTimeout(r, 50));', PROMISE],
  'window.setTimeout in a block': ['await new Promise((r) => { window.setTimeout(r, 50); });', PROMISE],
  'globalThis["setTimeout"]': ["await new Promise((r) => globalThis['setTimeout'](r, 50));", PROMISE],
  'timer nested in the executor': ['await new Promise((r) => { if (true) { setTimeout(r, 50); } });', PROMISE],
  'resolve inside a timer that never rejects': ['await new Promise((res, rej) => setTimeout(() => res(), 50));', PROMISE],
  'resolve then reject in one timer callback': [
    "await new Promise((res, rej) => { setTimeout(() => { res(); rej(new Error('late')); }, 50); });",
    PROMISE,
  ],
  'resolve then reject, arrow executor': [
    "await new Promise((res, rej) => setTimeout(() => { res(); rej(new Error('late')); }, 50));",
    PROMISE,
  ],
  'try resolve, catch reject': [
    'await new Promise((res, rej) => { setTimeout(() => { try { res(); } catch (e) { rej(e); } }, 50); });',
    PROMISE,
  ],
  'reject then resolve in one timer callback': [
    "await new Promise((res, rej) => { setTimeout(() => { rej(new Error('x')); res(); }, 50); });",
    PROMISE,
  ],
  'conditional reject, unconditional resolve': [
    'await new Promise((r, rej) => { setTimeout(() => { if (never) rej(new Error("x")); r(); }, 50); });',
    PROMISE,
  ],
  'resolve handed to a helper beside reject': [
    "await new Promise((res, rej) => { setTimeout(() => { done(res); rej(new Error('x')); }, 50); });",
    PROMISE,
  ],
  'resolve passed by reference to a timer': ['await new Promise((res, rej) => setTimeout(res, 50));', PROMISE],
  'setTimeout aliased, then called in an executor': [
    'const wait = setTimeout; await new Promise((r) => wait(r, 50));',
    ALIAS,
  ],
  'globalThis.setTimeout aliased': ['const wait = globalThis.setTimeout; wait(() => undefined, 50);', ALIAS],
  'setTimeout reassigned': ['let wait; wait = setTimeout; wait(() => undefined, 50);', ALIAS],
  'restore into a non-host object slot': [
    'const orig = setTimeout; const h = {} as { setTimeout?: unknown }; h.setTimeout = orig;',
    ALIAS,
  ],
  'restore through a Map.set': ["const orig = setTimeout; const m = new Map(); m.set('setTimeout', orig);", ALIAS],
  'restore through a stubGlobal that is not vi': ["const orig = setTimeout; other.stubGlobal('setTimeout', orig);", ALIAS],
  'saved timer as a stray stubGlobal argument': ["const orig = setTimeout; vi.stubGlobal('setTimeout', () => 0, orig);", ALIAS],
  'timer parked in a non-host slot': ['const h = {} as { setTimeout?: unknown }; h.setTimeout = setTimeout;', ALIAS],
  'setTimeout destructured': ['const { setTimeout: wait } = globalThis; wait(() => undefined, 50);', ALIAS],
  'setTimeout passed as a value': ['run(setTimeout);', SYNTAX],
  'promisify(setTimeout)': ["import { promisify } from 'node:util'; const wait = promisify(setTimeout);", SYNTAX],
  'awaited promisify(setTimeout)(50)': ["import { promisify } from 'node:util'; await promisify(setTimeout)(50);", SYNTAX],
  'util.promisify(setTimeout)': ["import util from 'node:util'; const wait = util.promisify(setTimeout);", SYNTAX],
  'promisify(globalThis.setTimeout)': [
    "import { promisify } from 'node:util'; const wait = promisify(globalThis.setTimeout);",
    ALIAS,
  ],
  'static timers/promises import': ["import { setTimeout as wait } from 'node:timers/promises';", SYNTAX],
  'bare timers/promises import': ["import { setTimeout as wait } from 'timers/promises';", SYNTAX],
  'dynamic timers/promises import': ["const { setTimeout: wait } = await import('node:timers/promises');", API],
  'dynamic import bound to a name': ["const t = await import('node:timers/promises'); await t.setTimeout(5);", API],
  'dynamic import of bare timers/promises, awaited call': ["await (await import('timers/promises')).setTimeout(5);", API],
  'setTimeout destructured from itself': ['const { call } = setTimeout; call(globalThis, () => undefined, 50);', ALIAS],
  'self.setTimeout in an executor': ['await new Promise((r) => self.setTimeout(r, 50));', PROMISE],
  'global.setTimeout in an executor': ['await new Promise((r) => global.setTimeout(r, 50));', PROMISE],
  'globalThis["setInterval"] in an executor': ["await new Promise((r) => globalThis['setInterval'](r, 5));", PROMISE],
  'window.setInterval in an executor': ['await new Promise((r) => window.setInterval(r, 5));', PROMISE],
  'saved timer copy is called': ['const orig = globalThis.setTimeout; orig(() => undefined, 50);', ALIAS],
  'saved timer copy is restored and also called': [
    'const orig = setTimeout; setTimeout = (() => 0) as never; orig(() => undefined, 5); setTimeout = orig;',
    ALIAS,
  ],
  'saved timer copy is passed on': ['const orig = setTimeout; run(orig);', ALIAS],
  'timer copy stored on an object': ['const box = {} as { wait?: unknown }; box.wait = setTimeout;', ALIAS],
  'setInterval resolving in an executor': [
    'await new Promise<void>((r) => { const id = setInterval(() => { clearInterval(id); r(); }, 5); });',
    PROMISE,
  ],
  'setInterval by reference in an executor': ['await new Promise((r) => globalThis.setInterval(r, 5));', PROMISE],
  'outer variable resolve called from a timer': [
    'let r: () => void = () => undefined; const p = new Promise<void>((res) => { r = res; }); setTimeout(() => r(), 50); await p;',
    PROMISE,
  ],
  'outer variable resolve handed to a timer': [
    'let r: () => void = () => undefined; const p = new Promise<void>((res) => { r = res; }); setTimeout(r, 50); await p;',
    PROMISE,
  ],
  'resolve stored on an object, timer elsewhere': [
    'const d = {} as { resolve: () => void }; const p = new Promise<void>((res) => { d.resolve = res; }); setTimeout(() => { d.resolve(); }, 50); await p;',
    PROMISE,
  ],
  'resolve pushed to an array, timer elsewhere': [
    'const rs: Array<() => void> = []; const p = new Promise<void>((res) => { rs.push(res); }); setTimeout(() => rs[0](), 50); await p;',
    PROMISE,
  ],
  'resolve pushed, timer drains the array': [
    'const rs: Array<() => void> = []; const p = new Promise<void>((res) => rs.push(res)); setTimeout(() => rs.forEach((f) => f()), 50); await p;',
    PROMISE,
  ],
  'resolve stashed through a helper that pushes': [
    'const rs: Array<() => void> = []; const stash = (f: () => void) => { rs.push(f); }; const p = new Promise<void>((res) => stash(res)); setTimeout(() => rs.forEach((f) => f()), 50); await p;',
    PROMISE,
  ],
  'resolve stashed through a helper that assigns': [
    'let saved: () => void = () => undefined; function stash(f: () => void) { saved = f; } const p = new Promise<void>((res) => { stash(res); }); setTimeout(saved, 50); await p;',
    PROMISE,
  ],
  'resolve stashed as the second helper argument': [
    'const rs: Array<() => void> = []; const stash = (_n: number, f: () => void) => { rs.push(f); }; const p = new Promise<void>((res) => stash(1, res)); setTimeout(() => rs[0](), 50); await p;',
    PROMISE,
  ],
  'resolve stashed two helpers deep': [
    'let saved: () => void = () => undefined; function keep(f: () => void) { saved = f; } function stash(f: () => void) { keep(f); } const p = new Promise<void>((res) => stash(res)); setTimeout(() => saved(), 50); await p;',
    PROMISE,
  ],
  'resolve stored on this in a class': [
    'class W { q: Array<() => void> = []; go() { const p = new Promise<void>((res) => { this.q.push(res); }); setTimeout(() => this.q[0](), 50); return p; } }',
    PROMISE,
  ],
  'Promise.withResolvers, resolve destructured': [
    'const { promise, resolve } = Promise.withResolvers<void>(); setTimeout(resolve, 50); await promise;',
    PROMISE,
  ],
  'Promise.withResolvers, resolve renamed': [
    'const { promise, resolve: done } = Promise.withResolvers<void>(); setTimeout(() => done(), 50); await promise;',
    PROMISE,
  ],
  'Promise.withResolvers, object kept': [
    'const d = Promise.withResolvers<void>(); setTimeout(() => d.resolve(), 50); await d.promise;',
    PROMISE,
  ],
  'Promise.withResolvers, resolve handed to a timer': [
    'const d = Promise.withResolvers<void>(); setTimeout(d.resolve, 50); await d.promise;',
    PROMISE,
  ],
  'named executor that is a sleep': ['function waitFn(r: () => void) { setTimeout(r, 50); } await new Promise(waitFn);', PROMISE],
  'named arrow executor that is a sleep': ['const waitFn = (r: () => void) => setTimeout(r, 50); await new Promise(waitFn);', PROMISE],
  'cast host before .setTimeout': ['await new Promise((r) => (globalThis as any).setTimeout(r, 50));', PROMISE],
  'timer callee behind as': [
    'type Wait = (cb: () => void, ms: number) => void; await new Promise((r) => (setTimeout as Wait)(r, 50));',
    PROMISE,
  ],
  'timer callee behind !': ['await new Promise((r) => setTimeout!(r, 50));', PROMISE],
  'timer callee behind a type assertion': [
    'type Wait = (cb: () => void, ms: number) => void; await new Promise((r) => (<Wait>setTimeout)(r, 50));',
    PROMISE,
  ],
  'timer callee behind satisfies': [
    'type Wait = (cb: () => void, ms: number) => void; await new Promise((r) => (setTimeout satisfies Wait)(r, 50));',
    PROMISE,
  ],
  'setTimeout cast, then aliased': [
    'type Wait = (cb: () => void, ms: number) => void; const w = setTimeout as Wait; await new Promise((r) => w(r, 50));',
    ALIAS,
  ],
  'setTimeout! aliased': ['const w = setTimeout!; w(() => undefined, 50);', ALIAS],
  'type-asserted setTimeout aliased': ['const w = <typeof setTimeout>setTimeout; w(() => undefined, 50);', ALIAS],
  'cast host timer aliased': ['const w = (globalThis as any).setTimeout; w(() => undefined, 50);', ALIAS],
  'alias through ||': ['const w = (globalThis as any).fake || setTimeout; w(() => undefined, 50);', ALIAS],
  'alias through ??': ['const w = (globalThis as any).fake ?? setTimeout; w(() => undefined, 50);', ALIAS],
  'alias through a conditional': ['const w = pick ? setTimeout : other; w(() => undefined, 50);', ALIAS],
  'assigned through ||': ['let w; w = (globalThis as any).fake || setTimeout; w(() => undefined, 50);', ALIAS],
  'assigned through a conditional': ['let w; w = pick ? other : setTimeout; w(() => undefined, 50);', ALIAS],
  'executor read off an object': ['await new Promise(obj.fn);', PROMISE],
  'executor built by a call': ['await new Promise(makeWait(50));', PROMISE],
  'executor spread from arguments': ['await new Promise(...args);', PROMISE],
  'cast imported executor': ["import { waitFn } from './helpers'; await new Promise(waitFn as never);", PROMISE],
  'cast inline sleep executor': ['await new Promise(((r: () => void) => setTimeout(r, 50)) as never);', PROMISE],
  'executor handed in as a parameter': [
    'function wait(exec: (r: () => void) => void) { return new Promise(exec); } await wait((r) => setTimeout(r, 50));',
    PROMISE,
  ],
  'imported executor cannot be read': ["import { waitFn } from './helpers'; await new Promise(waitFn);", PROMISE],
  'timers.promises.setTimeout': ["import * as t from 'node:timers'; await t.promises.setTimeout(50);", SYNTAX],
  'promises imported from node:timers': ["import { promises } from 'node:timers'; await promises.setTimeout(50);", SYNTAX],
  'promises imported under another name': ["import { promises as tp } from 'node:timers'; const wait = tp;", SYNTAX],
  'timers.promises["setTimeout"]': ["import timers from 'node:timers'; await timers.promises['setTimeout'](50);", SYNTAX],
  'require of timers/promises': ["const { setTimeout: wait } = require('node:timers/promises');", API],
  'require of bare timers/promises': ["const wait = require('timers/promises');", API],
  'setInterval destructured, used in an executor': [
    'const { setInterval: wait } = globalThis; await new Promise((r) => wait(r, 5));',
    ALIAS,
  ],
  'setInterval passed as a value': ['run(setInterval);', SYNTAX],
  'promisify(setInterval)': ["import { promisify } from 'node:util'; const wait = promisify(setInterval);", SYNTAX],
  'setInterval aliased': ['const wait = setInterval; await new Promise((r) => wait(r, 5));', ALIAS],
  'globalThis.setInterval aliased': ['const wait = globalThis.setInterval; wait(() => undefined, 5);', ALIAS],
  'setInterval alias through ||': ['const w = (globalThis as any).fake || setInterval; w(() => undefined, 5);', ALIAS],
  'setInterval parked in a non-host slot': ['const h = {} as { setInterval?: unknown }; h.setInterval = setInterval;', ALIAS],
  'Promise behind a cast': ['await new (Promise as never)((r: () => void) => setTimeout(r, 50));', PROMISE],
  'Promise behind a type assertion': ['await new (<PromiseConstructor>Promise)((r) => setTimeout(r, 50));', PROMISE],
  'Promise on globalThis': ['await new globalThis.Promise((r) => setTimeout(r, 50));', PROMISE],
  'withResolvers behind a cast': [
    'const d = (Promise as any).withResolvers(); setTimeout(() => d.resolve(), 50); await d.promise;',
    PROMISE,
  ],
  'node:timers namespace import, promises.setInterval': [
    "import * as t from 'node:timers'; for await (const _ of t.promises.setInterval(50)) break;",
    SYNTAX,
  ],
  'node:timers default import, promises.setInterval': [
    "import timers from 'node:timers'; for await (const _ of timers.promises.setInterval(50)) break;",
    SYNTAX,
  ],
  'timers.promises.scheduler.wait': ["import * as t from 'node:timers'; await t.promises.scheduler.wait(50);", SYNTAX],
  'setTimeout imported from node:timers': [
    "import { setTimeout as later } from 'node:timers'; await new Promise((r) => later(r, 50));",
    SYNTAX,
  ],
  'bare timers import': ["import { setInterval as tick } from 'timers'; tick(() => undefined, 5);", SYNTAX],
  'dynamic import of node:timers': ["const t = await import('node:timers'); t.setTimeout(() => undefined, 5);", API],
  'require of node:timers': ["const t = require('node:timers'); t.setTimeout(() => undefined, 5);", API],
  'require of bare timers': ["const { setTimeout: wait } = require('timers');", API],
  'process.getBuiltinModule of timers': ["const t = process.getBuiltinModule('node:timers'); t?.setTimeout(() => undefined, 5);", API],
  'setTimeout.call in an executor': ['await new Promise((r) => setTimeout.call(globalThis, r, 50));', PROMISE],
  'setTimeout.apply in an executor': ['await new Promise((r) => setTimeout.apply(globalThis, [r, 50]));', PROMISE],
  'setTimeout.bind called in an executor': ['await new Promise((r) => setTimeout.bind(globalThis)(r, 50));', PROMISE],
  'setInterval.call in an executor': ['await new Promise((r) => setInterval.call(globalThis, r, 5));', PROMISE],
  'globalThis.setTimeout.call in an executor': ['await new Promise((r) => globalThis.setTimeout.call(globalThis, r, 50));', PROMISE],
  'cast setTimeout.call in an executor': ['await new Promise((r) => (setTimeout as any).call(globalThis, r, 50));', PROMISE],
  'setTimeout bound, then aliased': ['const w = setTimeout.bind(globalThis); await new Promise((r) => w(r, 50));', ALIAS],
  'timer stored as an object property value': ['const t = { wait: setTimeout }; t.wait(() => undefined, 50);', ALIAS],
  'timer stored under a host member as an object value': ['const t = { wait: globalThis.setInterval };', ALIAS],
  'timer in a shorthand object property': ['const t = { setTimeout };', ALIAS],
  'timer behind a conditional in an object value': ['const t = { wait: pick ? setTimeout : other };', ALIAS],
  'timer in an array': ['const t = [setTimeout]; t[0](() => undefined, 50);', ALIAS],
  'timer as a parameter default': ['async function f(w = setTimeout) { await new Promise((r) => w(r, 50)); }', ALIAS],
  'timer as a destructuring default': ['const { w = setTimeout } = opts;', ALIAS],
  'timer as a class field': ['class A { wait = setTimeout; }', ALIAS],
  'setTimeout destructured by a string key': ["const { 'setTimeout': wait } = globalThis; wait(() => undefined, 50);", ALIAS],
  'setInterval destructured by a computed key': ["const { ['setInterval']: wait } = globalThis; wait(() => undefined, 5);", ALIAS],
  'resolve by reference behind a cast': ['await new Promise((res, rej) => setTimeout(res as never, 50));', PROMISE],
  'defaulted resolve param, resolve then reject': [
    "await new Promise((res = undefined, rej) => { setTimeout(() => { res(); rej(new Error('x')); }, 50); });",
    PROMISE,
  ],
  'destructured first param, reject in the timer': [
    "await new Promise(({ a }: any, rej) => { setTimeout(() => { a(); rej(new Error('x')); }, 50); });",
    PROMISE,
  ],
  'rest first param, reject in the timer': [
    "await new Promise((...args: any[]) => { setTimeout(() => { args[0](); args[1](new Error('x')); }, 50); });",
    PROMISE,
  ],
  'resolve leaked from a defaulted param': [
    'let r: () => void = () => undefined; const p = new Promise<void>((res = r) => { r = res; }); setTimeout(() => r(), 50); await p;',
    PROMISE,
  ],
  'resolve renamed by a const, then reject on the side': [
    "await new Promise((res, rej) => { const done = res; setTimeout(() => { done(); if (0) rej(new Error('x')); }, 50); });",
    PROMISE,
  ],
  'resolve renamed twice, then reject on the side': [
    "await new Promise((res, rej) => { const a = res; const b = a; setTimeout(() => { b(); if (0) rej(new Error('x')); }, 50); });",
    PROMISE,
  ],
  'resolve renamed by assignment, then reject on the side': [
    "await new Promise((res, rej) => { let done; done = res; setTimeout(() => { done(); if (0) rej(new Error('x')); }, 50); });",
    PROMISE,
  ],
  'resolve renamed, then stored outside': [
    'let r: () => void = () => undefined; const p = new Promise<void>((res) => { const x = res; r = x; }); setTimeout(() => r(), 50); await p;',
    PROMISE,
  ],
  'resolve renamed, then pushed': [
    'const rs: Array<() => void> = []; const p = new Promise<void>((res) => { const x = res; rs.push(x); }); setTimeout(() => rs[0](), 50); await p;',
    PROMISE,
  ],
  'resolve renamed, then stashed through a helper': [
    'let saved: () => void = () => undefined; function stash(f: () => void) { saved = f; } const p = new Promise<void>((res) => { const x = res as () => void; stash(x); }); setTimeout(() => saved(), 50); await p;',
    PROMISE,
  ],
  'Promise aliased to a const': ['const P = Promise; await new P((r) => setTimeout(r, 50));', PROMISE],
  'globalThis.Promise aliased to a const': ['const P = globalThis.Promise; await new P((r) => setTimeout(r, 50));', PROMISE],
  'cast Promise aliased to a const': ['const P = Promise as PromiseConstructor; await new P((r) => setTimeout(r, 50));', PROMISE],
  'aliased Promise with opaque executor': ["import { waitFn } from './helpers'; const P = Promise; await new P(waitFn);", PROMISE],
  'withResolvers through an aliased Promise': [
    'const P = Promise; const d = P.withResolvers<void>(); setTimeout(() => d.resolve(), 50); await d.promise;',
    PROMISE,
  ],
  'withResolvers assigned to a declared variable': [
    'let d: ReturnType<typeof Promise.withResolvers<void>>; d = Promise.withResolvers<void>(); setTimeout(() => d.resolve(), 50); await d.promise;',
    PROMISE,
  ],
  'withResolvers assigned to a member': [
    'const box = {} as { d: ReturnType<typeof Promise.withResolvers<void>> }; box.d = Promise.withResolvers<void>(); setTimeout(() => box.d.resolve(), 50); await box.d.promise;',
    PROMISE,
  ],
  'withResolvers destructured by assignment': [
    'let resolve: () => void = () => undefined; let promise: Promise<void>; ({ promise, resolve } = Promise.withResolvers<void>()); setTimeout(resolve, 50); await promise;',
    PROMISE,
  ],
  'leaked resolve called through parens': [
    'const d = Promise.withResolvers<void>(); setTimeout(() => (d).resolve(), 50); await d.promise;',
    PROMISE,
  ],
  'leaked resolve called with ?.': [
    'const d = Promise.withResolvers<void>(); setTimeout(() => d?.resolve(), 50); await d.promise;',
    PROMISE,
  ],
  'leaked resolve called behind a cast': [
    'const d = Promise.withResolvers<void>(); setTimeout(() => (d as any).resolve(), 50); await d.promise;',
    PROMISE,
  ],
  'leaked resolve called by a string key': [
    "const d = {} as { resolve: () => void }; const p = new Promise<void>((res) => { d.resolve = res; }); setTimeout(() => d['resolve'](), 50); await p;",
    PROMISE,
  ],
  'resolve stored by index, timer drains the array': [
    'const rs: Array<() => void> = []; const p = new Promise<void>((res) => { rs[0] = res; }); setTimeout(() => rs.forEach((f) => f()), 50); await p;',
    PROMISE,
  ],
  'resolve stored by a variable index, timer calls another index': [
    'const rs: Array<() => void> = []; let i = 0; let j = 0; const p = new Promise<void>((res) => { rs[i] = res; }); setTimeout(() => rs[j](), 50); await p;',
    PROMISE,
  ],
  'resolve stored on this behind parens': [
    'class W { r: () => void = () => undefined; go() { const p = new Promise<void>((res) => { this.r = res; }); setTimeout(() => (this).r(), 50); return p; } }',
    PROMISE,
  ],
  'sleep helper': ['const sleep = (ms: number) => ms;', SYNTAX],
};

const allowed: Record<string, string> = {
  'deadline guard, reject arrow': "await new Promise((r, reject) => { setTimeout(() => reject(new Error('late')), 50); });",
  'deadline guard, renamed reject': "await new Promise((r, rej) => { setTimeout(() => rej(new Error('late')), 50); });",
  'deadline guard, block body': "await new Promise((r, reject) => { setTimeout(() => { reject(new Error('late')); }, 50); });",
  'deadline guard, arrow executor': "await new Promise((r, rej) => setTimeout(() => rej(new Error('late')), 50));",
  'deadline guard, globalThis.setTimeout': "await new Promise((r, rej) => { globalThis.setTimeout(() => rej(new Error('late')), 50); });",
  'deadline guard, reject by reference': 'await new Promise((r, rej) => setTimeout(rej, 50));',
  'deadline guard touching a property named like resolve':
    "const log = { resolve: 0 }; await new Promise((resolve, reject) => { setTimeout(() => { log.resolve = 1; reject(new Error('late')); }, 50); });",
  'deadline guard with an object key named like resolve':
    "await new Promise((resolve, reject) => { setTimeout(() => { reject(new Error('late')); void { resolve: 1 }; }, 50); });",
  'Promise subclass-shaped name is not Promise': 'class MyPromise { constructor(f: (r: () => void) => void) { f(() => undefined); } } void new MyPromise((r) => { r(); });',
  'Promise on a non-host receiver': 'await new lib.Promise((r) => { setTimeout(r, 50); });',
  'deadline guard, conditional reject only': "await new Promise((r, rej) => { setTimeout(() => { if (never) rej(new Error('x')); }, 50); });",
  'same name, another scope, block variable':
    'let r: () => void = () => undefined; const p = new Promise<void>((res) => { r = res; }); { const r = () => undefined; setTimeout(() => r(), 50); } await p;',
  'same name, another scope, timer parameter':
    'let r: () => void = () => undefined; const p = new Promise<void>((res) => { r = res; }); setTimeout((r: () => void) => r(), 50); await p;',
  'same name, another scope, function parameter':
    'let r: () => void = () => undefined; const p = new Promise<void>((res) => { r = res; }); function later(r: () => void) { setTimeout(() => r(), 50); } await p;',
  'same name as a property in the timer':
    'let r: () => void = () => undefined; const p = new Promise<void>((res) => { r = res; }); setTimeout(() => ({ r: 1 }).r, 50); await p;',
  'resolve pushed, timer unrelated to the array':
    'const rs: Array<() => void> = []; const other = [1]; const p = new Promise<void>((res) => { rs.push(res); }); setTimeout(() => other.pop(), 50); await p;',
  'resolve passed where the helper stores another parameter':
    'const rs: Array<unknown> = []; const stash = (f: () => void, n: number) => { rs.push(n); }; const p = new Promise<void>((res) => stash(res, 1)); setTimeout(() => rs.pop(), 50); await p;',
  'recursive helper that never stores it':
    'function spin(f: () => void): void { spin(f); } const p = new Promise<void>((res) => { if (false) spin(res); res(); }); setTimeout(() => undefined, 50); await p;',
  'resolve passed to a helper that only calls it':
    'const fire = (f: () => void) => { f(); }; const p = new Promise<void>((res) => fire(res)); setTimeout(() => undefined, 50); await p;',
  'Promise.withResolvers, reject from a timer':
    "const d = Promise.withResolvers<void>(); setTimeout(() => d.reject(new Error('late')), 50); await d.promise.catch(() => undefined);",
  'Promise.withResolvers, reject destructured':
    "const { promise, reject } = Promise.withResolvers<void>(); setTimeout(() => reject(new Error('late')), 50); await promise.catch(() => undefined);",
  'Promise.withResolvers, no timer': 'const d = Promise.withResolvers<void>(); queueMicrotask(() => d.resolve()); await d.promise;',
  'deadline guard in a named executor': 'function guard(_r: () => void, rej: (e: Error) => void) { setTimeout(() => rej(new Error("late")), 50); } await new Promise(guard);',
  'deadline guard in a named arrow executor':
    'const guard = (_r: () => void, rej: (e: Error) => void) => setTimeout(() => rej(new Error("late")), 50); await new Promise(guard);',
  'deadline guard in a cast inline executor':
    "await new Promise(((_r: () => void, rej: (e: Error) => void) => setTimeout(() => rej(new Error('late')), 50)) as never);",
  'setTimeout on a receiver that is not a global host': 'await new Promise((r) => { server.setTimeout(r, 50); });',
  'setTimeout on a nested receiver': 'await new Promise((r) => { a.b.setTimeout(r, 50); });',
  'setTimeout on a call result': 'await new Promise((r) => { getServer().setTimeout(r, 50); });',
  'another method on a global host': 'await new Promise((r) => { globalThis.queueMicrotask(r); });',
  'computed key that is not a literal': 'await new Promise((r) => { globalThis[name](r, 50); });',
  'outer reject called from a timer': "let rej: (e: Error) => void = () => undefined; const p = new Promise<void>((_r, j) => { rej = j; }); setTimeout(() => rej(new Error('late')), 50); await p.catch(() => undefined);",
  'resolve kept for an event, no timer': 'let r: () => void = () => undefined; const p = new Promise<void>((res) => { r = res; }); queueMicrotask(() => r()); await p;',
  'save and restore the real timer': 'const orig = globalThis.setTimeout; globalThis.setTimeout = (() => 0) as never; globalThis.setTimeout = orig;',
  'save and restore through stubGlobal': "import { vi } from 'vitest'; const orig = setTimeout; vi.stubGlobal('setTimeout', () => 0); vi.stubGlobal('setTimeout', orig);",
  'save and restore, bare setTimeout': 'const orig = setTimeout; setTimeout = (() => 0) as never; setTimeout = orig;',
  'save and restore setInterval': 'const orig = setInterval; setInterval = (() => 0) as never; setInterval = orig;',
  'save and restore setInterval through stubGlobal': "import { vi } from 'vitest'; const orig = setInterval; vi.stubGlobal('setInterval', () => 0); vi.stubGlobal('setInterval', orig);",
  'expect on the real setInterval': 'expect(setInterval).toBeDefined();',
  'restore on window': 'const orig = window.setTimeout; window.setTimeout = (() => 0) as never; window.setTimeout = orig;',
  'restore on self': 'const orig = self.setTimeout; self.setTimeout = (() => 0) as never; self.setTimeout = orig;',
  'restore on global': 'const orig = global.setTimeout; global.setTimeout = (() => 0) as never; global.setTimeout = orig;',
  'restore on globalThis computed': "const orig = setTimeout; globalThis['setTimeout'] = (() => 0) as never; globalThis['setTimeout'] = orig;",
  'expect on the real timer': 'expect(setTimeout).toBeDefined(); expect(globalThis.setTimeout).toBeTypeOf("function");',
  'mocked() on the timer': "import { vi } from 'vitest'; vi.mocked(setTimeout).mockClear(); vi.isMockFunction(setTimeout);",
  'timer outside a promise': 'const id = setTimeout(() => undefined, 50); clearTimeout(id);',
  'fake timers': "import { vi } from 'vitest'; vi.useFakeTimers(); vi.advanceTimersByTime(50);",
  'fake timers faked by name': "import { vi } from 'vitest'; vi.useFakeTimers({ toFake: ['setTimeout'] });",
  'import from a local file named timers': "import { tick } from './timers'; tick();",
  'import of a package that only starts with timers': "import { tick } from 'timers-helper'; tick();",
  'call on a method that is not the timer': 'await new Promise((r) => { server.setTimeout.call(server, r, 50); });',
  'bind on a function that is not the timer': 'const f = handler.bind(globalThis); f();',
  'config value named setTimeout read off a non-host object': 'const ms = opts.setTimeout; expect(ms).toBe(5);',
  'config value named setInterval read off a non-host object': "const ms = opts['setInterval']; expect(ms).toBe(5);",
  'non-host timer member reassigned': 'let ms; ms = server.setTimeout; expect(ms).toBe(5);',
  'object key named setTimeout holding a number': 'const t = { setTimeout: 5, setInterval: 10 }; expect(t).toBeDefined();',
  'object key named setTimeout holding a stub': "import { vi } from 'vitest'; const t = { setTimeout: vi.fn() }; expect(t).toBeDefined();",
  'array of timer names': "const t = ['setTimeout', 'setInterval']; expect(t).toBeDefined();",
  'parameter default that is not the timer': 'function f(w = 5) { return w; } f();',
  'destructuring another key by string': "const { 'queueMicrotask': q } = globalThis; q(() => undefined);",
  'deadline guard, reject by reference behind a cast': 'await new Promise((r, rej) => setTimeout(rej as never, 50));',
  'deadline guard, reject by reference behind a non-null': 'await new Promise((r, rej) => setTimeout(rej!, 50));',
  'deadline guard, callback behind a cast': "await new Promise((r, rej) => setTimeout((() => rej(new Error('late'))) as never, 50));",
  'deadline guard with a defaulted reject param': "await new Promise((r, rej = (e: Error) => { throw e; }) => { setTimeout(() => rej(new Error('late')), 50); });",
  'deadline guard with an unrelated local beside it': "await new Promise((r, rej) => { const msg = 'late'; setTimeout(() => rej(new Error(msg)), 50); });",
  'renamed value that is not the resolve, timer unrelated':
    'let r: () => void = () => undefined; const p = new Promise<void>((res) => { const x = 1; r = res; void x; }); setTimeout(() => undefined, 50); await p;',
  'constructor alias that is not Promise': 'class Q { constructor(f: (r: () => void) => void) { f(() => undefined); } } const P = Q; void new P((r) => { r(); });',
  'Promise alias with a deadline guard': "const P = Promise; await new P((r, rej) => { setTimeout(() => rej(new Error('late')), 50); });",
  'withResolvers assigned, reject from a timer': "let d: ReturnType<typeof Promise.withResolvers<void>>; d = Promise.withResolvers<void>(); setTimeout(() => d.reject(new Error('late')), 50); await d.promise.catch(() => undefined);",
  'resolve stored by index, timer unrelated to the array':
    'const rs: Array<() => void> = []; const other = [1]; const p = new Promise<void>((res) => { rs[0] = res; }); setTimeout(() => other.pop(), 50); await p;',
  'resolve stored on one member, timer reads a sibling':
    'const d = {} as { resolve: () => void; other: () => void }; const p = new Promise<void>((res) => { d.resolve = res; }); setTimeout(() => d.other(), 50); await p;',
};

const SLEEP = 'await new Promise((r) => setTimeout(r, 50));';
// Every extension in the scope glob (tests/**/*.{ts,tsx,mts}), at the top of tests/ and nested.
const extensions = ['ts', 'tsx', 'mts'];

// Every row id in the spec's section 2 and 3 tables (tests/lint/no-sleep-rule-spec.md), so deleting a row from the case tables
// fails here, and a row added to the spec without a case fails the parse test below. A13 is the glob test.
const SPEC_ROWS = [
  '1', '2a', '2b', '2c', '2d', '2d:fallback', '2d:conditional', '2e:host-var', '3a', '3b', '3c', '3d', '3e', '3f',
  '3a:export', '3a:named', '3b:export-all', '3b:export-ns', '3c:import-equals', '3c:template', '3c:const',
  '3d:template', '3d:let', '3e:computed', '3e:template', '3e:const', '3c:hole', '3d:hole', '3e:hole',
  '3d:hole-const', '3f:alias', '3f:destructured-host', '3f:import', '4a', '4b', '4c', '4d', '4e', '4a:reassigned',
  '4a:fallback', '4a:logical', '4a:default-param', '4a:reflect', '4a:reflect-alias', '4a:reflect-args', '4b:reflect',
  '4c:reflect', '4d:reflect', '4e:reflect', '4e:host-var', '4e:assign', '4e:param', '4e:reflect-assign', '4x:race',
  '4x:noop', '5', '5:swapped', '6', '6:named-callback', '6:bind-resolve', '6:literal', '6:array', '6:wrapper',
  '6:outer', '7a', '7b', '7a:default-fn', '8a', '8b', '8c', '8d', '8a:assign', '8a:param', '8a:cast', '8a:cast2',
  '8a:comma', '8a:logical', '8a:conditional', '8a:nested', '8a:host-var', '8a:default', '8d:let', '8d:let-member',
  '8d:let-twice', '8d:let-reversed', '9a', '9b', '9a:plain', '9a:shorthand', '9b:destructure', '9c', '9d:return',
  '9d:arrow', '9d:template', '9d:default-global', '9d:default-destructured', '9x:cast', '10a', '10b', '10c',
  '10c:destructure', '10d', '10e', '10f', '10f:optional-ref', '10f:optional-call', '10g', '10h', '10i', '10j',
  '10a:field', '10a:field-private', '10a:field-static', '10a:class-expr', '10a:static-this', '10h:bag-object',
  '10h:bag-key', '10h:bag-array', '10h:bag-nested', '10i:call', '10i:apply', '10i:bind', '10i:bound-const',
  '10i:destructured-call', '10j:bag-object', '10l:copy-before', '10l:copy-in-fn', '10l:chain', '10k:callback',
  '10k:declared', '10k:bind', '10k:wrapper', '10k:hop', '11a', '11a:page', '11b', '11c', '11d', '11e',
  '11b:let-twice', '11b:let-reversed', '12a', '12a:string', '12b', '12c', '12d', '12a:let', '12a:assigned',
  '12a:param', '12b:let', '12c:let', '12d:let', '12a:let-twice', '12a:let-reversed', '12a:let-append',
  '12e:function', '12e:local-fn', '12e:local-decl', '12e:const', '13a', '13b', '13a:alias', '13a:destructured-host',
  '14a', '14b', '14c', '14d:flag', '14d:one', '14d:for', '14d:var', '14d:assign', '14d:return', '14d:set-flag',
  '14d:assign-flag', '14d:continue', '14d:else', '14d:block', '14d:throw', '14d:throw-new', '14d:member',
  '14d:derived', '14d:test-var', '14d:test-var-do', '14d:test-flag', '14f:local-arrow', '14f:local-decl',
  '14f:local-guard', '14f:local-var', '12a:param-undefined', '4a:default-undefined', '8a:default-void', '14f:alias',
  '14f:alias-bind', '14f:alias-destructured', '10i:let-reassigned', '10i:let-reversed', '3d:let-reversed', '3g', '6:held', '6:emit', '6:listener', '3a:mixed', '3a:side-effect', '3b:export-mixed', '5:fallback', '5:ternary', '10m:fallback', '14f:cycle', '14f:cycle-arrows', '14f:cycle-complete', '9x:host', '9x:host-computed', '9x:host-var', '9x:host-cast', '9x:host-destructured', '9x:host-new', '3g:host', '14f:alias-cast', '14f:alias-cast-call', '14f:alias-fallback', '14f:alias-fallback-call', '14f:local-typed', '5:bind', '5:wrapper', '5:wrapper-fn', '4a:default-exported', '4a:default-exported-const', '4a:default-export-list', '4a:default-maybe', '4a:default-maybe-logical', '4a:default-undefined-var', '4a:default-undefined-copy', '12f:eval', '12f:eval-indirect', '12f:new-function', '12f:function', '12a:default-recursive', '5:overload', '14f:overload', '10a:static-by-name', '10a:static-private', '9x:matcher-inner', '9x:matcher-inner-host', '5:this-param', '5:this-param-wrapper', '5:wrapper-call', '5:bind-twice', '12f:eval-alias', '12f:function-alias', '14f:this-param', '2b:self-bare', '2b:self-copy', '2b:self-default', '2b:self-declared', '2b:window-declared', '10a:static-block'
];
const SPEC_ALLOWED = [
  'A1a', 'A1b', 'A1c', 'A1c:declared', 'A1c:arrow', 'A1c:outer', 'A1c:bind', 'A2a', 'A2b', 'A2c', 'A2a:cast',
  'A2a:nonnull', 'A2b:cast', 'A3', 'A3:opts-read', 'A3:server-call', 'A3:destructure', 'A3:destructure-key',
  'A3:destructure-computed', 'A3:destructure-param', 'A4', 'A5', 'A6', 'A6:expect-timer', 'A6:host-literal-other',
  'A7', 'A7:stamps', 'A7:record', 'A7:count', 'A7:unguarded', 'A8', 'A9', 'A9:field', 'A10', 'A11', 'A12', 'A14',
  'A14:atomics', 'A14:store', 'A14:driver-key', 'A14:var', 'A15:callback', 'A15:other', 'A15:return',
  'A15:script-const', 'A15:destructure', 'A15:class', 'A15:field-plain', 'A15:local-fn', 'A15:module-other',
  'A15:this-other-class', 'A15:default-overridden', 'A15:default-overridden-promise', 'A15:default-overridden-host',
  'A15:host-var-config', 'A15:host-var-member', 'A15:alias-other', 'A7:clock-test-var', 'A7:local-work-fn',
  'A7:local-counter', 'A7:local-stamps', 'A7:local-clock-outside', 'A15:default-null', 'A7:alias-stamps',
  'A15:module-head', 'A2d', 'A3:expect', 'A6:mocked', 'A1d', 'A1d:destroy', 'A1d:off', 'A15:type-import', 'A15:type-inline', 'A15:type-export', 'A14:cycle-no-read', 'A14:cycle-work', 'A3:value', 'A14:fallback-no-read', 'A5:wrapper-other', 'A5:wrapper-guard', 'A15:default-both-defined', 'A15:default-fallback-defined', 'A15:default-var-defined', 'A12:eval-plain', 'A15:node-hole', 'A15:default-recursive', 'A15:default-recursive-arrow', 'A15:default-mutual', 'A15:default-recursive-promise', 'A6:matcher', 'A6:matcher-not-host', 'A6:matcher-strict-equal', 'A6:assert', 'A6:restore-asserted', 'A6:soft', 'A5:wrapper-call-other', 'A5:bind-twice-other', 'A12:eval-alias-plain', 'A15:self-param', 'A15:window-param', 'A15:global-local', 'A15:self-destructured', 'A14:date-search', 'A14:sorted-throw'
];

// The planted violation per rule id: one banned row that only that rule reports.
const PLANTED: Record<string, string> = { [PROMISE]: '1', [ALIAS]: '9a', [SYNTAX]: '3a', [API]: '11a' };

describe('sleep ban lint rules', () => {
  for (const [row, code, rule, id] of bannedCases) {
    it(`reports spec row ${row} with ${rule}`, async () => {
      const messages = await sleepMessages(code);
      const hit = messages.find((m) => m.ruleId === rule && (m.messageId === id || m.message.includes(id)));
      expect(hit, `row ${row} not reported as ${rule} (${id}); got ${JSON.stringify(messages.map((m) => [m.ruleId, m.messageId]))}`).toBeDefined();
      // Every ban says what it caught and ends with the signals to wait on instead.
      expect(hit?.message.endsWith(SIGNALS), `row ${row} message does not end with the signal list: ${hit?.message}`).toBe(true);
    });
  }

  for (const [row, code] of allowedCases) {
    it(`allows spec row ${row}`, async () => {
      expect(await ruleIds(code)).toEqual([]);
    });
  }

  for (const [name, [code, rule]] of Object.entries(banned)) {
    it(`flags ${name} with ${rule}`, async () => {
      expect(await ruleIds(code)).toContain(rule);
    });
  }

  for (const [name, code] of Object.entries(allowed)) {
    it(`allows ${name}`, async () => {
      expect(await ruleIds(code)).toEqual([]);
    });
  }

  for (const ext of extensions) {
    for (const dir of ['tests', 'tests/lint', 'tests/a/b']) {
      it(`flags a sleep promise in ${dir}/snippet.${ext}`, async () => {
        expect(await ruleIds(SLEEP, `${dir}/snippet.${ext}`)).toContain(PROMISE);
      });
    }
    it(`reports nothing for the same sleep outside the test glob, .${ext}`, async () => {
      // Backoff, retry and poll code under src/ and scripts/ legitimately uses timers.
      expect(await ruleIds(SLEEP, `src/lib/wait.${ext}`)).toEqual([]);
      expect(await ruleIds(SLEEP, `scripts/wait.${ext}`)).toEqual([]);
    });
  }
});

describe('spec coverage', () => {
  it('has a row for every bypass class, 1 to 14', () => {
    const classes = new Set(bannedCases.map(([row]) => Number.parseInt(row, 10)));
    for (let cls = 1; cls <= 14; cls++) expect(classes.has(cls), `class ${cls} has no row`).toBe(true);
  });

  it('keeps every spec bypass row and allowed row', () => {
    const banned = new Set(bannedCases.map(([row]) => row));
    const allowed = new Set(allowedCases.map(([row]) => row));
    expect(SPEC_ROWS.filter((row) => !banned.has(row))).toEqual([]);
    expect(SPEC_ALLOWED.filter((row) => !allowed.has(row))).toEqual([]);
  });

  // The two older name-keyed lists at the top of this file are not copies of the case rows (most of their shapes have no row), but a snippet in both
  // must agree: banned in one place and allowed in the other would make one of the tests lie.
  it('keeps the name-keyed lists consistent with the case rows', () => {
    const bannedRule = new Map(bannedCases.map(([, code, rule]) => [code, rule]));
    const allowedCode = new Set(allowedCases.map(([, code]) => code));
    expect(Object.entries(banned).filter(([, [code, rule]]) => allowedCode.has(code) || (bannedRule.has(code) && bannedRule.get(code) !== rule)).map(([name]) => name)).toEqual([]);
    expect(Object.entries(allowed).filter(([, code]) => bannedRule.has(code)).map(([name]) => name)).toEqual([]);
  });

  it('has every harness shape as an exact case row', () => {
    const banned = new Set(bannedCases.map(([, code]) => code));
    const allowed = new Set(allowedCases.map(([, code]) => code));
    expect(harnessBanned.filter(([, , code]) => !banned.has(code)).map(([cls, name]) => `${cls} ${name}`)).toEqual([]);
    expect(harnessAllowed.filter(([, , code]) => !allowed.has(code)).map(([cls, name]) => `${cls} ${name}`)).toEqual([]);
  });
});

describe('spec tables', () => {
  const COPY = join('tests', 'lint', 'no-sleep-rule-spec.md');
  const section = (num: string) => {
    const text = readFileSync(COPY, 'utf8');
    const start = text.indexOf(`## ${num}.`);
    return text.slice(start, text.indexOf('\n## ', start + 1));
  };
  const ids = (num: string) => [...section(num).matchAll(/^\| ([^|]+?) \|/gm)].map((m) => m[1] ?? '').filter((id) => id !== 'ID');

  it.each(['2', '3'])('keeps the section %s heading count equal to its rows', (num) => {
    const heading = section(num).split('\n')[0] ?? '';
    expect(heading).toContain(`(${ids(num).length} rows)`);
  });

  // A blank line ends a table, and the rows after it render as plain text while the id parse above still reads them.
  it.each(['2', '3'])('keeps the section %s rows in one table', (num) => {
    const at = section(num)
      .split('\n')
      .flatMap((line, i) => (line.startsWith('|') ? [i] : []));
    expect((at.at(-1) ?? 0) - (at[0] ?? 0) + 1, `a blank line splits the section ${num} table`).toBe(at.length);
  });

  it('pins every banned row the spec lists', () => {
    expect(ids('2').filter((id) => !SPEC_ROWS.includes(id))).toEqual([]);
  });

  it('pins every allowed row the spec lists', () => {
    expect(ids('3').filter((id) => id !== 'A13' && !SPEC_ALLOWED.includes(id))).toEqual([]);
  });

  it('has a case for every row the spec lists', () => {
    const banned = new Set(bannedCases.map(([row]) => row));
    const allowed = new Set(allowedCases.map(([row]) => row));
    expect(ids('2').filter((id) => !banned.has(id))).toEqual([]);
    expect(ids('3').filter((id) => id !== 'A13' && !allowed.has(id))).toEqual([]);
  });

  // The copy in this repo is what the parse tests read, the rule module is what the other repos port, and the cases file is the table that
  // proves it. All three are pinned by hash in a committed file, so a change to any that skips the pin fails in CI, where no home directory
  // holds a canonical copy to compare to. The repo's own eslint.config.js is not pinned: an unrelated edit there needs no regen.
  // The pin only compares these three files with their recorded hashes. It does not compare the spec copy with the canonical one under
  // ~/.claude/reference, so drift from the canonical copy is caught by a `cmp` run by hand, not by CI.
  // A port compares its own three files against the same pins. Update them after an intended change:
  //   node -e "const c=require('crypto'),f=require('fs');const h=(p)=>c.createHash('sha256').update(f.readFileSync(p)).digest('hex');f.writeFileSync('tests/lint/no-sleep-pins.json',JSON.stringify({spec:h('tests/lint/no-sleep-rule-spec.md'),rule:h('eslint/no-sleep.js'),cases:h('tests/lint/no-sleep-cases.ts')},null,2)+'\\n')"
  it('matches the pinned hashes of the spec, the rule module and the cases', () => {
    const hash = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex');
    const pins = JSON.parse(readFileSync(join('tests', 'lint', 'no-sleep-pins.json'), 'utf8')) as { spec: string; rule: string; cases: string };
    expect({ spec: hash(COPY), rule: hash('eslint/no-sleep.js'), cases: hash('tests/lint/no-sleep-cases.ts') }).toEqual(pins);
  });
});

// A block that sets `no-restricted-syntax` replaces what an earlier block set. A repo that already restricts syntax in tests keeps its own
// selectors beside the banned ones when it wraps its blocks in withNoSleep.
describe('no-restricted-syntax merge', () => {
  it('keeps the host selectors beside the banned ones', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'no-sleep-merge-'));
    try {
      const file = join(dir, 'eslint.config.mjs');
      const rule = pathToFileURL(resolve('eslint/no-sleep.js')).href;
      const host = "{ files: ['tests/**/*.{ts,tsx,mts}'], rules: { 'no-restricted-syntax': ['error', { selector: 'DebuggerStatement', message: 'host: no debugger' }] } }";
      writeFileSync(file, `import { withNoSleep } from ${JSON.stringify(rule)};\nexport default withNoSleep([${host}]);\n`);
      const merged = new ESLint({ overrideConfigFile: file, cwd: resolve('.') });
      const code = 'debugger;\nfunction sleep() {}\n';
      const [result] = await merged.lintText(code, { filePath: 'tests/lint/snippet.ts' });
      const messages = (result?.messages ?? []).map((m) => m.message);
      expect(messages.some((m) => m.startsWith('host: no debugger'))).toBe(true);
      expect(messages.some((m) => m.startsWith('No sleep helper'))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// Which of the host's blocks apply to the test files is read from their globs: a block that covers every test path is merged, one that
// covers none (JavaScript only, or another directory) is left alone, and one that covers some would be dropped or widened, so it throws.
describe('no-restricted-syntax glob match', () => {
  const host = { selector: 'DebuggerStatement', message: 'host: no debugger' };
  const run = (files: unknown[] | undefined, ignores?: string[]) => {
    const blocks = withNoSleep([{ files, ignores, rules: { 'no-restricted-syntax': ['error', host] } }] as Linter.Config[]) as Linter.Config[];
    const rule = blocks.at(-1)?.rules?.['no-restricted-syntax'] as unknown[];
    return rule.includes(host) ? 'merged' : 'left alone';
  };
  const globs: Record<string, [unknown[] | undefined, 'merged' | 'left alone' | 'throws', string[]?]> = {
    'no files': [undefined, 'merged'],
    'the test glob': [['tests/**/*.{ts,tsx,mts}'], 'merged'],
    'a catch-all of the three extensions': [['**/*.{ts,tsx,mts}'], 'merged'],
    'the whole test directory': [['tests/**'], 'merged'],
    'every file': [['**/*'], 'merged'],
    'a superset of the extensions': [['**/*.{ts,tsx,mts,js}'], 'merged'],
    'one extension of three': [['tests/**/*.ts'], 'throws'],
    'test files by name only': [['**/*.test.ts'], 'throws'],
    'one subdirectory of the tests': [['tests/lint/**'], 'throws'],
    'a catch-all of one extension': [['**/*.ts'], 'throws'],
    'two globs that together stop short': [[['tests/**', '**/*.ts']], 'throws'],
    'the whole directory with a subdirectory ignored': [['tests/**'], 'throws', ['tests/e2e/**']],
    'JavaScript only': [['**/*.{js,mjs}'], 'left alone'],
    'source only': [['src/**/*.ts'], 'left alone'],
    'scripts only': [['scripts/**'], 'left alone'],
  };
  for (const [name, [files, want, ignores]] of Object.entries(globs)) {
    it(`${want === 'throws' ? 'refuses' : want === 'merged' ? 'merges' : 'leaves alone'} a block for ${name}`, () => {
      if (want === 'throws') expect(() => run(files, ignores)).toThrow(/some test files but not all/);
      else expect(run(files, ignores)).toBe(want);
    });
  }
});

describe('planted violations', () => {
  // With one rule switched off, its planted row must stop reporting: the case depends on that rule,
  // so deleting the rule from the config fails here instead of passing quietly.
  for (const [rule, row] of Object.entries(PLANTED)) {
    it(`${row} depends on ${rule}`, async () => {
      const code = bannedCases.find(([r]) => r === row)?.[1] ?? '';
      expect(code, `no banned row ${row}`).not.toBe('');
      expect(await ruleIds(code)).toContain(rule);
      const muted = new ESLint({
        overrideConfigFile: 'eslint.config.js',
        overrideConfig: { files: ['tests/**/*.{ts,tsx,mts}'], rules: { [rule]: 'off' } },
      });
      expect((await sleepMessages(code, 'tests/lint/snippet.ts', muted)).map((m) => m.ruleId)).toEqual([]);
    });
  }

  it('plants a row for every rule the banned table names', () => {
    expect(new Set(bannedCases.map(([, , rule]) => rule))).toEqual(new Set(Object.keys(PLANTED)));
  });
});

describe('known gaps', () => {
  // The Known gaps list is written in the module comment, the spec and gapCases. The comment is parsed here: every line needs at least one
  // case, every case names a line that exists, and the spec lists as many lines.
  const bulletsIn = (text: string, marker: string, line: RegExp) => {
    const at = text.indexOf(marker);
    const out: string[] = [];
    for (const l of text.slice(at).split('\n').slice(1)) {
      const m = line.exec(l);
      if (m) out.push(m[1] ?? '');
      else if (/^\/\/\s{3}/.test(l) && out.length) out[out.length - 1] += l;
      else break;
    }
    return out;
  };
  it('has a case for every line of the Known gaps comment, and a spec line for each', () => {
    const lines = bulletsIn(readFileSync('eslint/no-sleep.js', 'utf8'), '// Known gaps (an AST rule', /^\/\/ - (.*)$/);
    expect(lines.length).toBeGreaterThan(0);
    expect(gapCases.filter(([, , at]) => at < 0 || at >= lines.length).map(([name]) => name)).toEqual([]);
    expect(lines.map((_, i) => i).filter((i) => !gapCases.some(([, , at]) => at === i)).map((i) => lines[i]?.slice(0, 60))).toEqual([]);
    const spec = readFileSync(join('tests', 'lint', 'no-sleep-rule-spec.md'), 'utf8');
    const at = spec.indexOf('**Accepted gaps');
    const bullets = spec.slice(at, spec.indexOf('\n\n', at)).split('\n').filter((l) => l.startsWith('- '));
    expect(bullets.length).toBe(lines.length);
  });

  for (const [name, code] of gapCases) {
    it(`still misses ${name}`, async () => {
      expect(await ruleIds(code), `${name} is reported now: move it out of the Known gaps comment into bannedCases`).toEqual([]);
    });
  }

  for (const [name, code, rule] of acceptedFalsePositives) {
    it(`still reports ${name}`, async () => {
      expect(await ruleIds(code)).toContain(rule);
    });
  }
});

// A long file must not cost seconds: the dataflow pass revisits every helper and every body, and the
// old shapes below took 15 s and 0.8 s. A fixed bound cannot tell a fast pass from a slow one on a fast box, so
// this counts the rule's own work instead of timing it. Four times the input costs about 4x (linear); 16x would be quadratic, so
// the bound is 6. The same input cost 40x to 100x with the follow memo gone or with a recursive descendants walk, and a
// chain of clock functions was exponential without its memo (4x the links cost over 1000x). Parsing and the other rules are off, so
// a slow walk is not hidden. SLEEP_OPS_LOG=1 prints every count.
describe('lint cost on long files', () => {
  // Only the ban rules are on, so nothing else in the config is counted or parsed twice.
  const counted = new ESLint({
    overrideConfigFile: true,
    overrideConfig: withNoSleep([
      { files: ['**/*.{ts,tsx,mts}'], languageOptions: { parser: tsParser, parserOptions: { ecmaVersion: 2022, sourceType: 'module' } } },
    ]) as Linter.Config[],
  });
  // The rule counts its own work (unwrap, scope lookups, reads of writes, each step of a walk, each node visited) in globalThis.__sleepOps.
  // A count is the same on every run and on a loaded host, which a clock reading is not. A linear rule reads 4 for 4x the input and a
  // quadratic one 16, so the bound sits at 6.
  const counter = globalThis as { __sleepOps?: number };
  const ops = async (code: string) => {
    counter.__sleepOps = 0;
    try {
      const [result] = await counted.lintText(code, { filePath: 'tests/lint/snippet.ts' });
      expect(result?.messages.filter((m) => m.fatal)).toEqual([]);
      return counter.__sleepOps;
    } finally {
      delete counter.__sleepOps;
    }
  };
  // A count of zero would make the ratio 0 (or infinite) and pass for the wrong reason, so both ends must have done work.
  const costRatio = async (sample: (code: string) => Promise<number>, make: (n: number) => string, small: number, big: number) => {
    const base = await sample(make(small));
    const slow = await sample(make(big));
    expect(base, 'nothing was counted at the small size').toBeGreaterThan(0);
    expect(slow, 'nothing was counted at the big size').toBeGreaterThan(0);
    return { base, slow, ratio: slow / base };
  };
  const chain = (n: number) => {
    const lines = [`let ${Array.from({ length: n }, (_, i) => `c${i}: any`).join(', ')};`];
    for (let i = n - 1; i >= 1; i--) lines.push(`c${i} = c${i - 1};`);
    lines.push('c0 = Promise.withResolvers<void>();', 'const sink: unknown[] = [];', 'function stash(f: () => void) {');
    for (let i = 0; i < n; i++) lines.push('  sink.push(f);');
    lines.push('}');
    for (let i = 0; i < n; i++) lines.push(`stash(c${i}.resolve);`);
    lines.push('setTimeout(sink[0] as () => void, 5);');
    return lines.join('\n');
  };
  // Each function returns a call to the one before it, and the loop reads the clock through the last.
  const clocks = (n: number) => {
    const lines = ['function f0() { return Date.now(); }'];
    for (let i = 1; i < n; i++) lines.push(`function f${i}() { return f${i - 1}(); }`);
    lines.push(`while (f${n - 1}() < 5) {}`);
    return lines.join('\n');
  };
  // Each helper calls the one before it twice, and the executor hands its resolve to the top one: the hits of a level are
  // the hits of the level below, copied into its caller.
  const fan = (n: number) => {
    const lines = ['function h0(f: () => void) { setTimeout(f, 5); }'];
    for (let i = 1; i <= n; i++) lines.push(`function h${i}(f: () => void) { h${i - 1}(f); h${i - 1}(f); }`);
    lines.push(`await new Promise<void>((r) => h${n}(r));`);
    return lines.join('\n');
  };
  // One name written N times, each write another read of it: a read that revisits every write at every level costs N^3.
  const timerKey = (write: string) => (n: number) =>
    `let k = 'setTimeout'; ${Array.from({ length: n }, () => write).join(' ')} await new Promise((r) => (globalThis as any)[k](r, 50));`;
  const script = (n: number) =>
    `let s = 'setTimeout(() => 0, 5)'; ${Array.from({ length: n }, () => 's = s;').join(' ')} await page.evaluate(s);`;
  // Every variable written from every other.
  const complete = (n: number) => {
    const lines = [`let ${Array.from({ length: n }, (_, i) => `v${i}: any`).join(', ')};`];
    for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) if (i !== j) lines.push(`v${i} = v${j};`);
    lines.push("v0 = 'setTimeout'; await new Promise((r) => (globalThis as any)[v0](r, 50));");
    return lines.join('\n');
  };
  // N timers in one file that all call the same N-line helper. A resolve is stored, so every timer is checked against it, and
  // only the last one calls it back. The helper is read once, not once per timer.
  const timersLeak = (n: number) => {
    const lines = ['const log: number[] = [];', 'let saved: () => void = () => undefined;', 'const p = new Promise<void>((res) => { saved = res; });', 'function work() {'];
    for (let i = 0; i < n; i++) lines.push(`  log.push(${i});`);
    lines.push('}');
    for (let i = 0; i < n; i++) lines.push('setTimeout(() => work(), 5);');
    lines.push('setTimeout(() => saved(), 5);', 'await p;');
    return lines.join('\n');
  };
  // N deadline guards whose callbacks all call the same N-line helper with their reject, and one real sleep at the end.
  const timersGuard = (n: number) => {
    const lines = ['const log: number[] = [];', 'function work(j: (e: Error) => void) {'];
    for (let i = 0; i < n; i++) lines.push(`  log.push(${i});`);
    lines.push('  j(new Error("late"));', '}');
    for (let i = 0; i < n; i++) lines.push('await new Promise<void>((r, rej) => { setTimeout(() => work(rej), 50); void r; });');
    lines.push('await new Promise<void>((r) => setTimeout(r, 5));');
    return lines.join('\n');
  };
  // Executors nested N deep, one name per level and the same name at every level. The innermost one sleeps, so the shape
  // reports once and an empty answer cannot pass for a fast one.
  const nestedWith = (name: (i: number) => string) => (n: number) => {
    let body = `setTimeout(${name(0)}, 5);`;
    for (let i = 0; i < n; i++) body = `await new Promise<void>((${name(i)}) => {\n${body}\n${name(i)}();\n});`;
    return `const resolveOuter = () => undefined;\nasync function run() {\n${body}\n}`;
  };
  // A long file of plain declarations before a clock loop: every token and comment of the program is read once, not spread onto a stack.
  const plain = (n: number) => `${Array.from({ length: n }, (_, i) => `const a${i} = ${i};`).join('\n')}\nconst now = () => Date.now();\nwhile (now() < 5) {}\n`;
  // Every level also holds a deadline guard, which is judged against every executor around it.
  const nestedTimers = (n: number) => {
    let body = 'resolveOuter();';
    for (let i = 0; i < n; i++) body = `await new Promise<void>((r${i}, j${i}) => {\n${body}\nsetTimeout(() => j${i}(new Error('x')), 50);\nvoid r${i};\n});`;
    return `const resolveOuter = () => undefined;\nasync function run() {\n${body}\n}`;
  };
  // Clock helpers that call each other. A ring reads the clock in one member; a dense cycle has every helper call two others;
  // a complete graph has every helper call every other. Each must be reported, and none may cost more than its input.
  const clockRing = (n: number) => {
    const lines = Array.from({ length: n }, (_, i) => `function m${i}() { return m${(i + 1) % n}()${i === 0 ? ' + Date.now()' : ''}; }`);
    lines.push('while (m0() < 5) {}');
    return lines.join('\n');
  };
  const clockRingBlock = (n: number) => {
    const lines = Array.from({ length: n }, (_, i) => `const m${i} = () => { return m${(i + 1) % n}()${i === 0 ? ' + Date.now()' : ''}; };`);
    lines.push('while (m0() < 5) {}');
    return lines.join('\n');
  };
  const clockDense = (n: number) => {
    const lines = Array.from({ length: n }, (_, i) => `function m${i}() { return m${(i + 1) % n}() + m${(i + 2) % n}() + Date.now(); }`);
    lines.push('while (m0() < 5) {}');
    return lines.join('\n');
  };
  const clockComplete = (n: number) => {
    const lines = Array.from({ length: n }, (_, i) => `function m${i}() { return ${Array.from({ length: n }, (_, j) => j).filter((j) => j !== i).map((j) => `m${j}()`).join(' + ')} + Date.now(); }`);
    lines.push('while (m0() < 5) {}');
    return lines.join('\n');
  };
  // A resolve handed down a complete graph of helpers, one of which sets the timer, and one handed to a stored resolve.
  const helpersComplete = (n: number) => {
    const lines = Array.from({ length: n }, (_, i) => `function a${i}(f: () => void) { ${Array.from({ length: n }, (_, j) => (j === i ? '' : `a${j}(f);`)).join(' ')} ${i === 0 ? 'setTimeout(f, 5);' : ''} }`);
    lines.push('await new Promise<void>((r) => a1(r));');
    return lines.join('\n');
  };
  const reachComplete = (n: number) => {
    const lines = ['let saved: () => void = () => undefined;', 'const p = new Promise<void>((res) => { saved = res; });'];
    for (let i = 0; i < n; i++) lines.push(`function g${i}() { ${Array.from({ length: n }, (_, j) => (j === i ? '' : `g${j}();`)).join(' ')} ${i === 0 ? 'saved();' : ''} }`);
    lines.push('setTimeout(() => g1(), 5);', 'await p;');
    return lines.join('\n');
  };
  // A helper that hands its argument on through a ring of returns, with the timer in one of them.
  const returnRing = (n: number) => {
    const lines = Array.from({ length: n }, (_, i) => `function t${i}(f: () => void) { ${i === 0 ? 'setTimeout(f, 5); ' : ''}return t${(i + 1) % n}(f); }`);
    lines.push('await new Promise<void>((r) => t1(r));');
    return lines.join('\n');
  };
  // A resolver copied N times, each copy built from the one before it twice.
  const doubling = (n: number) => {
    const lines = ['await new Promise<void>((r) => {', '  const a0 = r;'];
    for (let i = 1; i <= n; i++) lines.push(`  const a${i} = a${i - 1} ?? a${i - 1};`);
    lines.push(`  setTimeout(a${n}, 5);`, '});');
    return lines.join('\n');
  };
  const doublingHelper = (n: number) => {
    const lines = ['function h(f: () => void) {', '  const a0 = f;'];
    for (let i = 1; i <= n; i++) lines.push(`  const a${i} = a${i - 1} ?? a${i - 1};`);
    lines.push(`  setTimeout(a${n}, 5);`, '}', 'await new Promise<void>((r) => h(r));');
    return lines.join('\n');
  };
  const doublingFlow = (n: number) => {
    const lines = ['const d = Promise.withResolvers<void>();', 'const a0 = d.resolve;'];
    for (let i = 1; i <= n; i++) lines.push(`const a${i} = a${i - 1} ?? a${i - 1};`);
    lines.push(`setTimeout(a${n}, 5);`, 'await d.promise;');
    return lines.join('\n');
  };
  // Script text passed round a ring of variables, plainly and inside arrays.
  const scriptRing = (n: number) => {
    const lines = ["let s0 = 'setTimeout(() => 0, 5)';"];
    for (let i = 1; i < n; i++) lines.push(`let s${i} = s${i - 1};`);
    lines.push(`s0 = s${n - 1};`, 'await page.evaluate(s0);');
    return lines.join('\n');
  };
  const scriptRingBags = (n: number) => {
    const lines = ["let s0 = 'setTimeout(() => 0, 5)';"];
    for (let i = 1; i < n; i++) lines.push(`let s${i} = [s${i - 1}, s${(i + 1) % n}];`);
    lines.push(`s0 = s${n - 1};`, 'await page.evaluate(s0);');
    return lines.join('\n');
  };
  // A busy loop whose clock read reaches the test through a chain of N copies, a loop per copy of one clock, the same copies in a ring,
  // and a chain of clock helpers where only the bottom one is async (so each round drops one more).
  const busyChain = (n: number) => {
    const lines = [`let done = false; let ${Array.from({ length: n + 1 }, (_, i) => `t${i} = 0`).join(', ')};`, 'while (!done) {'];
    for (let i = n; i >= 1; i--) lines.push(`  t${i} = t${i - 1};`);
    lines.push('  t0 = Date.now();', `  done = t${n} > 5;`, '}');
    return lines.join('\n');
  };
  const aliasLoops = (n: number) => {
    const lines = ['const k0 = Date.now;'];
    for (let i = 1; i <= n; i++) lines.push(`const k${i} = k${i - 1};`);
    for (let i = 0; i <= n; i++) lines.push(`while (k${i}() < 5) {}`);
    return lines.join('\n');
  };
  const aliasRing = (n: number) => {
    const lines = ['let k0 = Date.now;'];
    for (let i = 1; i < n; i++) lines.push(`let k${i} = k${i - 1};`);
    lines.push(`k0 = k${n - 1};`);
    for (let i = 0; i < n; i++) lines.push(`while (k${i}() < 5) {}`);
    return lines.join('\n');
  };
  const clockCascade = (n: number) => {
    const lines = [`async function f${n}() { await 1; return Date.now(); }`];
    for (let i = n - 1; i >= 0; i--) lines.push(`function f${i}() { f${i + 1}(); return Date.now(); }`);
    // Every helper falls out, so f0 is no clock; the plain read is the report that proves the file was linted.
    lines.push('while (f0() < 5) {}', 'while (Date.now() < 5) {}');
    return lines.join('\n');
  };
  // The same copies of Date, each read with `new`: the names asked about are a fresh array at every call site.
  const dateLoops = (n: number) => {
    const lines = ['const D0 = Date;'];
    for (let i = 1; i <= n; i++) lines.push(`const D${i} = D${i - 1};`);
    for (let i = 0; i <= n; i++) lines.push(`while (new D${i}().getTime() < 5) {}`);
    return lines.join('\n');
  };
  // Every shape is run at a size and at the size that has four times the input (twice the width for a graph whose edges are the
  // square of its nodes). The same reports must come back at both before anything is counted; linear cost is a ratio near 4, so a
  // bound of 6 leaves room for a constant overhead and nothing for quadratic cost, which would read 16.
  // Sizes stay under the parser's own stack limit (a little past 100 nested executors).
  const sleeps = (n: number) => Array.from({ length: n }, () => PROMISE);
  const busy = (n: number) => Array.from({ length: n }, () => API);
  for (const [name, make, small, factor, ids] of [
    ['a reverse assignment chain into a helper of the same length', chain, 100, 4, () => [PROMISE]],
    ['nested executors', nestedWith((i) => `r${i}`), 25, 4, () => [PROMISE]],
    ['nested executors that share one name', nestedWith(() => 'r'), 25, 4, () => [PROMISE]],
    ['nested executors that each hold a deadline guard', nestedTimers, 25, 4, (n: number) => sleeps(n - 1)],
    ['a chain of clock functions with a loop on the top one', clocks, 100, 4, () => [API]],
    ['a long file of declarations before a clock loop', plain, 5000, 4, () => [API]],
    ['a busy loop fed through a chain of N copies', busyChain, 100, 4, () => [API]],
    ['a loop on each of N copies of one clock', aliasLoops, 100, 4, (n: number) => busy(n + 1)],
    ['a loop on each of N copies of a clock in a ring', aliasRing, 100, 4, (n: number) => busy(n)],
    ['a cascade of clock helpers that loses one per round', clockCascade, 100, 4, () => [API]],
    ['a loop on each of N copies of Date read with new', dateLoops, 100, 4, (n: number) => busy(n + 1)],
    ['helpers that each call the one below twice', fan, 20, 4, () => [PROMISE]],
    ['a timer key written N times from itself', timerKey('k = k;'), 100, 4, () => [PROMISE]],
    ['a timer key written N times through ||', timerKey('k = k || k;'), 100, 4, () => [PROMISE]],
    ['a script written N times from itself', script, 100, 4, () => [API]],
    ['N variables each written from all the others', complete, 20, 2, () => [PROMISE]],
    ['N timers that call one N-line helper while a resolve is stored', timersLeak, 100, 4, () => [PROMISE]],
    ['N deadline guards that call one N-line helper with their reject', timersGuard, 100, 4, () => [PROMISE]],
    ['a ring of clock helpers', clockRing, 100, 4, () => [API]],
    ['a ring of clock helpers declared as arrows', clockRingBlock, 100, 4, () => [API]],
    ['a dense cycle of clock helpers', clockDense, 40, 4, () => [API]],
    ['a complete graph of clock helpers', clockComplete, 20, 2, () => [API]],
    ['a complete graph of helpers that pass a resolve down', helpersComplete, 20, 2, () => [PROMISE]],
    ['a complete graph of helpers that call a stored resolve', reachComplete, 20, 2, () => [PROMISE]],
    ['a ring of helpers that return each other', returnRing, 100, 4, () => [PROMISE]],
    ['a resolver copied through ?? N times', doubling, 100, 4, () => [PROMISE]],
    ['a resolver copied through ?? inside a helper', doublingHelper, 100, 4, () => [PROMISE]],
    ['a resolver bag copied through ?? N times', doublingFlow, 100, 4, () => [PROMISE]],
    ['script text round a ring of variables', scriptRing, 100, 4, () => [API]],
    ['script text round a ring of arrays', scriptRingBags, 40, 4, () => [API]],
  ] as const) {
    it(`grows under 6x for ${factor === 4 ? '4x the input' : '4x the edges'}: ${name}`, async () => {
      const big = small * factor;
      expect(await ruleIds(make(small))).toEqual(ids(small));
      expect(await ruleIds(make(big))).toEqual(ids(big));
      const { base, slow, ratio } = await costRatio(ops, make, small, big);
      if (process.env.SLEEP_OPS_LOG) console.log(`${name}: ${base} ops at ${small}, ${slow} ops at ${big}, ratio ${ratio.toFixed(2)}`);
      expect(ratio, `${name}: ${base} ops at ${small}, ${slow} ops at ${big}`).toBeLessThan(6);
    }, 120_000);
  }

  // The check itself, against stubs with a known cost: quadratic growth must read 16 and linear growth 4, and a stub that counts nothing
  // must not pass for cheap.
  it('reads quadratic growth as over the bound, linear growth as under it, and an empty count as a failure', async () => {
    const text = (n: number) => 'x'.repeat(n);
    const quadratic = async (code: string) => code.length ** 2;
    const linear = async (code: string) => code.length;
    expect((await costRatio(quadratic, text, 100, 400)).ratio).toBe(16);
    expect((await costRatio(linear, text, 100, 400)).ratio).toBe(4);
    await expect(costRatio(async () => 0, text, 100, 400)).rejects.toThrow('nothing was counted');
    await expect(costRatio(async (code) => (code.length > 100 ? 0 : 5), text, 100, 400)).rejects.toThrow('nothing was counted');
  });
});

// A cut recursion is not remembered: `a` and `b` call each other, and each executor reaches a timer through
// whichever it calls first. Remember the cut walk and the second executor reads an empty answer.
describe('follow memo', () => {
  it('reports both executors when two helpers call each other', async () => {
    const code =
      'function a(f: () => void): void { b(f); setTimeout(f, 5); } function b(f: () => void): void { a(f); } await new Promise<void>((r) => a(r)); await new Promise<void>((r) => b(r));';
    expect(await ruleIds(code)).toEqual([PROMISE, PROMISE]);
  });

  it('walks a helper once per parameter, not once per function', async () => {
    const make = (calls: string) =>
      `const after = (a: unknown, f: unknown) => { void a; setTimeout(f as () => void, 50); }; await new Promise<void>((r) => { ${calls} });`;
    expect(await ruleIds(make('after(r, 0); after(0, r);'))).toEqual([PROMISE]);
    expect(await ruleIds(make('after(0, r); after(r, 0);'))).toEqual([PROMISE]);
    // The resolve only ever lands in the parameter the timer ignores.
    expect(await ruleIds(make('after(r, 0); after(r, 1);'))).toEqual([]);
  });
});

// A walk that recurses once per link throws a RangeError at about two thousand links, and a throw aborts the lint run, so
// every follow walk keeps its own stack. Each chain is 3000 links with a sleep or a clock loop at the end.
describe('long chains', () => {
  const N = 3000;
  const chain = (first: string, link: (i: number) => string, last: (n: number) => string) =>
    [first, ...Array.from({ length: N }, (_, i) => link(i + 1)), last(N)].join('\n');
  const copies = (a: string, b: string, last: (n: number) => string) => chain(`const ${a}0 = ${b};`, (i) => `const ${a}${i} = ${a}${i - 1};`, last);
  const cases: Record<string, [string, string]> = {
    'const copies of a clock': [copies('k', 'Date.now', (n) => `while (k${n}() < 5) {}`), API],
    'copies of a host': [copies('g', 'globalThis', (n) => `await new Promise<void>((r) => g${n}.setTimeout(r, 50));`), PROMISE],
    'destructured copies of a host': [
      chain('const g0 = globalThis;', (i) => `const { self: g${i} } = g${i - 1};`, (n) => `await new Promise<void>((r) => g${n}.setTimeout(r, 50));`),
      PROMISE,
    ],
    'copies of a timer through casts': [chain('const c0 = setTimeout as any;', (i) => `const c${i} = c${i - 1} as any;`, (n) => `await new Promise<void>((r) => c${n}(r, 50));`), ALIAS],
    'copies of Promise': [copies('P', 'Promise', (n) => `await new P${n}<void>((r) => setTimeout(r, 50));`), PROMISE],
    'helpers that each call the one below': [
      chain('function h0(f: () => void) { setTimeout(f, 5); }', (i) => `function h${i}(f: () => void) { h${i - 1}(f); }`, (n) => `await new Promise<void>((r) => h${n}(r));`),
      PROMISE,
    ],
    'copies of a timer key': [copies('k', "'setTimeout'", (n) => `await new Promise<void>((r) => globalThis[k${n}](r, 50));`), PROMISE],
    'copies of a script': [copies('s', "'setTimeout(() => 0, 5)'", (n) => `await page.evaluate(s${n});`), API],
    'copies of undefined behind a default': [
      chain('const u0 = undefined;', (i) => `const u${i} = u${i - 1};`, (n) => `function run(s = 'setTimeout(() => 0, 5)') { return page.evaluate(s); } run(u${n});`),
      API,
    ],
    'copies of withResolvers': [
      copies('m', 'Promise.withResolvers', (n) => `const b = m${n}.call(Promise); await new Promise<void>((r) => { setTimeout(b.resolve, 5); void r; });`),
      PROMISE,
    ],
  };
  for (const [name, [code, rule]] of Object.entries(cases)) {
    it(`reports ${name} without a stack overflow`, async () => {
      const ids = await ruleIds(code);
      expect(ids.length).toBeGreaterThan(0);
      expect(new Set(ids)).toEqual(new Set([rule]));
    });
  }
});

describe('one message per shape', () => {
  // A destructure is matched by more than one selector arm; each shape must still report once.
  for (const [row, code, , id] of bannedCases.filter(([, , , messageId]) => messageId === 'destructure')) {
    it(`reports row ${row} once`, async () => {
      expect((await sleepMessages(code)).filter((m) => m.messageId === id)).toHaveLength(1);
    });
  }
});
