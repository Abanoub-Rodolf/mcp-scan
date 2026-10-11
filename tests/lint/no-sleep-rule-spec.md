# No-sleep lint rule spec (canonical, 2026-10-10)

Every repo's "no fixed sleeps in tests" ESLint rule must meet this. A contributor hardening one repo's rule reads this first, so it does not rediscover the bypass list.

Built from: theboctorwedding `sleep-rule-gaps` (`eslint.config.mjs`, `scripts/lint-no-sleep.test.mjs`), chat-export-extension `sleep-rule-gaps` (`eslint.config.js`, `tests/lint/no-sleep.test.ts`), mcp-scan `origin/main` (`eslint.config.js`, plus its `tests/lint/no-sleep-promise.test.ts`). Every snippet below was run through those three configs with ESLint `lintText` on 2026-10-10 (status in section 6).

## 1. The contract

Tests sync on a signal (marker file, log line, reply, element state, fake timers), never on a fixed sleep; a timer is legal only as a poll interval inside a loop with one shared deadline, or as a deadline guard that rejects. Error paths answer every in-flight request, so a failed write, pipe or queue never leaves a request unanswered (full text: `agent-execution-contract.md`, Tests and failure paths).

The lint rule enforces the first half. It must be hard to bypass by accident: every shape below is something a contributor, a code assistant or a tired person actually writes.

## 2. Bypass classes: every row MUST be reported (256 rows)

Each snippet sits at the top level of an in-scope test file. `r` is the resolve, `rej` the reject. A row passes only when the named rule id reports it (section 5).

| ID | Bypass | Planted snippet |
|---|---|---|
| 1 | setInterval parity | `await new Promise<void>((r) => { const id = setInterval(() => { clearInterval(id); r(); }, 50); });` |
| 2a | `.call` | `await new Promise((r) => setTimeout.call(globalThis, r, 50));` |
| 2b | `.apply` | `await new Promise((r) => setTimeout.apply(globalThis, [r, 50]));` |
| 2b:self-bare | the global self calling the timer inside an executor | `await new Promise<void>((r) => self.setTimeout(r, 50));` |
| 2b:self-copy | a local self that is a copy of the real host | `const self = globalThis; await new Promise<void>((r) => self.setTimeout(r, 50));` |
| 2b:self-default | a parameter named self that defaults to the real host | `const f = (self = globalThis) => new Promise<void>((r) => self.setTimeout(r, 50)); await f();` |
| 2b:self-declared | an ambient declare const self is still the host | `declare const self: Window; await new Promise<void>((r) => self.setTimeout(r, 50));` |
| 2b:window-declared | an ambient declare var window is still the host | `declare var window: Window; await new Promise<void>((r) => window.setTimeout(r, 50));` |
| 2c | `.bind` | `await new Promise((r) => setTimeout.bind(globalThis)(r, 50));` |
| 2d | comma expression | `await new Promise((r) => (0, setTimeout)(r, 50));` |
| 2d:fallback | comma-free callee, `undefined ?? setTimeout` | `await new Promise((r) => (undefined ?? setTimeout)(r, 50));` |
| 2d:conditional | callee picked by a conditional | `await new Promise((r) => (pick ? setTimeout : other)(r, 50));` |
| 2e:host-var | host held in a const | `const g = globalThis; await new Promise((r) => g.setTimeout(r, 50));` |
| 3a | timers/promises import | `import { setTimeout as wait } from 'node:timers/promises'; await wait(50);` |
| 3b | timers import (bare name) | `import timers from 'timers'; void timers;` |
| 3c | timers require | `const t = require('node:timers'); void t;` |
| 3d | timers dynamic import | `const t = await import('timers/promises'); void t;` |
| 3e | getBuiltinModule | `const t = process.getBuiltinModule('node:timers'); void t;` |
| 3f | scheduler.wait | `await scheduler.wait(50);` and `await (globalThis as any).scheduler.wait(50);` |
| 3a:export | re-exported by name | `export { setTimeout } from 'node:timers/promises';` |
| 3a:named | named import from node:timers, called through an alias | `import { setTimeout as st } from 'node:timers'; st(() => undefined, 50);` |
| 3a:mixed | one value specifier beside a type specifier | `import { type Timeout, setTimeout as st } from 'node:timers'; st(() => undefined, 50);` |
| 3a:side-effect | bare import of the module | `import 'node:timers';` |
| 3b:export-all | `export *` re-export | `export * from 'timers';` |
| 3b:export-ns | `export * as` re-export | `export * as t from 'node:timers/promises';` |
| 3b:export-mixed | re-export with one value specifier beside a type one | `export { type Timeout, setTimeout } from 'node:timers';` |
| 3c:import-equals | `import t = require()` | `import t = require('timers'); void t;` |
| 3c:template | require, name as a template with no hole | `` const t = require(`node:timers`); void t; `` |
| 3c:const | require, name held in a const | `const m = 'node:timers'; const t = require(m); void t;` |
| 3d:template | dynamic import, name as a template with no hole | `` const t = await import(`node:timers/promises`); void t; `` |
| 3d:let | dynamic import, name held in a let, judged by every write | `let m = 'timers'; const t = await import(m); void t;` |
| 3d:let-reversed | dynamic import, name in a let whose last write is the timers module | `let m = './x'; m = 'timers'; const t = await import(m); void t;` |
| 3e:computed | getBuiltinModule behind a computed key | `const t = process['getBuiltinModule']('timers'); void t;` |
| 3e:template | getBuiltinModule, name as a template with no hole | `` const t = process.getBuiltinModule(`timers`); void t; `` |
| 3e:const | getBuiltinModule, name held in a const | `const m = 'timers'; const t = process.getBuiltinModule(m); void t;` |
| 3c:hole | require, template that starts with timers and has a hole | `` const t = require(`timers${suffix}`); void t; `` |
| 3d:hole | dynamic import, template that starts with timers and has a hole | `` const t = await import(`timers${suffix}`); void t; `` |
| 3e:hole | getBuiltinModule, template with a hole, node: prefix | `` const t = process.getBuiltinModule(`node:timers${suffix}`); void t; `` |
| 3d:hole-const | import, name held in a const template with a hole | `` const m = `timers${suffix}`; const t = await import(m); void t; `` |
| 3f:alias | scheduler held in a const | `const s = globalThis.scheduler; await s.wait(50);` |
| 3f:destructured-host | scheduler destructured off the host | `const { scheduler: s } = globalThis; await s.wait(50);` |
| 3f:import | scheduler imported from node:timers/promises | `import { scheduler } from 'node:timers/promises'; await scheduler.wait(50);` |
| 3g | promisify wrapped around the timer | `import { promisify } from 'node:util'; await promisify(setTimeout)(50);` |
| 3g:host | promisify wrapped around the host's timer | `import { promisify } from 'node:util'; const wait = promisify(globalThis.setTimeout);` |
| 4a | Promise via alias | `const P = Promise; await new P((r) => setTimeout(r, 50));` |
| 4b | Promise via globalThis | `await new globalThis.Promise((r) => setTimeout(r, 50));` |
| 4c | Promise via cast | `await new (Promise as any)((r: () => void) => setTimeout(r, 50));` |
| 4d | Promise subclass | `class P extends Promise<void> {} await new P((r) => setTimeout(r, 50));` |
| 4e | Promise destructured off the host | `const { Promise: P } = globalThis; await new P((r) => setTimeout(r, 50));` |
| 4a:reassigned | Promise copied by assignment | `let P; P = Promise; await new P((r) => setTimeout(r, 50));` |
| 4a:fallback | Promise behind `undefined ?? Promise` | `const P = undefined ?? Promise; await new P((r) => setTimeout(r, 50));` |
| 4a:logical | Promise behind `\|\|` | `const P = (globalThis as any).Fake \|\| Promise; await new P((r) => setTimeout(r, 50));` |
| 4a:default-param | Promise as a parameter default | `async function run(P = Promise) { await new P((r) => setTimeout(r, 50)); } await run();` |
| 4a:default-undefined | Promise default, the only call passes `undefined` | `async function run(P = Promise, ms = 0) { await new P((r) => setTimeout(r, ms)); } await run(undefined, 50);` |
| 4a:default-exported | Promise default on an exported function, called with another value here | `export async function run(P = Promise) { await new P((r) => setTimeout(r, 50)); } await run(Fake);` |
| 4a:default-exported-const | the same on an exported arrow | `export const run = async (P = Promise) => { await new P((r) => setTimeout(r, 50)); }; await run(Fake);` |
| 4a:default-export-list | the same, exported by name in a list | `async function run(P = Promise) { await new P((r) => setTimeout(r, 50)); } export { run }; await run(Fake);` |
| 4a:default-maybe | one call passes a conditional that may be undefined | `async function run(P = Promise) { await new P((r) => setTimeout(r, 50)); } await run(pick ? undefined : Fake);` |
| 4a:default-maybe-logical | one call passes a fallback that may be undefined | `async function run(P = Promise) { await new P((r) => setTimeout(r, 50)); } await run(opts.P ?? undefined);` |
| 4a:default-undefined-var | the only call passes a name set to `undefined` | `async function run(P = Promise) { await new P((r) => setTimeout(r, 50)); } const u = undefined; await run(u);` |
| 4a:default-undefined-copy | the same through a second name | `async function run(P = Promise) { await new P((r) => setTimeout(r, 50)); } const u = undefined; const v = u; await run(v);` |
| 4a:reflect | `Reflect.construct(Promise, ...)` | `await Reflect.construct(Promise, [(r: () => void) => setTimeout(r, 50)]);` |
| 4a:reflect-alias | `Reflect.construct` on an alias | `const P = Promise; await Reflect.construct(P, [(r: () => void) => setTimeout(r, 50)]);` |
| 4a:reflect-args | `Reflect.construct` with unreadable args (opaque) | `await Reflect.construct(Promise, args);` |
| 4b:reflect | `Reflect.construct` on `globalThis.Promise` | `await Reflect.construct(globalThis.Promise, [(r: () => void) => setTimeout(r, 50)]);` |
| 4c:reflect | `Reflect.construct` on a cast Promise | `await Reflect.construct(Promise as any, [(r: () => void) => setTimeout(r, 50)]);` |
| 4d:reflect | `Reflect.construct` on a subclass | `class P extends Promise<void> {} await Reflect.construct(P, [(r: () => void) => setTimeout(r, 50)]);` |
| 4e:reflect | `Reflect.construct` on a destructured Promise | `const { Promise: P } = globalThis; await Reflect.construct(P, [(r: () => void) => setTimeout(r, 50)]);` |
| 4e:host-var | Promise destructured off a host held in a const | `const g = globalThis; const { Promise: P } = g; await new P((r) => setTimeout(r, 5));` |
| 4e:assign | Promise destructured by assignment off the host | `let P; ({ Promise: P } = globalThis); await new P((r) => setTimeout(r, 50));` |
| 4e:param | Promise destructured in a parameter default off the host | `async function run({ Promise: P } = globalThis) { await new P((r) => setTimeout(r, 50)); } await run();` |
| 4e:reflect-assign | `Reflect.construct` on a Promise destructured by assignment | `let P; ({ Promise: P } = globalThis); await Reflect.construct(P, [(r: () => void) => setTimeout(r, 50)]);` |
| 4x:race | resolver given to a listener beside a timer (section 4) | `await new Promise((r) => { server.on('x', r); setTimeout(r, 5000); });` |
| 4x:noop | resolver given to any call beside a timer (section 4) | `await new Promise((r) => { noop(r); setTimeout(r, 50); });` |
| 5 | resolve to a same-file helper that times | `const after = (f: () => void) => setTimeout(f, 50); await new Promise<void>((r) => after(r));` |
| 5:swapped | same helper, resolve in the parameter the timer ignores first, then in the one it uses | `const after = (a: unknown, f: unknown) => { void a; setTimeout(f as () => void, 50); }; await new Promise<void>((r) => { after(r, 0); after(0, r); });` |
| 5:fallback | helper copies the resolve behind `??` before the timer | `function h(f: () => void) { const a = f ?? f; setTimeout(a, 5); } await new Promise<void>((r) => h(r));` |
| 5:ternary | helper copies the resolve behind a conditional before the timer | `function h(f: () => void) { const a = pick ? f : f; setTimeout(a, 5); } await new Promise<void>((r) => h(r));` |
| 5:bind | resolve bound before it is handed to a timing helper | `function after(f: () => void) { setTimeout(f, 50); } await new Promise<void>((r) => after(r.bind(null)));` |
| 5:wrapper | resolve wrapped in an arrow before it is handed to a timing helper | `function after(f: () => void) { setTimeout(f, 50); } await new Promise<void>((r) => after(() => r()));` |
| 5:wrapper-fn | resolve wrapped in a function expression with a block body | `function after(f: () => void) { setTimeout(f, 50); } await new Promise<void>((r) => after(function () { r(); }));` |
| 5:this-param | helper that declares a TypeScript this parameter before the callback | `function after(this: void, f: () => void) { setTimeout(f, 50); } await new Promise<void>((r) => after(r));` |
| 5:this-param-wrapper | the same with the resolve wrapped and a defaulted delay after it | `function after(this: void, f: () => void, ms = 50) { setTimeout(f, ms); } await new Promise<void>((r) => after(() => r()));` |
| 5:wrapper-call | resolve run through call inside a wrapper handed to a timing helper | `function after(f: () => void) { setTimeout(f, 50); } await new Promise<void>((r) => after(() => r.call(null)));` |
| 5:bind-twice | resolve bound twice before it is handed to a timing helper | `function after(f: () => void) { setTimeout(f, 50); } await new Promise<void>((r) => after(r.bind(null).bind(null)));` |
| 5:overload | resolve handed to an overloaded helper that times its parameter | `function after(f: () => void): void; function after(f: () => void, ms: number): void; function after(f: () => void, ms = 50): void { setTimeout(f, ms); } await new Promise<void>((r) => after(() => r()));` |
| 6 | resolve alias, then timer, reject only named | `await new Promise((r, rej) => { const ok = r; setTimeout(() => { ok(); void rej; }, 50); });` |
| 6:named-callback | timer callback declared in the file, touches resolve and names reject | `await new Promise((r, rej) => { const go = () => { r(); void rej; }; setTimeout(go, 50); });` |
| 6:bind-resolve | resolve handed over bound (`r.bind(null)`), reject named | `await new Promise((r, rej) => { void rej; setTimeout(r.bind(null), 50); });` |
| 6:literal | resolve held in an object literal, reject named | `await new Promise((r, rej) => { const o = { r }; setTimeout(() => { o.r(); rej(new Error('late')); }, 50); });` |
| 6:array | resolve held in an array literal, reject named | `await new Promise((r, rej) => { const a = [r]; setTimeout(() => { a[0](); rej(new Error('late')); }, 50); });` |
| 6:held | resolve stored in an array, the timer drains it beside a reject | `await new Promise((r, rej) => { const rs: Array<() => void> = []; rs.push(r); setTimeout(() => { rs.forEach((f) => f()); rej(new Error('late')); }, 50); });` |
| 6:emit | resolve given to a listener, the timer emits the event beside a reject | `await new Promise((r, rej) => { ee.on('x', r); setTimeout(() => { ee.emit('x'); rej(new Error('late')); }, 50); });` |
| 6:listener | resolve given to a listener, the timer never rejects | `await new Promise((r) => { child.on('exit', r); setTimeout(() => { child.kill(); }, 50); });` |
| 6:wrapper | timer callback calls a function declared in the file that calls resolve | `await new Promise((r, rej) => { const go = () => { r(); }; setTimeout(() => { go(); rej(new Error('late')); }, 50); });` |
| 6:outer | resolve stored in an outer variable, a helper declared in the file calls it | `let ok = () => undefined; const late = (j: (e: Error) => void) => { ok(); void j; }; await new Promise((r, rej) => { ok = r; setTimeout(() => late(rej), 50); });` |
| 7a | defaulted resolve param | `await new Promise((r = () => undefined) => setTimeout(r, 50));` |
| 7b | defaulted resolve, reject named | `await new Promise((r = () => undefined, rej) => setTimeout(() => { r(); void rej; }, 50));` |
| 7a:default-fn | defaulted resolve param on a named executor | `function ex(r = () => undefined) { setTimeout(r, 50); } await new Promise(ex);` |
| 8a | destructure, identifier key | `const { setTimeout: wait } = globalThis; await new Promise((r) => wait(r, 50));` |
| 8b | destructure, string key | `const { 'setTimeout': wait } = window; await new Promise((r) => wait(r, 50));` |
| 8c | destructure, computed literal key | `const { ['setTimeout']: wait } = self; await new Promise((r) => wait(r, 50));` |
| 8d | destructure, computed variable key | `const k = 'setTimeout'; const { [k]: wait } = globalThis; await new Promise((r) => wait(r, 50));` |
| 8a:assign | destructure by assignment off the host | `let wait; ({ setTimeout: wait } = globalThis); await new Promise((r) => wait(r, 50));` |
| 8a:param | destructure in a parameter default off the host | `async function run({ setTimeout: wait } = globalThis) { await new Promise((r) => wait(r, 50)); } await run();` |
| 8a:default-void | host default, the only call passes `void 0` | `function run({ setTimeout: wait } = globalThis) { return new Promise((r) => wait(r, 50)); } run(void 0);` |
| 8a:cast | destructure off the host behind a cast | `const { setTimeout: wait } = globalThis as any; await new Promise((r) => wait(r, 50));` |
| 8a:cast2 | destructure off the host behind two casts | `const { setTimeout: wait } = globalThis as unknown as Window; await new Promise((r) => wait(r, 50));` |
| 8a:comma | destructure off the host behind a comma | `const { setTimeout: wait } = (0, globalThis); await new Promise((r) => wait(r, 50));` |
| 8a:logical | destructure off the host behind `??` | `const { setTimeout: wait } = globalThis ?? window; await new Promise((r) => wait(r, 50));` |
| 8a:conditional | destructure off the host behind a conditional | `const { setTimeout: wait } = pick ? globalThis : window; await new Promise((r) => wait(r, 50));` |
| 8a:nested | destructure under a host key | `const { window: { setTimeout: wait } } = globalThis; await new Promise((r) => wait(r, 50));` |
| 8a:host-var | destructure off a host held in a const | `const g = globalThis; const { setTimeout: wait } = g; await new Promise((r) => wait(r, 50));` |
| 8a:default | destructure off the host with a default value | `const { setTimeout: wait = fallback } = globalThis; await new Promise((r) => wait(r, 50));` |
| 8d:let | computed key held in a let, judged by every write | `let k = 'setTimeout'; const { [k]: wait } = globalThis; await new Promise((r) => wait(r, 50));` |
| 8d:let-member | let key on a member call | `let k = 'setTimeout'; await new Promise((r) => (globalThis as any)[k](r, 50));` |
| 8d:let-twice | timer key in a let written twice, both timer | `let k = 'setTimeout'; k = 'setTimeout'; await new Promise((r) => (globalThis as any)[k](r, 50));` |
| 8d:let-reversed | timer key in a let whose last write is the timer | `let k = 'title'; k = 'setTimeout'; await new Promise((r) => (globalThis as any)[k](r, 50));` |
| 9a | object alias of the timer | `const box = { wait: setTimeout }; await new Promise((r) => box.wait(r, 50));` |
| 9b | array alias of the timer | `const fns = [setTimeout]; await new Promise((r) => fns[0](r, 50));` |
| 9a:plain | plain alias of the timer | `const w = setTimeout; await new Promise((r) => w(r, 50));` |
| 9a:shorthand | timer kept by object shorthand | `const box = { setTimeout }; await new Promise((r) => box.setTimeout(r, 50));` |
| 9b:destructure | timer taken out of an array literal by destructuring | `const [wait] = [setTimeout]; await new Promise((r) => wait(r, 50));` |
| 9c | default-param alias | `async function run(wait = setTimeout) { await new Promise((r) => wait(r, 50)); } await run();` |
| 9d:return | timer returned from a function | `function mk() { return setTimeout; } const w = mk(); await new Promise((r) => w(r, 50));` |
| 9d:arrow | timer returned from an arrow call | `const w = (() => setTimeout)(); await new Promise((r) => w(r, 50));` |
| 9d:template | timer put into a template | `` const t = `${setTimeout}`; void t; `` |
| 9d:default-global | timer as a parameter default, off the host | `const run = async (wait = globalThis.setTimeout) => new Promise((r) => wait(r, 50)); await run();` |
| 9d:default-destructured | timer as a destructured parameter default | `async function run({ wait = setTimeout } = {}) { await new Promise((r) => wait(r, 50)); } await run();` |
| 9x:cast | timer passed as a value behind a cast | `run(setTimeout as never);` |
| 9x:host | the host's timer passed as a value | `run(globalThis.setTimeout);` |
| 9x:host-computed | the host's timer passed through a literal key | `run(globalThis['setTimeout']);` |
| 9x:host-var | the timer passed off a const that holds the host | `const g = globalThis; run(g.setTimeout);` |
| 9x:host-cast | the timer passed off a cast host | `run((globalThis as any).setTimeout);` |
| 9x:matcher-inner | the timer handed to a call inside a matcher's argument | `expect(1).toBe(run(setTimeout));` |
| 9x:matcher-inner-host | the host's timer handed to a call inside a matcher's argument | `expect(1).toBe(run(globalThis.setTimeout));` |
| 9x:host-destructured | the timer passed off a host destructured from the host | `const { window: w } = globalThis; run(w.setTimeout);` |
| 9x:host-new | the host's timer handed to a constructor | `new Runner(globalThis.setInterval);` |
| 10a | withResolvers, object kept | `const d = Promise.withResolvers<void>(); setTimeout(() => d.resolve(), 50); await d.promise;` |
| 10b | withResolvers, destructured | `const { promise, resolve } = Promise.withResolvers<void>(); setTimeout(resolve, 50); await promise;` |
| 10c | withResolvers, assigned | `let d; d = Promise.withResolvers<void>(); setTimeout(d.resolve, 50); await d.promise;` |
| 10c:destructure | withResolvers destructured by assignment | `let resolve: () => void; ({ resolve } = Promise.withResolvers<void>()); setTimeout(resolve, 50);` |
| 10d | leak through a cast or paren | `const d = Promise.withResolvers<void>(); setTimeout((d as any).resolve, 50); await d.promise;` |
| 10e | leak through a comma | `const d = Promise.withResolvers<void>(); setTimeout((0, d.resolve), 50); await d.promise;` |
| 10f | leak through optional chaining | `const d = Promise.withResolvers<void>(); setTimeout(() => d?.resolve(), 50); await d.promise;` |
| 10f:optional-ref | leak through an optional chain, as a value | `const d = Promise.withResolvers<void>(); setTimeout(d?.resolve, 50); await d.promise;` |
| 10f:optional-call | leak through an optional call | `const d = Promise.withResolvers<void>(); setTimeout(() => d.resolve?.(), 50); await d.promise;` |
| 10g | leak through a computed member | `const d = Promise.withResolvers<void>(); setTimeout(d['resolve'], 50); await d.promise;` |
| 10h | leak through an array store | `const q: Array<() => void> = []; const d = Promise.withResolvers<void>(); q.push(d.resolve); setTimeout(() => q[0](), 50); await d.promise;` |
| 10i | withResolvers via globalThis or cast | `const d = (Promise as any).withResolvers(); setTimeout(() => d.resolve(), 50); await d.promise;` |
| 10j | second hop (mcp-scan already closes it) | `const d = Promise.withResolvers<void>(); const { resolve } = d; setTimeout(resolve, 50); await d.promise;` |
| 10a:field | class field bag | `class A { d = Promise.withResolvers<void>(); go() { setTimeout(() => this.d.resolve(), 5); return this.d.promise; } }` |
| 10a:field-private | private class field bag | `class A { #d = Promise.withResolvers<void>(); go() { setTimeout(() => this.#d.resolve(), 5); return this.#d.promise; } }` |
| 10a:field-static | static class field bag | `class A { static d = Promise.withResolvers<void>(); } setTimeout(() => A.d.resolve(), 5); await A.d.promise;` |
| 10a:class-expr | static field of a class held in a const | `const A = class { static d = Promise.withResolvers<void>(); }; setTimeout(() => A.d.resolve(), 5); await A.d.promise;` |
| 10a:static-this | `this.d` inside a static method | `class A { static d = Promise.withResolvers<void>(); static go() { setTimeout(() => this.d.resolve(), 5); return this.d.promise; } }` |
| 10a:static-by-name | static bag reached by the class name inside a method | `class A { static d = Promise.withResolvers<void>(); static go() { setTimeout(() => A.d.resolve(), 5); return A.d.promise; } } await A.go();` |
| 10a:static-private | private static bag reached by the class name inside a method | `class A { static #d = Promise.withResolvers<void>(); static go() { setTimeout(() => A.#d.resolve(), 5); return A.#d.promise; } } await A.go();` |
| 10a:static-block | stored in a class static block, resolve handed to a timer | `class Q { static r: any; static { Q.r = Promise.withResolvers<void>(); } } setTimeout(Q.r.resolve, 5);` |
| 10h:bag-object | bag stored in an object literal | `const d = Promise.withResolvers<void>(); const e = { d }; setTimeout(() => e.d.resolve(), 50); await d.promise;` |
| 10h:bag-key | bag stored under a key | `const d = Promise.withResolvers<void>(); const e = { x: d }; setTimeout(() => e.x.resolve(), 50); await d.promise;` |
| 10h:bag-array | bag stored in an array literal | `const d = Promise.withResolvers<void>(); const q = [d]; setTimeout(() => q[0].resolve(), 50); await d.promise;` |
| 10h:bag-nested | bag nested in object and array literals | `const d = Promise.withResolvers<void>(); const e = { a: { b: [d] } }; setTimeout(() => e.a.b[0].resolve(), 50); await d.promise;` |
| 10i:call | `Promise.withResolvers.call(Promise)` | `const d = Promise.withResolvers.call(Promise); setTimeout(d.resolve, 50); await d.promise;` |
| 10i:apply | `.apply(Promise, [])` | `const d = Promise.withResolvers.apply(Promise, []); setTimeout(d.resolve, 50); await d.promise;` |
| 10i:bind | `.bind(Promise)()` | `const d = Promise.withResolvers.bind(Promise)(); setTimeout(d.resolve, 50); await d.promise;` |
| 10i:bound-const | bound once into a const | `const mk = Promise.withResolvers.bind(Promise); const d = mk(); setTimeout(d.resolve, 50); await d.promise;` |
| 10i:let-reassigned | bound `withResolvers` held in a let that is reassigned to it | `let mk: any = null; mk = Promise.withResolvers.bind(Promise); const d = mk(); setTimeout(d.resolve, 50); await d.promise;` |
| 10i:let-reversed | bound `withResolvers` in a let whose last write is something else | `let mk: any = Promise.withResolvers.bind(Promise); mk = null; const d = mk(); setTimeout(d.resolve, 50); await d.promise;` |
| 10i:destructured-call | destructured, then `.call` | `const { withResolvers: mk } = Promise; const d = mk.call(Promise); setTimeout(d.resolve, 50); await d.promise;` |
| 10j:bag-object | second hop through a bag in an object | `const d = Promise.withResolvers<void>(); const e = { d }; const { resolve } = e.d; setTimeout(resolve, 50); await d.promise;` |
| 10l:copy-before | copy taken before the bag exists, inside an if | `let a: any; let b: any; if (x) { b = a; } a = Promise.withResolvers<void>(); setTimeout(b.resolve, 5);` |
| 10l:copy-in-fn | copy inside a function called later | `let a: any; let b: any; function copy() { b = a; } a = Promise.withResolvers<void>(); copy(); setTimeout(b.resolve, 5);` |
| 10l:chain | copy chain written in reverse order | `let a: any; let b: any; let c: any; c = b; b = a; a = Promise.withResolvers<void>(); setTimeout(c.resolve, 5);` |
| 10m:fallback | stored resolve copied behind `??` | `const d = Promise.withResolvers<void>(); const a = d.resolve ?? d.resolve; setTimeout(a, 5); await d.promise;` |
| 10k:callback | timer callback declared in the file resolves the bag | `const d = Promise.withResolvers<void>(); const f = () => d.resolve(); setTimeout(f, 5); await d.promise;` |
| 10k:declared | same, function declaration | `const d = Promise.withResolvers<void>(); function f() { d.resolve(); } setTimeout(f, 5); await d.promise;` |
| 10k:bind | resolve bound into the callback | `const d = Promise.withResolvers<void>(); const f = d.resolve.bind(d); setTimeout(f, 5); await d.promise;` |
| 10k:wrapper | timer callback calls a function declared in the file that resolves the bag | `const d = Promise.withResolvers<void>(); const f = () => d.resolve(); setTimeout(() => f(), 5); await d.promise;` |
| 10k:hop | that function sits behind another one, beside a reject | `const d = Promise.withResolvers<void>(); const g = () => d.resolve(); const f = () => { d.reject(new Error('late')); g(); }; setTimeout(f, 5); await d.promise;` |
| 11a | waitForTimeout, any receiver | `await tab.waitForTimeout(500);` and `await getTab().waitForTimeout(500);` |
| 11a:page | waitForTimeout on a page | `await page.waitForTimeout(500);` |
| 11b | waitForTimeout, computed key | `await page['waitForTimeout'](500);` and `const k = 'waitForTimeout'; await (page as any)[k](500);` |
| 11c | waitForTimeout call/apply/bind | `await page.waitForTimeout.call(page, 500);` |
| 11d | waitForTimeout destructured | `const { waitForTimeout: w } = page; await w(500);` |
| 11e | waitForTimeout passed as a value | `run(page.waitForTimeout);` |
| 11b:let-twice | driver key in a let whose first write is the wait | `let k = 'waitForTimeout'; k = 'title'; await (page as any)[k]();` |
| 11b:let-reversed | driver key in a let whose last write is the wait | `let k = 'title'; k = 'waitForTimeout'; await (page as any)[k](500);` |
| 12a | script string to evaluate | `await tab.evaluate('new Promise((r) => setTimeout(r, 500))');` |
| 12a:string | script string handed to evaluate | `await page.evaluate('new Promise((r) => setTimeout(r, 500))');` |
| 12b | script template to waitForFunction | ``await page.waitForFunction(`new Promise((r) => setInterval(r, 5))`);`` |
| 12c | script string to addInitScript | `await context.addInitScript('setTimeout(() => undefined, 5)');` |
| 12d | script as `{ content }` | `await page.addInitScript({ content: 'setTimeout(() => undefined, 5)' });` |
| 12a:let | script held in a let | `let s = 'new Promise((r) => setTimeout(r, 500))'; await tab.evaluate(s);` |
| 12a:assigned | script assigned later | `let s: string; s = 'setTimeout(() => 0, 5)'; await page.evaluate(s);` |
| 12a:param | script as a parameter default | `async function run(s = 'new Promise((r) => setTimeout(r, 500))') { await tab.evaluate(s); } await run();` |
| 12a:param-undefined | script default, the only call passes `undefined` | `async function run(s = 'new Promise((r) => setTimeout(r, 500))') { await tab.evaluate(s); } await run(undefined);` |
| 12a:default-recursive | script default on a function that calls itself with the parameter | `async function poll(s = 'setTimeout(() => 0, 5)', n = 3): Promise<void> { await page.evaluate(s); if (n > 0) return poll(s, n - 1); } await poll();` |
| 12b:let | template script in a let | `` let s = `new Promise((r) => setInterval(r, 5))`; await page.waitForFunction(s); `` |
| 12c:let | init script in a let | `let s = 'setTimeout(() => undefined, 5)'; await context.addInitScript(s);` |
| 12d:let | `{ content }` script in a let | `let s = 'setTimeout(() => undefined, 5)'; await page.addInitScript({ content: s });` |
| 12a:let-twice | script in a let whose first write is a timer | `let s = 'setTimeout'; s = 'x'; await page.evaluate(s);` |
| 12a:let-reversed | script in a let whose last write is a timer | `let s = 'x'; s = 'setTimeout(() => 0, 5)'; await page.evaluate(s);` |
| 12a:let-append | script in a let that is appended to later | `let s = 'setTimeout(() => 0, 5)'; s += ''; await page.evaluate(s);` |
| 12e:function | function handed to addInitScript sets a timer | `await page.addInitScript(() => { setTimeout(() => undefined, 5); });` |
| 12e:local-fn | function declared in the file handed to evaluate | `const fn = () => { setTimeout(() => undefined, 5); }; await page.evaluate(fn);` |
| 12e:local-decl | function declaration handed to addInitScript | `function fn() { setTimeout(() => undefined, 5); } await page.addInitScript(fn);` |
| 12e:const | script const with no spaces | `const s = 'setTimeout(()=>0,5)'; await page.evaluate(s);` |
| 12f:eval | eval of a script that sets a timer | `eval('setTimeout(() => 0, 5)');` |
| 12f:eval-indirect | indirect eval, comma or global member | `(0, eval)('setTimeout(() => 0, 5)'); globalThis.eval('setTimeout(() => 0, 5)');` |
| 12f:eval-alias | eval held under another name | `const e = eval; e('setTimeout(() => 0, 5)');` |
| 12f:new-function | new Function with a body that sets a timer | `const f = new Function('r', 'setTimeout(r, 5)'); await new Promise((r) => f(r));` |
| 12f:function | Function called without new | `Function('setTimeout(() => 0, 5)')();` |
| 12f:function-alias | Function held under another name | `const F = Function; F('setTimeout(() => 0, 5)')();` |
| 13a | Atomics.wait | `Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);` |
| 13b | Atomics.waitAsync | `await Atomics.waitAsync(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500).value;` |
| 13a:alias | Atomics held in a const | `const A = Atomics; A.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);` |
| 13a:destructured-host | Atomics destructured off the host | `const { Atomics: A } = globalThis; A.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);` |
| 14a | Date.now busy loop, empty body | `const end = Date.now() + 500; while (Date.now() < end) {}` |
| 14b | performance.now busy loop | `const end = performance.now() + 500; for (; performance.now() < end; );` |
| 14c | busy loop, trivial body | `const end = Date.now() + 500; let n = 0; while (Date.now() < end) { n++; }` |
| 14d:flag | clock guard in the body, test is a flag | `let done = false; const end = Date.now() + 500; while (!done) { if (Date.now() > end) break; }` |
| 14d:one | clock guard in the body, test is `1` | `const end = Date.now() + 500; while (1) { if (Date.now() > end) break; }` |
| 14d:for | clock guard in a `for` with an unbounded test | `const end = Date.now() + 500; for (let i = 0; i < 1e9; i++) { if (Date.now() > end) break; }` |
| 14d:var | clock read into a variable that guards the exit | `const end = Date.now() + 500; while (true) { const t = Date.now(); if (t > end) break; }` |
| 14d:assign | clock read assigned, block break | `const end = Date.now() + 500; let t = 0; for (;;) { t = performance.now(); if (t > end) { break; } }` |
| 14d:return | clock guard that returns | `const end = Date.now() + 500; (() => { while (true) { if (Date.now() > end) return; } })();` |
| 14d:set-flag | clock guard sets the flag the test reads | `let done = false; const end = Date.now() + 500; while (!done) { if (Date.now() > end) done = true; }` |
| 14d:assign-flag | clock comparison assigned to the flag the test reads | `let done = false; const end = Date.now() + 500; while (!done) { done = Date.now() > end; }` |
| 14d:continue | clock guard that continues, then breaks | `const end = Date.now() + 500; while (true) { if (Date.now() < end) continue; break; }` |
| 14d:else | break in the else branch | `const end = Date.now() + 500; while (true) { if (Date.now() < end) {} else break; }` |
| 14d:block | break behind another statement in the block | `let n = 0; const end = Date.now() + 500; while (true) { if (Date.now() > end) { n = 1; break; } }` |
| 14d:throw | clock guard that throws | `const end = Date.now() + 500; while (true) { if (Date.now() > end) throw e; }` |
| 14d:throw-new | clock guard that throws a new error | `const end = Date.now() + 500; while (true) { if (Date.now() > end) throw new Error('late'); }` |
| 14d:member | clock read into a member path that guards the exit | `const end = Date.now() + 500; const box = { t: 0 }; while (true) { box.t = Date.now(); if (box.t > end) break; }` |
| 14d:derived | clock read into a variable, another variable derived from it guards the exit | `const end = Date.now() + 500; while (true) { const t = Date.now(); const left = end - t; if (left < 0) break; }` |
| 14d:test-var | loop test is a variable the body sets from the clock | `const end = Date.now() + 500; let t = Date.now(); while (t < end) { t = Date.now(); }` |
| 14d:test-var-do | the same in a do-while | `const end = Date.now() + 500; let t = 0; do { t = Date.now(); } while (t < end);` |
| 14d:test-flag | loop test is a flag the body sets to a clock comparison | `let ok = true; const end = Date.now() + 500; while (ok) { ok = Date.now() < end; }` |
| 14f:local-arrow | clock read through a local arrow function in the test | `const start = Date.now(); const elapsed = () => Date.now() - start; while (elapsed() < 500) {}` |
| 14f:local-decl | clock read through a local function declaration | `function now() { return performance.now(); } const end = now() + 500; while (now() < end) {}` |
| 14f:local-guard | clock read through a local function in a guard that breaks | `const start = Date.now(); function el() { return Date.now() - start; } while (true) { if (el() > 500) break; }` |
| 14f:local-var | clock read through a local function into the variable that guards the exit | `const now = () => Date.now(); const end = now() + 5; let t = 0; while (true) { t = now(); if (t > end) break; }` |
| 14f:local-typed | clock read through a local function in a file that also types a callback | `function w(f: () => void) { f(); } function now() { return performance.now(); } const end = now() + 500; while (now() < end) {}` |
| 14f:overload | clock read through an overloaded local function | `function now(): number; function now(x: number): number; function now(x = 0): number { return Date.now() + x; } const end = now() + 500; while (now() < end) {}` |
| 14f:this-param | clock helper that declares a this parameter | `function now(this: void) { return Date.now(); } const end = now() + 5; while (now() < end) {}` |
| 14f:cycle | two clock helpers that call each other, one reads the clock | `function a() { return b() + Date.now(); } function b() { return a(); } while (a() < 500) {}` |
| 14f:cycle-arrows | the same ring declared as arrows | `const a = () => b() + Date.now(); const b = () => a(); while (a() < 500) {}` |
| 14f:cycle-complete | three clock helpers that each call both others | `function a() { return b() + c() + Date.now(); } function b() { return a() + c(); } function c() { return a() + b(); } while (c() < 500) {}` |
| 14f:alias | clock read through a copy of `Date.now` | `const end = Date.now() + 500; const now = Date.now; while (now() < end) {}` |
| 14f:alias-bind | clock read through a bound `performance.now` | `const end = performance.now() + 500; const now = performance.now.bind(performance); while (now() < end) {}` |
| 14f:alias-destructured | clock read through `now` destructured off `Date` | `const end = Date.now() + 500; const { now } = Date; while (now() < end) {}` |
| 14f:alias-cast | local clock arrow behind a cast | `const end = Date.now() + 500; const f = ((): number => Date.now()) as () => number; while (f() < end) {}` |
| 14f:alias-cast-call | clock copy called behind a cast | `const end = Date.now() + 500; while ((Date.now as () => number)() < end) {}` |
| 14f:alias-fallback | clock copy behind `??`, `||` or a conditional | `const end = Date.now() + 500; const now = opts.now ?? Date.now; while (now() < end) {}` |
| 14f:alias-fallback-call | clock fallback called in place | `const end = Date.now() + 500; while ((opts.clock ? opts.clock : Date.now)() < end) {}` |

Notes on the rows:
- Rows 3, 8, 9 and 2 also hold for `setInterval`, `self`, `window`, `global`. Test at least one non-default spelling per row.
- 3a to 3e: a ban on the whole `timers` module, by name, in import, `import()`, `require()` and `getBuiltinModule()`, with and without the `node:` prefix. A template with no hole, and a const or a let holding the name, are read; a let is judged by every write the lint can read, so `let m = './x'; m = 'timers'` is banned too (3c:template, 3c:const, 3d:let, 3d:let-reversed). A template whose static head is `timers` or `node:timers`, alone or followed by `/`, is banned whatever its hole holds: ``timers${x}`` can load timers or timers/promises (3c:hole to 3d:hole-const). A head that goes on past `timers` with anything else, ``timers-browserify${x}``, names another package and is allowed (A15:module-head). A module name assembled any other way is an accepted gap. `export ... from`, `export *` and `import t = require()` count as imports. A type-only import or re-export loads nothing and is legal: `import type { Timeout } from 'node:timers'`, or a declaration whose every specifier is marked `type` (A15:type-import, A15:type-inline, A15:type-export); one value specifier beside the types, or a bare `import 'node:timers'`, is still banned (3a:mixed, 3a:side-effect, 3b:export-mixed).
- 11 and 12 apply wherever a browser driver (playwright, puppeteer) is a dependency. mcp-scan has none and may mark them N/A in Known gaps.
- 9x and 3g: the bare name `setTimeout` handed over as an argument is a selector. A member is judged by the alias rule and counts only when its object is a host: `globalThis`, `window`, `self`, `global`, a const that holds one, or one taken off a host by destructuring, behind a cast or not (9x:host to 9x:host-new, 3g:host). A member of anything else is a config value or a server method and stays legal (A3:value).
- 5:bind, 5:wrapper, 5:wrapper-fn: `r.bind(...)`, `() => r()` and `function () { r(); }` handed to a helper that times its parameter are the resolve. A wrapper that calls nothing the resolve goes by is not (A5:wrapper-other), and a helper whose timer calls the reject stays a guard (A5:wrapper-guard). Stored under another name first, the wrapper is an accepted gap.
- 5:fallback, 5:ternary, 10m:fallback: a resolve copied behind `??`, `||` or a conditional is still the resolve, in a helper or beside a stored one.
- 14f:cycle to 14f:cycle-complete: local clock functions are solved as a group. Helpers that call each other are clocks when each one is only clock reads and calls to clocks, and one of them returns a read; a ring that reads nothing, or has a member that does other work, is not (A14:cycle-no-read, A14:cycle-work).
- 4a:default-exported to 4a:default-maybe-logical: a parameter default stays live when the function is exported (`export function`, `export const`, `export { run }`), and when a call passes a conditional or a fallback that may be `undefined` (`pick ? undefined : P`, `a ?? undefined`). A function that passes its own defaulted parameters down a call to itself, or to a function that calls it back, keeps those defaults live while the walk is inside them, so the walk ends (A15:default-recursive, A15:default-recursive-arrow, A15:default-mutual, A15:default-recursive-promise, 12a:default-recursive). A name set to `undefined`, directly or through another name, passes nothing (4a:default-undefined-var, 4a:default-undefined-copy); a name that holds a value replaces the default (A15:default-var-defined). A conditional with a value on each side, or a fallback that has one, replaces it too (A15:default-both-defined, A15:default-fallback-defined).
- 14c: a loop body with no `await` and no call is still a busy wait. A body with either is a poll and stays legal (A7).
- 14d: a clock read in the loop test or update always counts. A clock read in the body counts when it feeds a `break`, `return`, `throw`, a `continue` that is followed by a `break`, or a write to a variable the loop test reads, at any depth and in either branch of an `if`, directly or through a variable or a member path (14d:var, 14d:member, 14d:derived). A loop whose test is a variable or a flag that the body sets from the clock is a wait, in a `while` and in a do-while (14d:test-var, 14d:test-var-do, 14d:test-flag). The clock may be read through a function declared in the file (an arrow or a declaration) whose body returns a clock read and makes no other call and no `await` (14f:local-arrow, 14f:local-decl, 14f:local-guard, 14f:local-var), also in a file that types a callback as `() => void` (14f:local-typed); a copy of the clock function counts too: `const now = Date.now`, `performance.now.bind(performance)` and `const { now } = Date` (14f:alias, 14f:alias-bind, 14f:alias-destructured), also behind a cast, and behind `??`, `||` or a conditional that may pick the real one (`const now = opts.now ?? Date.now`, `(opts.clock ? opts.clock : Date.now)()`; 14f:alias-cast, 14f:alias-cast-call, 14f:alias-fallback, 14f:alias-fallback-call), while a loop that only records a copy is not a wait (A7:alias-stamps), and a fallback between two things that are not clocks is not a clock (A14:fallback-no-read). A local function that does other work is not a clock (A7:local-work-fn). A loop that only records times (A7:stamps, A7:record, A7:count, A7:unguarded, A7:clock-test-var, A7:local-counter, A7:local-stamps, A7:local-clock-outside, A7:alias-stamps) is not a wait. A `for` with a bounded counter test and a clock guard that breaks is reported too (a false positive, section 7); a loop that spins on a counter and never reads a clock is an accepted gap.
- 12f:eval to 12f:function: `eval(...)`, `(0, eval)(...)`, `globalThis.eval(...)`, `new Function(...)` and `Function(...)` take a script like `evaluate` does, and are banned when its text sets a timer or a function handed to it does. Text the lint cannot read, or a script with no timer, stays legal (A12:eval-plain).
- A15:node-hole: a `node:` specifier with a hole (`import()` of a template headed `node:`) is not banned. Only a hole after a static head of `timers` can load the timers module.
- 4a to 4e: `Reflect.construct(P, [...])` is a `new P(...)`. A `Promise` held in a let, behind `??`/`||`, or a parameter default is still `Promise`; judge every write, not just the first. `Promise` destructured off a host is a `Promise` whether it is declared, assigned or taken in a parameter default, and whether the host is named or held in a const (4e, 4e:host-var, 4e:assign, 4e:param).
- 8a to 8d: a destructure only counts when its source is a host (`globalThis`, `window`, `self`, `global`), by declaration, assignment or parameter default, behind a cast or not. `const { setTimeout: ms } = opts` is a config read (A3:destructure, A15:host-var-config). The source may sit behind a comma, `??`, `||`, a conditional or a cast, be held in a const, or sit under a host key (`const { window: { setTimeout: w } } = globalThis`); every such shape is banned (8a:*). A host held in a const is a host everywhere, so `const g = globalThis; g.setTimeout(r, 50)` is banned too (2e:host-var). A key held in a let is judged by every write the lint can read: one that names a timer bans the use whatever order the writes run in (8d:let, 8d:let-twice, 8d:let-reversed). A write it cannot read (`k += 'x'`, `k = pick()`) names nothing.
- 10: a bag kept in an object or array literal, a class field (also a static one reached by a class expression or by `this` in a static method), or made with `Promise.withResolvers.call/apply/bind` is still a bag (10a:field, 10a:class-expr, 10a:static-this, 10h:bag-*, 10i:*). The bound function may sit in a let: every write the lint can read is judged (10i:let-reassigned, 10i:let-reversed). A `this.x` belongs to its own class: another class's field of the same name is not the bag (A15:this-other-class). Whatever settles in a callback declared in the file is judged by its body, and by the bodies of the functions that body calls, transitively (10k, 10k:wrapper, 10k:hop). The flow is a fixpoint: a copy taken before the bag exists, in an if, through a function or in a reverse chain, must still be reached (10l).
- 6: a timer callback is judged by its body when it is a name declared in the file, and `r.bind(...)` is a resolve (6:named-callback, 6:bind-resolve); `rej.bind(...)` is a reject (A1c:bind). The judging follows the functions declared in the file that the body calls, transitively, in both directions: a helper that calls the resolve makes the timer a sleep (6:wrapper, 6:outer), a helper that only calls the reject keeps it a guard (A1c:outer). A resolve held in an object or array literal is still the resolve (6:literal, 6:array). A timer inside the executor whose callback calls that executor's reject is a deadline guard even when it touches an emitter that only listens for the resolve, `child.on('exit', r)` then `child.kill()` (A1d, A1d:destroy); `off('x', r)` and `removeListener` take the resolve out of a listener list and do not call it (A1d:off). A resolve stored where code can call it back (6:held), an `emit` on the listener (6:emit) or a callback that never rejects (6:listener) keeps the timer a sleep.
- 12: a script held in a let or a parameter, a function (inline or declared in the file) handed to the page that sets a timer, and a const script are read (12a:let, 12e:*). A script or a driver key in a let is judged by every write the lint can read (12a:let-twice, 12a:let-reversed, 12a:let-append, 11b:let-twice, 11b:let-reversed). A parameter default counts only when some call in the file leaves the argument out or passes `undefined` or `void x`, which the default replaces (12a:param-undefined, 4a:default-undefined, 8a:default-void): `run(s = 'setTimeout(...)')` called as `run('document.title')` never uses it, and neither does `run(null)`, since `null` is not replaced (A15:default-overridden, A15:default-overridden-promise, A15:default-overridden-host, A15:default-null); a function that is exported, passed as a value or never called keeps its default.
- 3g: `promisify(setTimeout)` and `x.promisify(setTimeout)` are a sleep wherever the call sits, with the timer as an argument (3g).
- 3f and 13: `scheduler` and `Atomics` held in a const or destructured off a host are the same global (3f:alias, 3f:destructured-host, 13a:alias, 13a:destructured-host); a const that holds anything else is not (A15:alias-other).
- A2a to A2b: a restore may sit behind `as`, `!` or `satisfies`.
- 12: `${}` holes still carry the word, so the match is on the literal text of the script.

## 3. Allowed snippets: every row MUST NOT be reported (105 rows)

| ID | Why it is legal | Snippet |
|---|---|---|
| A1a | deadline guard, real reject | `await new Promise((r, rej) => { setTimeout(() => rej(new Error('late')), 50); });` |
| A1b | reject by reference | `await new Promise((r, rej) => setTimeout(rej, 50));` |
| A1c | reject through an alias | `await new Promise((r, rej) => { const fail = rej; setTimeout(() => fail(new Error('late')), 50); });` |
| A1c:declared | reject from a function declared in the file | `await new Promise((r, rej) => { function late() { rej(new Error('late')); } setTimeout(late, 50); });` |
| A1c:arrow | reject from an arrow declared in the file | `await new Promise((r, rej) => { const late = () => rej(new Error('late')); setTimeout(late, 50); });` |
| A1c:outer | reject through an outer helper | `const late = (j: (e: Error) => void) => j(new Error('late')); await new Promise((r, rej) => setTimeout(() => late(rej), 50));` |
| A1c:bind | reject bound into the callback | `await new Promise((r, rej) => setTimeout(rej.bind(null, new Error('late')), 50));` |
| A1d | deadline guard that kills the emitter holding the resolve | `await new Promise((r, rej) => { child.on('exit', r); setTimeout(() => { child.kill(); rej(new Error('timeout')); }, 5000); });` |
| A1d:destroy | deadline guard that destroys the socket holding the resolve | `await new Promise((r, rej) => { socket.once('data', r); setTimeout(() => { socket.destroy(); rej(new Error('timeout')); }, 5000); });` |
| A1d:off | deadline guard that detaches the resolve from the listener | `await new Promise((r, rej) => { ee.on('x', r); setTimeout(() => { ee.off('x', r); rej(new Error('timeout')); }, 5000); });` |
| A2a | timer saved, stubbed, restored | `const orig = globalThis.setTimeout; globalThis.setTimeout = (() => 0) as never; globalThis.setTimeout = orig;` |
| A2b | restore through stubGlobal | `const orig = setTimeout; vi.stubGlobal('setTimeout', () => 0); vi.stubGlobal('setTimeout', orig);` |
| A2c | fake-timer setup | `vi.useFakeTimers({ toFake: ['setTimeout'] }); vi.advanceTimersByTime(50); vi.useRealTimers();` |
| A2d | setInterval saved, stubbed and restored | `const orig = setInterval; setInterval = (() => 0) as never; setInterval = orig;` |
| A2a:cast | restore behind a cast | `const orig = setTimeout; setTimeout = orig as never;` |
| A2a:nonnull | restore behind `!` | `const orig = globalThis.setTimeout; globalThis.setTimeout = orig!;` |
| A2b:cast | stubGlobal restore behind a cast | `const orig = setTimeout; vi.stubGlobal('setTimeout', orig as never);` |
| A3 | config read, not a timer | `const t = opts.setTimeout ?? 5000; server.setTimeout(t); expect(opts.setTimeout).toBe(5000);` |
| A3:opts-read | config property read | `const ms = opts.setTimeout ?? 5000; if (ms) use(ms);` |
| A3:server-call | server timeout set through a call | `server.setTimeout(5000);` |
| A3:expect | config property asserted on | `expect(opts.setTimeout).toBe(5000);` |
| A3:value | config property handed on as a value | `use(opts.setTimeout); use(opts['setTimeout']); list.push(opts.setTimeout); new Thing(opts.setInterval);` |
| A3:destructure | config pattern with a default | `const { setTimeout: ms = 5000 } = opts; use(ms);` |
| A3:destructure-key | config pattern, setInterval key | `const { setInterval: every } = config; use(every);` |
| A3:destructure-computed | config pattern, computed key | `const k = 'setTimeout'; const { [k]: ms } = opts; use(ms);` |
| A3:destructure-param | config pattern in a parameter | `function f({ setTimeout: ms }: Opts) { use(ms); } f({ setTimeout: 5 });` |
| A4 | reject passed by reference behind a cast | `await new Promise((r, rej) => setTimeout(rej as never, 50));` |
| A5 | non-host `lib.Promise` | `const P = lib.Promise; use(P);` |
| A6 | timer outside any promise | `const id = setTimeout(() => undefined, 50); clearTimeout(id);` |
| A6:expect-timer | the timer function asserted on | `expect(setTimeout).toBeDefined(); expect(globalThis.setTimeout).toBeTypeOf('function');` |
| A6:matcher | the timer asserted as the argument of a matcher | `expect(patched).toBe(setTimeout);` |
| A6:matcher-not-host | the host's timer asserted through not | `expect(patched).not.toBe(globalThis.setTimeout);` |
| A6:matcher-strict-equal | the interval timer asserted with toStrictEqual | `expect(fn).toStrictEqual(setInterval);` |
| A6:assert | the timer asserted with node assert | `assert.strictEqual(patched, setTimeout);` |
| A6:restore-asserted | a saved timer compared back to the real slot | `const orig = globalThis.setTimeout; await run(); expect(globalThis.setTimeout).toBe(orig);` |
| A6:soft | the timer asserted through a soft matcher chain | `expect.soft(patched).resolves.not.toBe(setTimeout);` |
| A6:mocked | the mocked timer reset | `vi.mocked(setTimeout).mockClear();` |
| A6:host-literal-other | host indexed by a literal that is not a timer | `await new Promise((r) => { globalThis['queueMicrotask'](r); });` |
| A7 | poll loop that does work | `const end = Date.now() + 500; while (Date.now() < end) { await check(); }` |
| A7:stamps | loop that records times by index | `const stamps: number[] = []; for (let i = 0; i < 3; i++) stamps[i] = Date.now(); use(stamps);` |
| A7:record | loop that records the last time | `let last = 0; for (let i = 0; i < 3; i++) { last = Date.now(); } use(last);` |
| A7:count | loop that counts late samples | `let late = 0; for (let i = 0; i < 3; i++) { if (Date.now() > deadline) late++; } use(late);` |
| A7:unguarded | bounded loop with an unguarded clock read | `let n = 0; let t = 0; while (n < 3) { t = performance.now(); n++; } use(t);` |
| A8 | inspecting the real timer | `expect(setTimeout).toBeDefined(); vi.mocked(setTimeout).mockClear();` |
| A9 | withResolvers, reject only | `const d = Promise.withResolvers<void>(); setTimeout(() => d.reject(new Error('late')), 50); await d.promise.catch(() => undefined);` |
| A9:field | class field bag, reject only | `class A { d = Promise.withResolvers<void>(); go() { setTimeout(() => this.d.reject(new Error('late')), 5); return this.d.promise.catch(() => undefined); } }` |
| A10 | `setTimeout` on a non-host receiver | `await new Promise((r) => { server.setTimeout(r, 50); });` |
| A11 | script string with no timer | `await page.evaluate('document.title');` |
| A12 | wait on a locator | `await expect(page.locator('#x')).toBeVisible();` |
| A13 | same sleep, file outside the scope glob | `new Promise((r) => setTimeout(r, 50));` linted as `src/lib/wait.ts` reports nothing |
| A14 | wait on a user object | `await mySched.wait(50);` |
| A14:atomics | `wait` on a non-host Atomics | `await lib.Atomics.wait(5);` |
| A14:store | property that only starts with waitForTimeout | `const w = store.waitForTimeoutMs; use(w);` |
| A14:driver-key | object key, not a call | `const opts = { waitForTimeoutMs: 5 }; use(opts);` |
| A14:var | plain variable key and plain template | `` const k = 'title'; await (page as any)[k](); const j = `x`; use(j); `` |
| A14:cycle-no-read | a ring of helpers that never reads the clock | `function a() { return b(); } function b() { return a(); } let n = 0; while (a() < 500) { n++; }` |
| A14:cycle-work | a ring where one helper does other work | `function a() { return b() + Date.now(); } function b() { return a() + work(); } while (a() < 500) {}` |
| A15:callback | bag callback that only rejects | `const d = Promise.withResolvers<void>(); const f = () => d.reject(new Error('late')); setTimeout(f, 5); await d.promise.catch(() => undefined);` |
| A15:other | callback with no resolve or timer in a promise | `const f = () => undefined; setTimeout(f, 5);` |
| A15:self-param | a parameter named self is whatever it was given | `function f(self: Worker) { return new Promise<void>((r) => self.setTimeout(r, 50)); } await f(fake);` |
| A15:window-param | an arrow parameter named window | `const f = (window: Fake) => new Promise<void>((r) => window.setTimeout(r, 50)); await f(fake);` |
| A15:global-local | a local named global holding a fake | `let global: Fake = fake; await new Promise<void>((r) => global.setTimeout(r, 50));` |
| A15:self-destructured | self taken off an argument by a pattern | `const f = ({ self }: { self: Fake }) => new Promise<void>((r) => self.setTimeout(r, 50)); await f({ self: fake });` |
| A15:return | function returning a non-timer | `function mk() { return setTimeoutLike; } mk();` |
| A15:script-const | script const with no timer | `const s = 'document.title'; await page.evaluate(s);` |
| A15:destructure | destructure off Atomics, not a wait | `const { notify } = Atomics; notify(arr, 0, 1);` |
| A15:class | subclass executor with no resolver | `void new (class extends Base {})((r) => { setTimeout(r, 5); });` |
| A15:field-plain | class field that is not a bag | `class A { n = 1; go() { setTimeout(() => this.n++, 5); } }` |
| A15:local-fn | local function with no timer handed to evaluate | `const fn = () => document.title; await page.evaluate(fn);` |
| A15:module-other | a module named `./timers` | `` const t = await import('./timers'); void t; const u = require(`./timers`); void u; `` |
| A15:module-head | templates headed by another package whose name starts with `timers` | `` const t = await import(`timers-browserify${x}`); void t; const u = require(`timers-browserify${y}`); void u; `` |
| A15:type-import | type-only import of a timers type | `import type { Timeout } from 'node:timers'; export type Handle = Timeout;` |
| A15:type-inline | every specifier marked `type` | `import { type Timeout, type Immediate as Im } from 'timers/promises'; export type Handle = Timeout \| Im;` |
| A15:type-export | type-only re-export | `export type { Timeout } from 'node:timers'; export { type Immediate } from 'timers';` |
| A15:this-other-class | another class has a field of the same name that is not a bag | `class A { d = Promise.withResolvers<void>(); } class B { d = { resolve: () => undefined }; go() { setTimeout(() => this.d.resolve(), 5); } }` |
| A15:default-overridden | script default that every call overrides | `async function run(s = 'setTimeout(() => 0, 5)') { await tab.evaluate(s); } await run('document.title');` |
| A15:default-null | script default that a call overrides with `null`, which a default does not replace | `async function run(s = 'setTimeout(() => 0, 5)') { await tab.evaluate(s); } await run(null);` |
| A15:default-overridden-promise | Promise default that every call overrides | `async function run(P = Promise) { await new P((r) => setTimeout(r, 50)); } await run(Fake);` |
| A15:default-overridden-host | host default that every call overrides | `function run({ setTimeout: ms } = globalThis) { use(ms); } run(opts);` |
| A15:host-var-config | destructure off a const that holds a config object | `const h = opts; const { setTimeout: ms } = h; use(ms);` |
| A15:host-var-member | member call on a const that holds a config object | `const h = opts; h.setTimeout(5); use(h);` |
| A15:alias-other | `wait` on a const that is not Atomics | `const A = Other; A.wait(5);` |
| A7:clock-test-var | loop that times each pass, test is a counter | `let n = 0; const t0 = Date.now(); while (n < 3) { n++; const dt = Date.now() - t0; use(dt); }` |
| A7:local-work-fn | loop that does work, clock read through a local function | `const t0 = Date.now(); const check = () => { void fetch('x'); return Date.now() - t0; }; while (check() < 500) {}` |
| A7:local-counter | loop that counts, the local clock function only times each pass | `let n = 0; const tick = () => { n++; return n; }; while (tick() < 5) {}` |
| A7:local-stamps | loop that records the local clock function | `const stamp = () => Date.now(); const s: number[] = []; for (let i = 0; i < 3; i++) s[i] = stamp(); use(s);` |
| A7:local-clock-outside | local clock function called outside any loop | `const t0 = Date.now(); const dt = () => Date.now() - t0; const a = dt(); use(a);` |
| A7:alias-stamps | loop that records a copy of the clock | `const stamp = Date.now; const s: number[] = []; for (let i = 0; i < 3; i++) s[i] = stamp(); use(s);` |
| A14:fallback-no-read | fallback between two non-clock counters | `let n = 0; const tick = opts.tick ?? (() => n++); while (tick() < 500) {}` |
| A14:date-search | a date compare in a loop that breaks, no clock read | `const stamps = ['a']; let i = 0; while (i < stamps.length) { if (new Date(stamps[i]) > new Date(5)) break; i++; }` |
| A14:sorted-throw | a sorted-order check that throws, dates parsed from strings | `const xs: string[] = []; for (let i = 1; i < xs.length; i++) { if (new Date(xs[i]) < new Date(xs[i - 1])) throw new Error('unsorted'); }` |
| A5:wrapper-other | a wrapper that never calls the resolve, handed to a timing helper | `function after(f: () => void) { setTimeout(f, 50); } await new Promise<void>((r) => { r(); after(() => work()); });` |
| A5:wrapper-call-other | a wrapper that calls something else through call | `function after(f: () => void) { setTimeout(f, 50); } await new Promise<void>((r) => { r(); after(() => work.call(null)); });` |
| A5:bind-twice-other | something else bound twice and handed to the helper | `function after(f: () => void) { setTimeout(f, 50); } await new Promise<void>((r) => { r(); after(work.bind(null).bind(null)); });` |
| A5:wrapper-guard | a wrapped resolve beside a reject that the helper's timer calls | `function after(f: () => void, rej: (e: Error) => void) { setTimeout(() => rej(new Error('late')), 50); void f; } await new Promise<void>((r, j) => after(() => r(), j));` |
| A15:default-both-defined | every call passes a conditional with a value on each side | `async function run(P = Promise) { await new P((r) => setTimeout(r, 50)); } await run(pick ? Fake : Other);` |
| A15:default-fallback-defined | every call passes a fallback that has a value | `async function run(P = Promise) { await new P((r) => setTimeout(r, 50)); } await run(opts.P ?? Fake);` |
| A15:default-var-defined | the only call passes a name that holds a value | `async function run(P = Promise) { await new P((r) => setTimeout(r, 50)); } const u = Fake; await run(u);` |
| A12:eval-plain | eval and Function with scripts that set no timer, or with text the lint cannot read | `eval('1 + 1'); eval(code); new Function('a', 'return a')(1);` |
| A12:eval-alias-plain | eval held under another name with a script that sets no timer | `const e = eval; e('1 + 1'); const F = Function; F('return 1')();` |
| A15:node-hole | a node: specifier with a hole is not the timers module | `` const m = await import(`node:${x}`); use(m); `` |
| A15:default-recursive | defaulted parameters passed down a self-call | `async function poll(s = 'document.title', n = 3): Promise<void> { await page.evaluate(s); if (n > 0) return poll(s, n - 1); } await poll();` |
| A15:default-recursive-arrow | the same as an arrow | `const poll = async (s = 'document.title', n = 3): Promise<void> => { await page.evaluate(s); if (n > 0) return poll(s, n - 1); }; await poll();` |
| A15:default-mutual | the same through two functions that call each other | `async function a(s = 'x', n = 2): Promise<void> { await page.evaluate(s); if (n) await b(s, n - 1); } async function b(s = 'y', n = 2): Promise<void> { if (n) await a(s, n - 1); } await a();` |
| A15:default-recursive-promise | a Promise default passed down a self-call | `async function w(P = Promise, n = 2): Promise<void> { await new P((r: () => void) => r()); if (n) await w(P, n - 1); } await w();` |

An allowed row that reports is a bug in the rule, not in the test. Do not delete the row to make CI green.

## 4. Policy fork: resolver handed to a listener

mcp-scan lets `new Promise((r) => { server.on('x', r); setTimeout(r, 5000); })` through (a fallback in a race on a real signal). theboctorwedding and chat-export-extension report it.

Default is strict: report it, and rewrite the test as a deadline guard that rejects (`setTimeout(() => rej(new Error('late')), 5000)`) so a timeout fails loudly instead of resolving quietly. A repo keeping the exemption must say so in Known gaps and plant `new Promise((r) => { noop(r); setTimeout(r, 50); })` as the case that shows the edge of it.

## 5. The proof rule

The rule is not done until all of this is in a test the CI lint job runs (exit code checked; never `allow_failure`, never manual):

1. **Real config, real lint.** Build `new ESLint({ overrideConfigFile })` on the repo's own config and call `lintText(code, { filePath })` per snippet, with `filePath` inside the scope glob. Never re-implement the rule in the test.
2. **Parse check first.** Fail the case if any message is `fatal`. A snippet that does not parse reports nothing, so an allowed case would pass for the wrong reason.
3. **Filter to the ban rules.** Count only the sleep rule ids (`local/no-sleep-promise`, `local/no-timer-alias`, `local/no-sleep-api`, `no-restricted-syntax`, `no-restricted-imports`). An unused-variable report must not pass for a ban.
4. **Assert the rule id, not just any report.** Each banned row names the id that must report it, plus the messageId (local rules) or a message fragment (`no-restricted-syntax`, which shares one messageId). `opaque` is not a detected sleep. The one exception is 4a:reflect-args, whose id is `opaque` on purpose: `Reflect.construct(Promise, args)` cannot be read, so the rule refuses the call instead of judging it.
5. **Allowed rows assert an empty list** (`deepEqual(ids, [])`).
6. **Class coverage test.** The table rows carry their class number; the test asserts every class 1 to 14 has a row. Deleting a class then fails CI.
7. **Glob test.** Every extension in the scope glob reports a plain `new Promise((r) => setTimeout(r, 50))`, at the top of the test dir and nested; a file outside the glob reports nothing (A13).
8. **Mute test (the planted violation).** For each distinct rule id in the banned table, lint one planted row with that rule set to `off` through `overrideConfig` and assert the report is gone. This proves the case depends on the rule, so a rule deleted from the config fails the suite instead of passing quietly.
9. **Cost test.** Assert how the rule's work scales, not a fixed bound and not a clock reading (a clock reading on a busy host moves by more than the growth it is meant to catch). The rule counts its own work in `globalThis.__sleepOps` (it is a no-op unless a test sets it to a number; it lives on `globalThis` because ESLint loads the config as a module instance of its own): every unwrap, scope lookup and read of a name's writes, every step of a walk and every node it visits adds one. Lint each built file at size N and again at 4N of input (2N for a graph whose edges are the square of its nodes, so its input is 4x as well) with only the ban rules on through `overrideConfig`, assert first that the same reports come back at both sizes, then assert the count at 4N over the count at N is under 6, and that both counts are above zero (a count of zero would make the ratio 0 and pass for the wrong reason). Linear cost reads 4 and quadratic 16, and the count is the same on every run, so there is no noise to leave room for. A stub with a known cost proves the check reads 16 for quadratic and 4 for linear, and that a stub that counts nothing fails. Shapes: a reverse-order assignment chain with N calls into an N-line helper; executors nested N deep (distinct names, one shared name, and with a deadline guard at every level; the innermost one sleeps, so each reports and an empty answer cannot pass for a fast one; the parser itself overflows a little past 100 levels); a file of 5000 and then 20000 plain declarations before a clock loop (the program's token list once overflowed the stack when spread); a busy loop fed through a chain of N copies, a loop on each of N copies of one clock (and the same copies in a ring), and a cascade of clock helpers that loses one per round (a plain clock loop beside it is the report); a `new` on each of N copies of `Date`; a chain, a ring, a dense cycle (every helper calls two others) and a complete graph of clock helpers; a complete graph of helpers that pass a resolve down, and one that calls a stored resolve; a ring of helpers that return each other; a resolver copied N times through `??` (in the executor, in a helper, and as a bag); a key or a script written N times from itself; script text round a ring of variables and of arrays; fan-out helpers that each call the one below twice; N timers in one file that all call the same N-line helper while a resolve is stored; and N deadline guards that call that helper with their reject. Each of those once cost more than its input: a fixpoint that re-swept every link, a copy chain walked from its end by every loop, a memo keyed by an array literal that never hit, a walk that re-read a helper per timer, a function body re-read by every function around it, a follow that copied its hits per caller, a clock solver that gave up at a cycle, a scope lookup that walked up through every level of nested functions for a global such as `Promise`, and executors nested N deep that each re-judged every timer already reported inside them. A fixed 3 s bound passes with any of those reverted, so it is not a test.
10. **Fixpoint test.** Rows 10l plant a copy that precedes the bag. A rule whose flow pass runs once must fail them: mutate the loop to a single pass and confirm the rows go red.
11. **Once per contributor, by hand:** copy the config to scratch, delete the rule block, run the lint test and confirm a nonzero exit, restore, `diff` byte-identical, rerun green. Paste the exit codes in the MR.
12. **Memo tests.** `function a(f) { b(f); setTimeout(f, 5); } function b(f) { a(f); } await new Promise((r) => a(r)); await new Promise((r) => b(r));` reports exactly 2 (a walk that was cut short must not be remembered), and 5:swapped reports (the cycle guard is keyed by function and parameter, not by function alone).
13. **Spec-parse test.** Keep a copy of this file in the repo. Parse the section 2 and 3 tables out of it and assert every row id is in the pin lists (SPEC_ROWS, SPEC_ALLOWED) and in the case tables, so a row added here without a case fails CI. Another asserts each table is one block with no blank line inside it, since a blank line ends a table and the rows after it render as plain text. Another asserts the `(N rows)` count in each of those two headings matches the ids parsed from its table. Keep the shapes an outside tester ran against the rule in `tests/lint/no-sleep-harness-shapes.ts` and assert each is an exact row of the case tables, so no shape lives only in a scratch directory. A last test asserts the sha256 of the spec copy, of the rule module and of the cases file against a committed `tests/lint/no-sleep-pins.json`, so drift fails in CI and not only on a machine that holds the canonical file; a port compares its own three files against the same pins. The rules live in their own module (`eslint/no-sleep.js`, which exports `withNoSleep` and the message tail `SIGNALS`) and the repo's `eslint.config.js` wraps its blocks in it, so an unrelated config edit does not move a pin; the tests import `SIGNALS` instead of repeating it. A13 is covered by the glob test.
14. **Long-chain test.** Every walk that follows a name keeps its own stack, since a walk that recurses once per link throws a RangeError at about two thousand links and a throw aborts the lint run. Build a 3000-link chain for each follow (copies of a clock, of a host plain and destructured, of a timer through casts, of Promise, of a timer key, of a script, of `undefined` behind a parameter default, of `Promise.withResolvers`, and helpers that each call the one below), lint it, and assert the lint returns and reports the rule that owns the shape.

## 6. Reference status on 2026-10-10

Measured on that date with the rows and variants it had then (83 banned and 31 allowed snippets, a historical count; the headings of sections 2 and 3 carry the current ones) through each config's own `lintText`. The shapes the outside harness ran are vendored in `tests/lint/no-sleep-harness-shapes.ts`, and a test asserts each is an exact case row.

| Repo (branch) | Rows missed | False positives |
|---|---|---|
| theboctorwedding (`sleep-rule-gaps`) | 3e, 3f, 7b, 8b, 8c, 8d, 9a, 9b, 9c, 10c, 10d, 10f, 10g, 10h, 10i, 10j, 12d, 14c | A3 (`const t = opts.setTimeout` reports `no-timer-alias`) |
| chat-export-extension (`sleep-rule-gaps`) | 2a to 2d, 3b, 3c, 3e, 3f, 4a, 4d, 4e, 5, 8b to 8d, 9a to 9c, 10c, 10d, 10f to 10h, 10j, 11a to 11e, 12a to 12d, 13a, 13b, 14a to 14c | A1c and reject through a helper, A3, A4 (`setTimeout(rej as never, 50)` reports `no-sleep-promise`) |
| mcp-scan (`origin/main`, a3b627d) | 2a to 2d, 3f, 5, 8b to 8d, 9a to 9c, 10c, 10h, 11 to 14 | none |

chat-export-extension (`sleep-rule-spec`): every banned row and variant in `tests/lint/no-sleep-cases.ts` is reported and every allowed row is not, so 0 banned shapes are missed and 0 allowed shapes are reported. The accepted gaps and false positives in section 7 each have a row in the same file and stay as listed there.

Read it as the work list: a row missed is a row the contributor hardening the rule must close, in the same commit that adds the snippet. The theboctorwedding gaps comment calls 10j and 14c deliberate; this spec overrides it, because mcp-scan already closes 10j and 14c has a cheap definition (no `await`, no call).

## 7. Scope, messages and Known gaps

**Where it applies.** Test and e2e globs only, via a `files` entry on its own config block:
- theboctorwedding: `e2e/**/*.{ts,tsx,mts,cts,js,jsx,mjs,cjs}`
- chat-export-extension: `tests/**/*.{ts,tsx,mts}`
- mcp-scan: `tests/**/*.ts`

**Merge, do not replace.** A config block that sets `no-restricted-syntax` replaces the options an earlier block set, so a port that only appends the banned selectors drops every selector its own config restricts in tests. The reference wraps the repo's blocks in `withNoSleep(blocks)`, which keeps the entries of earlier blocks that apply to the test files in front of the banned ones. It matches each block's `files` (and `ignores`) against sample test paths of every extension and depth the test glob covers: a block that covers all of them (no `files`, a catch-all glob, `tests/**`, the test glob) is merged; a block that covers none (`**/*.{js,mjs}`, `src/**`) never applies to a test and is left alone, so a JavaScript-only block is not promoted onto TypeScript tests; a block that covers some (`tests/**/*.ts`, `**/*.test.ts`, `tests/lint/**`, or `tests/**` with a subdirectory ignored) would be dropped or widened by a merge, so `withNoSleep` throws and the selectors are merged by hand into a block without `files`. Rows of that table are in the test file under `no-restricted-syntax glob match`. A test lints a host block that bans `debugger` and asserts both it and the sleep helper ban report.

The extension list must match the repo's parser block, and helpers under those dirs count as tests. Never apply it to `src/` or `scripts/`: backoff, retry and poll code legitimately uses timers.

**Messages.** Every ban says what it caught and ends with the repo's signal list (`Wait on a signal instead: an expect(locator) assertion, waitForResponse, waitForFunction.` for Playwright repos; `vi.waitFor, fake timers, or an awaited event.` for vitest repos).

**Known gaps convention.** One block comment directly above the rule definition, opening with:

`// Known gaps (an AST rule, not a dataflow engine). A sleep still gets through when:`

then a dash list, one gap per bullet, each shape in backticks. Rules:
- A shape is in the banned table or in Known gaps, never both, never neither. The test file header points at the comment.
- An unsuffixed base row (an id with no `:` suffix, such as 4e or 10a) may not be a gap, except 11 and 12 marked N/A for a repo with no browser driver. A named variant may be a gap if it is listed here.
- A false positive the rule accepts is named in the same comment ("reported as an alias, a false positive rather than a miss").
- Closing a gap moves its line out and adds its snippet in the same commit.

**Accepted gaps (do not spend effort on these):**
- a resolve reaching a timer through an imported helper, or a timer built in another module;
- a script, module name or timer key assembled at runtime (`'set' + 'Timeout'`) or computed by a call (`const k = pick()`);
- the host handed to a function as an argument (`function f(g) { return new Promise((r) => g.setTimeout(r, 50)); } f(globalThis)`);
- a resolve reaching a timer through a method helper (`const h = { after: (f) => setTimeout(f, 50) }; h.after(r)`), or inside an object handed to a helper (`after({ f: r })`);
- a bag returned from a local function (`const d = mk()`), or a resolve read through `for (const f of [d.resolve])`;
- a loop that spins on a counter and never reads a clock (`for (let i = 0; i < 1e9; i++) {}`), or reads it through a function imported from another module (`import { now } from './clock'; while (now() < end) {}`);
- the host reached through itself (`globalThis.globalThis.setTimeout`, `window.self.setTimeout`);
- a script handed to a local function as an argument (`run('setTimeout(...)')`);
- a Promise subclass imported from another module (`import { Base } from './base'; new (class extends Base {})(...)`);
- the clock read by `Date.now.call(Date)` or `Reflect.apply(Date.now, Date, [])`, held in an object (`const c = { now: Date.now }; c.now()`), or a local clock function copied or picked by another name (`const g = f`, `const g = opts.g ?? f`);
- a resolve wrapped and stored under another name before it is handed to a timing helper (`const g = () => r(); after(g)`, `const g = r.bind(null); after(g)`);
- a timer started without `setTimeout` or `setInterval` (`AbortSignal.timeout(50)`), or the loop turn used as a flush (`setImmediate(r)`);
- the timer read off the host by a call or a spread (`Reflect.get(globalThis, 'setTimeout')`, `{ ...globalThis }`);
- a resolve picked out of an array before it is handed to a timing helper (`after([r][0])`), or passed on by a wrapper to another call (`after(() => Promise.resolve().then(r))`);
- a bag held by a class or object that is copied before its resolve is read (`class Q { static d = Promise.withResolvers(); } const Z = Q; setTimeout(Z.d.resolve, 5)`, `const { d } = Q`, `new Q().d`);
- `createRequire(import.meta.url)('timers')` and `module.require('timers')`.

**False positives the rule accepts** (reported rather than missed; name them in the same comment):
- any variable or function named `sleep` (`const sleep = 50`);
- a deadline guard whose timer callback redeclares the resolve name (`(r, rej) => setTimeout(() => { const r = 1; rej(e); })`), since names are matched, not scopes;
- a deadline guard that calls the reject through an object literal that holds it (`const o = { rej }; setTimeout(() => o.rej(e), 50)`);
- a counted loop with a clock guard that breaks (`for (let i = 0; i < 10; i++) { if (Date.now() > end) break; }`): it cannot spin, but it is reported as 14d:for is.
- a local object named `scheduler` or `Atomics` with a `wait` method (`const scheduler = { wait }; scheduler.wait(50)`): globals are matched by name, not scope;
- `new Promise(queueMicrotask)`, `new Promise(process.nextTick)` and `new Promise(setImmediate)`: the scheduler is handed to the executor and reported as unreadable;
- a poll loop that sleeps between checks under one deadline (`while (!ok && Date.now() - start < 1000) { ok = await check(); await new Promise((r) => setTimeout(r, 50)); }`);
- a timer that a fake clock advances at once (`setTimeout(r, 1000); vi.advanceTimersByTime(1000)` inside the executor).

**Closed, so not a gap:** `run(setTimeout as X)` is row 9x:cast and must be reported. The host reached through a const, `const { setTimeout: wait } = g`, and a timer key or script held in a let written more than once are rows 8a:host-var, 2e:host-var, 8d:let-twice, 12a:let-twice and 12a:let-append.
